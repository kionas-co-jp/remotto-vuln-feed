//! NVD CVE 2.0 data feeds: CPE-based affected ranges and NVD's own scores.
//! The yearly feeds are read once; later runs apply the "modified" feed,
//! which covers the last eight days, and reread everything after a gap.
use crate::catalog::cpe_fields;
use crate::feed::{Score, ScoreOrigin, Span};
use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path};

pub const FEED_URL: &str = "https://nvd.nist.gov/feeds/json/cve/2.0";
const FIRST_YEAR: i32 = 2002;
/// The modified feed holds eight days; reread the yearly feeds before a gap.
const MODIFIED_WINDOW: Duration = Duration::days(7);

/// What the NVD analysis of one CVE contributes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NvdRecord {
    pub last_modified: String,
    /// Affected versions per CPE "vendor:product" (escaped as in CPE names).
    #[serde(default)]
    pub products: BTreeMap<String, Vec<Span>>,
    #[serde(default)]
    pub scores: Vec<Score>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    /// When the feeds were last applied; None reads every yearly feed.
    pub updated_at: Option<DateTime<Utc>>,
    pub records: BTreeMap<String, NvdRecord>,
}

#[derive(Deserialize)]
struct Feed {
    #[serde(default)]
    vulnerabilities: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    cve: Cve,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cve {
    id: String,
    #[serde(default)]
    last_modified: String,
    #[serde(default)]
    vuln_status: String,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Default, Deserialize)]
struct Metrics {
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<Metric>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metric {
    #[serde(default)]
    source: String,
    #[serde(default, rename = "type")]
    kind: String,
    cvss_data: CvssData,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssData {
    version: String,
    #[serde(default)]
    vector_string: Option<String>,
    base_score: f32,
}

#[derive(Deserialize)]
struct Configuration {
    #[serde(default)]
    negate: bool,
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    #[serde(default)]
    negate: bool,
    #[serde(default)]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
    version_start_including: Option<String>,
    version_start_excluding: Option<String>,
    version_end_including: Option<String>,
    version_end_excluding: Option<String>,
}

/// Platforms an application configuration can run on, from the
/// non-vulnerable OS names it is combined with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Host {
    Desktop,
    Other,
}

fn host(vendor: &str, product: &str) -> Host {
    let desktop = match vendor {
        "microsoft" => product.starts_with("windows"),
        "apple" => matches!(product, "macos" | "mac_os_x" | "mac_os" | "mac_os_x_server"),
        "linux" => product == "linux_kernel",
        "debian" | "canonical" | "redhat" | "suse" | "fedoraproject" => true,
        _ => false,
    };
    if desktop {
        Host::Desktop
    } else {
        Host::Other
    }
}

/// target_sw values of desktop software; ecosystems such as node.js,
/// wordpress or python name libraries and plugins that endpoints never list
/// as installed programs.
fn desktop_target(target: &str) -> bool {
    matches!(target, "*" | "-" | "") || target.contains("windows") || target.contains("mac")
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for c in value.chars() {
        if escaped || c != '\\' {
            out.push(c);
            escaped = false;
        } else {
            escaped = true;
        }
    }
    out
}

/// The affected span of one vulnerable CPE match, or None when it names no
/// comparable version ("-" means "not applicable").
fn span(fields: &[String], entry: &CpeMatch) -> Option<Span> {
    let version = fields.get(5).map(String::as_str).unwrap_or("*");
    let update = fields.get(6).map(String::as_str).unwrap_or("*");
    if version == "-" {
        return None;
    }
    if version != "*" {
        let mut exact = unescape(version);
        if !matches!(update, "*" | "-") {
            exact = format!("{exact}-{}", unescape(update));
        }
        return Some(Span {
            affected: true,
            start: Some(exact.clone()),
            start_inclusive: true,
            end: Some(exact),
            end_inclusive: true,
        });
    }
    let (start, start_inclusive) = match (
        &entry.version_start_including,
        &entry.version_start_excluding,
    ) {
        (Some(start), _) => (Some(start.clone()), true),
        (None, Some(start)) => (Some(start.clone()), false),
        (None, None) => (None, true),
    };
    let (end, end_inclusive) = match (&entry.version_end_including, &entry.version_end_excluding) {
        (Some(end), _) => (Some(end.clone()), true),
        (None, Some(end)) => (Some(end.clone()), false),
        (None, None) => (None, false),
    };
    Some(Span {
        affected: true,
        start,
        start_inclusive,
        end,
        end_inclusive,
    })
}

fn parse_cve(cve: &Cve) -> NvdRecord {
    let mut products: BTreeMap<String, Vec<Span>> = BTreeMap::new();
    for configuration in cve.configurations.iter().filter(|c| !c.negate) {
        let mut apps = Vec::new();
        let mut hosts = Vec::new();
        for node in configuration.nodes.iter().filter(|node| !node.negate) {
            for entry in &node.cpe_match {
                let Some(fields) = cpe_fields(&entry.criteria) else {
                    continue;
                };
                if fields.len() < 11 {
                    continue;
                }
                match (fields[2].as_str(), entry.vulnerable) {
                    ("a", true) => apps.push((fields, entry)),
                    ("o", false) => hosts.push(host(&fields[3], &fields[4])),
                    _ => {}
                }
            }
        }
        // Chrome "running on" Android, firmware of a device: not desktop software.
        if !hosts.is_empty() && !hosts.contains(&Host::Desktop) {
            continue;
        }
        for (fields, entry) in apps {
            if !desktop_target(&fields[10]) {
                continue;
            }
            let Some(span) = span(&fields, entry) else {
                continue;
            };
            let spans = products
                .entry(format!("{}:{}", fields[3], fields[4]))
                .or_default();
            if !spans.contains(&span) {
                spans.push(span);
            }
        }
    }
    let mut scores = Vec::new();
    let metrics = &cve.metrics;
    for metric in metrics
        .v40
        .iter()
        .chain(&metrics.v31)
        .chain(&metrics.v30)
        .chain(&metrics.v2)
    {
        // Secondary scores come from the CNA, already read from cvelist.
        if metric.source == "nvd@nist.gov" && metric.kind == "Primary" {
            scores.push(Score {
                origin: ScoreOrigin::Nvd,
                provider: "NVD".into(),
                version: metric.cvss_data.version.clone(),
                base_score: metric.cvss_data.base_score,
                vector: metric.cvss_data.vector_string.clone(),
            });
        }
    }
    NvdRecord {
        last_modified: cve.last_modified.clone(),
        products,
        scores,
    }
}

/// Applies one feed document; newer records replace older ones.
pub fn apply(index: &mut Index, gzip: &[u8]) -> Result<usize> {
    let mut json = Vec::new();
    flate2::read::GzDecoder::new(gzip)
        .read_to_end(&mut json)
        .context("Invalid NVD feed")?;
    let feed: Feed = serde_json::from_slice(&json).context("Invalid NVD feed")?;
    let mut applied = 0;
    for Item { cve } in feed.vulnerabilities {
        if cve.vuln_status.eq_ignore_ascii_case("rejected") {
            index.records.remove(&cve.id);
            continue;
        }
        let record = parse_cve(&cve);
        let newer = index
            .records
            .get(&cve.id)
            .is_none_or(|known| known.last_modified <= record.last_modified);
        if !newer {
            continue;
        }
        if record.products.is_empty() && record.scores.is_empty() {
            index.records.remove(&cve.id);
        } else {
            index.records.insert(cve.id, record);
        }
        applied += 1;
    }
    Ok(applied)
}

/// Brings the index up to date: the modified feed when the last update is
/// recent, otherwise every yearly feed followed by the modified feed.
pub async fn update(
    client: &reqwest::Client,
    cache: &Path,
    index: &mut Index,
    offline: bool,
) -> Result<()> {
    let directory = cache.join("nvd");
    std::fs::create_dir_all(&directory)?;
    let now = Utc::now();
    let full = index
        .updated_at
        .is_none_or(|updated| now - updated > MODIFIED_WINDOW);
    let mut feeds: Vec<String> = Vec::new();
    if full {
        feeds.extend((FIRST_YEAR..=now.year()).map(|year| year.to_string()));
    }
    feeds.push("modified".into());
    for name in feeds {
        let url = format!("{FEED_URL}/nvdcve-2.0-{name}.json.gz");
        let bytes = crate::sources::cached(
            client,
            &url,
            &directory.join(format!("{name}.json.gz")),
            offline,
        )
        .await?;
        let applied = apply(index, &bytes).with_context(|| format!("NVD feed {name}"))?;
        eprintln!("NVD {name}: {applied} records");
    }
    if !offline {
        index.updated_at = Some(now);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(value: serde_json::Value) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(value.to_string().as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    fn item(id: &str, modified: &str, configurations: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"cve": {
            "id": id, "lastModified": modified, "vulnStatus": "Analyzed",
            "metrics": {"cvssMetricV31": [
                {"source": "nvd@nist.gov", "type": "Primary",
                 "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": 8.8}},
                {"source": "cna@example.com", "type": "Secondary",
                 "cvssData": {"version": "3.1", "baseScore": 5.0}}]},
            "configurations": configurations
        }})
    }

    fn node(matches: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"operator": "OR", "negate": false, "cpeMatch": matches})
    }

    #[test]
    fn cpe_ranges_become_spans_and_mobile_or_plugin_targets_are_skipped() {
        let feed = serde_json::json!({"vulnerabilities": [
            item("CVE-2025-1", "2025-01-02T00:00:00.000", serde_json::json!([
                {"nodes": [node(serde_json::json!([
                    {"vulnerable": true, "criteria": "cpe:2.3:a:wireshark:wireshark:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "4.2.0", "versionEndExcluding": "4.2.6"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:wireshark:wireshark:4.0.1:*:*:*:*:*:*:*"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.6:rc1:*:*:*:*:*:*"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:wordpress:*:*",
                     "versionEndExcluding": "1.0"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:tool:-:*:*:*:*:*:*:*"}
                ]))]},
                // Chrome running on Android only.
                {"operator": "AND", "nodes": [
                    node(serde_json::json!([{"vulnerable": true,
                        "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", "versionEndExcluding": "110.0"}])),
                    node(serde_json::json!([{"vulnerable": false,
                        "criteria": "cpe:2.3:o:google:android:-:*:*:*:*:*:*:*"}]))]},
                // VLC running on Windows.
                {"operator": "AND", "nodes": [
                    node(serde_json::json!([{"vulnerable": true,
                        "criteria": "cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*", "versionEndIncluding": "3.0.20"}])),
                    node(serde_json::json!([{"vulnerable": false,
                        "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]))]}
            ])),
            {"cve": {"id": "CVE-2025-2", "lastModified": "2025-01-01T00:00:00.000", "vulnStatus": "Rejected"}}
        ]});
        let mut index = Index::default();
        assert_eq!(apply(&mut index, &gzip(feed)).unwrap(), 1);
        let record = &index.records["CVE-2025-1"];
        assert_eq!(
            record.products.keys().collect::<Vec<_>>(),
            vec![
                "notepad-plus-plus:notepad\\+\\+",
                "videolan:vlc_media_player",
                "wireshark:wireshark"
            ]
        );
        let wireshark = &record.products["wireshark:wireshark"];
        assert!(wireshark[0].contains(crate::feed::VersionScheme::Generic, "4.2.5"));
        assert!(!wireshark[0].contains(crate::feed::VersionScheme::Generic, "4.2.6"));
        assert!(wireshark[1].contains(crate::feed::VersionScheme::Generic, "4.0.1"));
        assert_eq!(
            record.products["notepad-plus-plus:notepad\\+\\+"][0]
                .start
                .as_deref(),
            Some("8.6-rc1")
        );
        assert!(record.products["videolan:vlc_media_player"][0]
            .contains(crate::feed::VersionScheme::Generic, "3.0.20"));
        assert_eq!(record.scores.len(), 1);
        assert_eq!(record.scores[0].origin, ScoreOrigin::Nvd);

        // An older copy (the yearly feed after the modified one) is ignored.
        let stale = serde_json::json!({"vulnerabilities": [
            item("CVE-2025-1", "2024-12-01T00:00:00.000", serde_json::json!([]))]});
        assert_eq!(apply(&mut index, &gzip(stale)).unwrap(), 0);
        assert!(!index.records["CVE-2025-1"].products.is_empty());

        // Rejection removes it.
        let rejected = serde_json::json!({"vulnerabilities": [
            {"cve": {"id": "CVE-2025-1", "lastModified": "2025-02-01T00:00:00.000", "vulnStatus": "Rejected"}}]});
        apply(&mut index, &gzip(rejected)).unwrap();
        assert!(index.records.is_empty());
    }
}
