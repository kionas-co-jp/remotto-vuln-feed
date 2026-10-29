//! Linux distribution advisories from OSV.dev: Debian and Ubuntu per-CVE
//! records and Red Hat, AlmaLinux and Rocky Linux errata. The first run reads
//! each ecosystem's all.zip; later runs fetch only the records listed as
//! changed in its modified_id.csv.
use crate::catalog::Catalog;
use crate::feed::{Confidence, Matcher, Product, Span, VersionScheme};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
};

pub const BASE_URL: &str = "https://storage.googleapis.com/osv-vulnerabilities";
/// More changed records than this since the last run: reread all.zip.
const MAX_INCREMENTAL: usize = 3000;

/// An OSV ecosystem directory and the records used from it.
pub struct Source {
    pub directory: &'static str,
    /// Record ID prefixes: per-CVE records or errata, not both.
    prefixes: &'static [&'static str],
}

pub const SOURCES: &[Source] = &[
    Source {
        directory: "Debian",
        prefixes: &["DEBIAN-CVE-"],
    },
    Source {
        directory: "Ubuntu",
        prefixes: &["UBUNTU-CVE-"],
    },
    Source {
        directory: "Red Hat",
        prefixes: &["RHSA-"],
    },
    Source {
        directory: "AlmaLinux",
        prefixes: &["ALSA-"],
    },
    Source {
        directory: "Rocky Linux",
        prefixes: &["RLSA-"],
    },
];

impl Source {
    fn wants(&self, id: &str) -> bool {
        self.prefixes.iter().any(|prefix| id.starts_with(prefix))
    }

    fn url(&self, file: &str) -> String {
        format!("{BASE_URL}/{}/{file}", self.directory.replace(' ', "%20"))
    }

    fn slug(&self) -> String {
        self.directory.to_ascii_lowercase().replace(' ', "-")
    }
}

/// Versions of one package affected by one CVE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub cve: String,
    /// Feed product key, e.g. "deb:debian:12:openssl" or "rpm:rhel:9:openssl".
    pub product: String,
    pub spans: Vec<Span>,
    /// Minor release of a Red Hat stream ("10.2"); later streams win.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<u32>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    /// Newest modified_id.csv timestamp applied.
    pub modified: Option<String>,
    pub records: BTreeMap<String, Vec<Entry>>,
}

#[derive(Deserialize)]
struct Record {
    id: String,
    #[serde(default)]
    modified: String,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    aliases: Option<Vec<String>>,
    #[serde(default)]
    upstream: Option<Vec<String>>,
    #[serde(default)]
    related: Option<Vec<String>>,
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Deserialize)]
struct Affected {
    package: Package,
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct Range {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

/// Feed product key, matcher and stream for an OSV package, or None for
/// releases the catalog does not publish (and Pro, EUS or debug packages).
pub fn product(
    catalog: &Catalog,
    ecosystem: &str,
    package: &str,
) -> Option<(String, Matcher, Option<u32>)> {
    let parts: Vec<&str> = ecosystem.split(':').collect();
    let releases = &catalog.linux;
    let deb = |distro: &str, release: &str| {
        (
            format!("deb:{distro}:{release}:{package}"),
            Matcher::DebPackage {
                distro: distro.into(),
                release: release.into(),
                source: package.into(),
            },
            None,
        )
    };
    let rpm = |distro: &str, release: &str, stream: Option<u32>| {
        (
            format!("rpm:{distro}:{release}:{package}"),
            Matcher::RpmPackage {
                distro: distro.into(),
                release: release.into(),
                name: package.into(),
            },
            stream,
        )
    };
    if package.ends_with("-debuginfo") || package.ends_with("-debugsource") {
        return None;
    }
    match parts.as_slice() {
        ["Debian", release] if releases.debian.iter().any(|r| r == release) => {
            Some(deb("debian", release))
        }
        // "Ubuntu:24.04:LTS"; Pro and FIPS streams need a subscription.
        ["Ubuntu", release] | ["Ubuntu", release, "LTS"]
            if releases.ubuntu.iter().any(|r| r == release) =>
        {
            Some(deb("ubuntu", release))
        }
        // "Red Hat:enterprise_linux:9::appstream", "Red Hat:enterprise_linux:10.2".
        ["Red Hat", "enterprise_linux", version, ..] => {
            let (major, minor) = version.split_once('.').unwrap_or((version, "0"));
            releases
                .rhel
                .iter()
                .any(|r| r == major)
                .then(|| rpm("rhel", major, minor.parse().ok()))
        }
        ["AlmaLinux", release] if releases.rhel.iter().any(|r| r == release) => {
            Some(rpm("almalinux", release, None))
        }
        ["Rocky Linux", release] if releases.rhel.iter().any(|r| r == release) => {
            Some(rpm("rocky", release, None))
        }
        _ => None,
    }
}

pub fn scheme(product: &str) -> VersionScheme {
    if product.starts_with("deb:") {
        VersionScheme::Dpkg
    } else {
        VersionScheme::Rpm
    }
}

/// OSV ECOSYSTEM events as spans: introduced..fixed (exclusive) or
/// introduced..last_affected (inclusive); "0" is "from the start".
fn spans(range: &Range) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut start: Option<Option<String>> = None;
    for event in &range.events {
        if let Some(version) = event.get("introduced") {
            if let Some(open) = start.take() {
                spans.push(span(open, None, false));
            }
            start = Some((version != "0").then(|| version.clone()));
        } else if let Some(version) = event.get("fixed") {
            spans.push(span(start.take().flatten(), Some(version.clone()), false));
        } else if let Some(version) = event.get("last_affected") {
            spans.push(span(start.take().flatten(), Some(version.clone()), true));
        }
    }
    if let Some(open) = start {
        spans.push(span(open, None, false));
    }
    spans
}

fn span(start: Option<String>, end: Option<String>, end_inclusive: bool) -> Span {
    Span {
        affected: true,
        start,
        start_inclusive: true,
        end,
        end_inclusive,
    }
}

/// ID, modification time and entries of one OSV record; no entries when it
/// is withdrawn or names no published release.
fn parse_record(json: &[u8], catalog: &Catalog) -> Result<(String, String, Vec<Entry>)> {
    let record: Record = serde_json::from_slice(json).context("Invalid OSV record")?;
    let mut cves: Vec<String> = record
        .aliases
        .iter()
        .chain(&record.upstream)
        .chain(&record.related)
        .flatten()
        .filter(|id| id.starts_with("CVE-"))
        .cloned()
        .collect();
    for prefix in ["DEBIAN-", "UBUNTU-"] {
        if let Some(cve) = record.id.strip_prefix(prefix) {
            cves.push(cve.to_string());
        }
    }
    cves.sort();
    cves.dedup();
    let mut entries = Vec::new();
    if record.withdrawn.is_none() {
        for affected in &record.affected {
            let Some((product, _, stream)) =
                product(catalog, &affected.package.ecosystem, &affected.package.name)
            else {
                continue;
            };
            let spans: Vec<Span> = affected
                .ranges
                .iter()
                .filter(|range| range.kind == "ECOSYSTEM")
                .flat_map(spans)
                .collect();
            if spans.is_empty() {
                continue;
            }
            for cve in &cves {
                entries.push(Entry {
                    cve: cve.clone(),
                    product: product.clone(),
                    spans: spans.clone(),
                    stream,
                });
            }
        }
    }
    Ok((record.id, record.modified, entries))
}

fn apply(index: &mut Index, id: String, entries: Vec<Entry>) {
    if entries.is_empty() {
        index.records.remove(&id);
    } else {
        index.records.insert(id, entries);
    }
}

/// Reads every wanted record of an all.zip archive.
pub fn read_archive(path: &Path, source: &Source, catalog: &Catalog) -> Result<Index> {
    let file =
        std::fs::File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("Invalid OSV archive")?;
    let mut index = Index::default();
    let mut newest = String::new();
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let name = file.name().trim_end_matches(".json").to_string();
        if !source.wants(&name) {
            continue;
        }
        let mut json = Vec::new();
        file.read_to_end(&mut json)?;
        let (id, modified, entries) =
            parse_record(&json, catalog).with_context(|| format!("OSV {name}"))?;
        newest = newest.max(modified);
        apply(&mut index, id, entries);
    }
    index.modified = (!newest.is_empty()).then_some(newest);
    Ok(index)
}

/// IDs changed after `since`, newest first; None when there are too many.
fn changed_since(csv: &str, since: &str, source: &Source) -> Option<Vec<(String, String)>> {
    let mut changed = Vec::new();
    for line in csv.lines() {
        let Some((modified, id)) = line.split_once(',') else {
            continue;
        };
        if modified <= since {
            break;
        }
        if source.wants(id) {
            changed.push((modified.to_string(), id.to_string()));
            if changed.len() > MAX_INCREMENTAL {
                return None;
            }
        }
    }
    Some(changed)
}

fn index_path(state: &Path, source: &Source) -> PathBuf {
    state.join(format!("osv-{}.json.gz", source.slug()))
}

/// Brings one ecosystem's index up to date and saves it.
pub async fn update(
    client: &reqwest::Client,
    cache: &Path,
    state: &Path,
    source: &Source,
    catalog: &Catalog,
    full: bool,
    offline: bool,
) -> Result<Index> {
    let path = index_path(state, source);
    let mut index: Index = if full {
        Index::default()
    } else {
        crate::read_gzip_json(&path)?
    };
    let directory = cache.join("osv");
    std::fs::create_dir_all(&directory)?;
    let archive = directory.join(format!("{}.zip", source.slug()));
    let incremental = match (&index.modified, offline) {
        (_, true) | (None, false) => None,
        (Some(since), false) => {
            let csv = crate::sources::cached(
                client,
                &source.url("modified_id.csv"),
                &directory.join(format!("{}-modified_id.csv", source.slug())),
                false,
            )
            .await?;
            changed_since(&String::from_utf8_lossy(&csv), since, source)
                .map(|changed| (changed, csv))
        }
    };
    match incremental {
        Some((changed, csv)) => {
            for (_, id) in changed.iter().rev() {
                match crate::sources::get(client, &source.url(&format!("{id}.json")), true).await {
                    Ok(json) => {
                        let (id, _, entries) =
                            parse_record(&json, catalog).with_context(|| format!("OSV {id}"))?;
                        apply(&mut index, id, entries);
                    }
                    Err(error) => eprintln!("warning: OSV {id}: {error}"),
                }
            }
            if let Some((newest, _)) = String::from_utf8_lossy(&csv)
                .lines()
                .next()
                .and_then(|line| line.split_once(','))
            {
                index.modified = Some(newest.to_string());
            }
            eprintln!(
                "OSV {}: {} changed records",
                source.directory,
                changed.len()
            );
        }
        None => {
            if !offline || !archive.exists() {
                crate::sources::download(client, &source.url("all.zip"), &archive, offline).await?;
            }
            let previous = index.modified.take();
            index = read_archive(&archive, source, catalog)?;
            if offline {
                index.modified = previous.or(index.modified);
            }
            eprintln!(
                "OSV {}: {} records from all.zip",
                source.directory,
                index.records.len()
            );
        }
    }
    crate::write_gzip_json(&path, &index)?;
    Ok(index)
}

/// Affected versions per (CVE, product) across records. Red Hat lists a CVE
/// again in later errata and per minor stream; the latest stream counts,
/// and within it the first fix ("below X") does.
pub fn merge(indexes: &[&Index]) -> BTreeMap<(String, String), Vec<Span>> {
    let mut best: BTreeMap<(String, String), (Option<u32>, Vec<Span>)> = BTreeMap::new();
    for entry in indexes
        .iter()
        .flat_map(|index| index.records.values())
        .flatten()
    {
        let key = (entry.cve.clone(), entry.product.clone());
        let scheme = scheme(&entry.product);
        match best.get_mut(&key) {
            None => {
                best.insert(key, (entry.stream, entry.spans.clone()));
            }
            Some((stream, spans)) => match entry.stream.cmp(stream) {
                Ordering::Greater => {
                    *stream = entry.stream;
                    *spans = entry.spans.clone();
                }
                Ordering::Less => {}
                Ordering::Equal => {
                    let below = |spans: &[Span]| {
                        spans.len() == 1 && spans[0].start.is_none() && !spans[0].end_inclusive
                    };
                    if below(spans) && below(&entry.spans) {
                        let (known, new) = (&spans[0].end, &entry.spans[0].end);
                        if let (Some(known), Some(new)) = (known, new) {
                            if scheme.compare(new, known) == Ordering::Less {
                                *spans = entry.spans.clone();
                            }
                        }
                    } else {
                        for span in &entry.spans {
                            if !spans.contains(span) {
                                spans.push(span.clone());
                            }
                        }
                    }
                }
            },
        }
    }
    best.into_iter()
        .map(|(key, (_, spans))| (key, spans))
        .collect()
}

/// Feed product for a Linux product key.
pub fn feed_product(catalog: &Catalog, key: &str) -> Option<Product> {
    let (kind, rest) = key.split_once(':')?;
    let (distro, rest) = rest.split_once(':')?;
    let (release, package) = rest.split_once(':')?;
    let ecosystem = match (kind, distro) {
        ("deb", "debian") => format!("Debian:{release}"),
        ("deb", "ubuntu") => format!("Ubuntu:{release}:LTS"),
        ("rpm", "rhel") => format!("Red Hat:enterprise_linux:{release}"),
        ("rpm", "almalinux") => format!("AlmaLinux:{release}"),
        ("rpm", "rocky") => format!("Rocky Linux:{release}"),
        _ => return None,
    };
    let (product_key, matcher, _) = product(catalog, &ecosystem, package)?;
    let label = match distro {
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "rhel" => "RHEL",
        "almalinux" => "AlmaLinux",
        _ => "Rocky Linux",
    };
    Some(Product {
        key: product_key,
        name: format!("{package} ({label} {release})"),
        matchers: vec![matcher],
        confidence: Confidence::Curated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml")).unwrap()
    }

    #[test]
    fn records_become_entries_for_published_releases() {
        let debian = serde_json::json!({
            "id": "DEBIAN-CVE-2024-6387", "modified": "2026-01-01T00:00:00Z",
            "upstream": ["CVE-2024-6387"],
            "affected": [
                {"package": {"name": "openssh", "ecosystem": "Debian:12"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u3"}]}]},
                {"package": {"name": "openssh", "ecosystem": "Debian:14"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
            ]
        });
        let (id, _, entries) = parse_record(debian.to_string().as_bytes(), &catalog()).unwrap();
        assert_eq!(id, "DEBIAN-CVE-2024-6387");
        // Debian 14 is not a published release.
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].cve, "CVE-2024-6387");
        assert_eq!(entries[0].product, "deb:debian:12:openssh");
        let entry = crate::feed::Affected {
            cve: entries[0].cve.clone(),
            product: entries[0].product.clone(),
            spans: entries[0].spans.clone(),
            default_affected: false,
            fixed: None,
            fix_url: None,
            scheme: scheme(&entries[0].product),
        };
        assert_eq!(entry.affects("1:9.2p1-2+deb12u2"), Some(true));
        assert_eq!(entry.affects("1:9.2p1-2+deb12u3"), Some(false));

        let ubuntu = serde_json::json!({
            "id": "UBUNTU-CVE-2024-6387", "upstream": ["CVE-2024-6387"],
            "affected": [
                {"package": {"name": "openssh", "ecosystem": "Ubuntu:24.04:LTS"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.6p1-3ubuntu13.3"}]}]},
                {"package": {"name": "openssh", "ecosystem": "Ubuntu:Pro:16.04:LTS"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
            ]
        });
        let (_, _, entries) = parse_record(ubuntu.to_string().as_bytes(), &catalog()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].product, "deb:ubuntu:24.04:openssh");

        let redhat = serde_json::json!({
            "id": "RHSA-2024:0001", "upstream": ["CVE-2023-1", "CVE-2023-2"],
            "affected": [
                {"package": {"name": "thunderbird", "ecosystem": "Red Hat:enterprise_linux:9::appstream"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:115.6.0-1.el9_3"}]}]},
                {"package": {"name": "thunderbird-debuginfo", "ecosystem": "Red Hat:enterprise_linux:9::appstream"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:115.6.0-1.el9_3"}]}]},
                {"package": {"name": "thunderbird", "ecosystem": "Red Hat:rhel_eus:9.4::appstream"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:115.6.0-1.el9_4"}]}]}
            ]
        });
        let (_, _, entries) = parse_record(redhat.to_string().as_bytes(), &catalog()).unwrap();
        let keys: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| (e.cve.as_str(), e.product.as_str()))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("CVE-2023-1", "rpm:rhel:9:thunderbird"),
                ("CVE-2023-2", "rpm:rhel:9:thunderbird")
            ]
        );

        let alma = serde_json::json!({
            "id": "ALSA-2024:0001", "related": ["CVE-2023-1"],
            "affected": [{"package": {"name": "thunderbird", "ecosystem": "AlmaLinux:9"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "115.6.0-1.el9_3.alma"}]}]}]
        });
        let (_, _, entries) = parse_record(alma.to_string().as_bytes(), &catalog()).unwrap();
        assert_eq!(entries[0].product, "rpm:almalinux:9:thunderbird");

        let withdrawn = serde_json::json!({"id": "RHSA-1", "withdrawn": "2024-01-01T00:00:00Z",
            "upstream": ["CVE-1"], "affected": redhat["affected"]});
        assert!(parse_record(withdrawn.to_string().as_bytes(), &catalog())
            .unwrap()
            .2
            .is_empty());
    }

    #[test]
    fn events_become_spans() {
        let range: Range =
            serde_json::from_value(serde_json::json!({"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.0-2"},
            {"introduced": "2.0-1"}, {"last_affected": "2.0-5"},
            {"introduced": "3.0-1"}]}))
            .unwrap();
        let spans = spans(&range);
        assert_eq!(spans.len(), 3);
        assert_eq!(
            (spans[0].start.as_deref(), spans[0].end.as_deref()),
            (None, Some("1.0-2"))
        );
        assert!(spans[1].end_inclusive);
        assert_eq!(spans[2].end, None);
    }

    #[test]
    fn later_streams_and_first_fixes_win() {
        let entry = |product: &str, fixed: &str, stream: Option<u32>| Entry {
            cve: "CVE-1".into(),
            product: product.into(),
            spans: vec![span(None, Some(fixed.into()), false)],
            stream,
        };
        let mut a = Index::default();
        a.records.insert(
            "RHSA-1".into(),
            vec![
                entry("rpm:rhel:9:pkg", "0:1.0-2.el9", Some(0)),
                entry("rpm:rhel:10:pkg", "0:1.0-2.el10_0", Some(0)),
            ],
        );
        let mut b = Index::default();
        b.records.insert(
            "RHSA-2".into(),
            vec![
                entry("rpm:rhel:9:pkg", "0:1.0-5.el9", Some(0)),
                entry("rpm:rhel:10:pkg", "0:1.0-4.el10_2", Some(2)),
            ],
        );
        let merged = merge(&[&a, &b]);
        let end = |product: &str| {
            merged[&("CVE-1".to_string(), product.to_string())][0]
                .end
                .clone()
                .unwrap()
        };
        assert_eq!(end("rpm:rhel:9:pkg"), "0:1.0-2.el9");
        assert_eq!(end("rpm:rhel:10:pkg"), "0:1.0-4.el10_2");
    }

    #[test]
    fn modified_lists_are_read_until_the_last_run() {
        let csv = "2026-10-29T02:00:00Z,RHSA-3\n2026-10-29T01:00:00Z,RHBA-9\n2026-10-28T00:00:00Z,RHSA-2\n2026-10-27T00:00:00Z,RHSA-1\n";
        let changed = changed_since(csv, "2026-10-28T00:00:00Z", &SOURCES[2]).unwrap();
        assert_eq!(
            changed,
            vec![("2026-10-29T02:00:00Z".to_string(), "RHSA-3".to_string())]
        );
    }

    #[test]
    fn linux_product_keys_round_trip() {
        let product = feed_product(&catalog(), "deb:ubuntu:24.04:openssh").unwrap();
        assert_eq!(product.name, "openssh (Ubuntu 24.04)");
        assert!(matches!(
            &product.matchers[0],
            Matcher::DebPackage { distro, release, source }
                if distro == "ubuntu" && release == "24.04" && source == "openssh"
        ));
        assert!(feed_product(&catalog(), "rpm:rocky:9:kernel").is_some());
        assert!(feed_product(&catalog(), "rpm:rhel:6:kernel").is_none());
    }
}
