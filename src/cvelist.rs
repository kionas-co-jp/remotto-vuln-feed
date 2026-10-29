//! CVE JSON 5 records from a CVEProject/cvelistV5 checkout, indexed
//! incrementally with `git diff` so a run reparses only changed records.
use crate::catalog::{Catalog, Listing};
use crate::feed::{
    compare_versions, Affected, Confidence, CveRecord, Kev, Matcher, Product, Score, ScoreOrigin,
    Span, Ssvc, VersionScheme,
};
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    process::Command,
};

const MAX_DESCRIPTION_CHARS: usize = 2000;
const MAX_REFERENCES: usize = 8;

/// What a record contributes to the feed. KEV and EPSS are merged later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Parsed {
    pub record: CveRecord,
    pub affected: Vec<Affected>,
    /// Windows releases named by this record.
    #[serde(default)]
    pub windows: Vec<Product>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
    pub commit: Option<String>,
    pub records: BTreeMap<String, Parsed>,
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
                .ok()
                .map(|time| time.and_utc())
        })
}

fn truncate(value: &str, max: usize) -> String {
    let value = value.trim();
    match value.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", &value[..end]),
        None => value.to_string(),
    }
}

/// A usable version from a CVE "version"/"lessThan" field, or None for
/// placeholders such as "0", "*", "n/a" or "unspecified".
fn clean(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches(['<', '>', '=', ' ']).trim();
    // ZDI writes "24.08 (x64)".
    let value = value.split(" (").next().unwrap_or("").trim();
    let lower = value.to_ascii_lowercase();
    let placeholder =
        ["0", "*", "-", "n/a", "na", "unspecified", "unknown", "all"].contains(&lower.as_str());
    (!placeholder && value.chars().any(|c| c.is_ascii_digit()) && !value.contains(' '))
        .then(|| value.to_string())
}

/// GitHub-style expressions: "< 2.43.7", ">= 2.44.0-rc0, < 2.44.4".
fn constraint(expression: &str, affected: bool) -> Option<Span> {
    let mut span = Span {
        affected,
        start: None,
        start_inclusive: true,
        end: None,
        end_inclusive: false,
    };
    for part in expression
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (operator, version) = ["<=", ">=", "<", ">", "="]
            .iter()
            .find_map(|operator| part.strip_prefix(operator).map(|rest| (*operator, rest)))?;
        let version = clean(version)?;
        match operator {
            "<" => (span.end, span.end_inclusive) = (Some(version), false),
            "<=" => (span.end, span.end_inclusive) = (Some(version), true),
            ">" => (span.start, span.start_inclusive) = (Some(version), false),
            ">=" => (span.start, span.start_inclusive) = (Some(version), true),
            _ => {
                span.start = Some(version.clone());
                span.end = Some(version);
                span.end_inclusive = true;
            }
        }
    }
    (span.start.is_some() || span.end.is_some()).then_some(span)
}

fn span(entry: &Value) -> Option<Span> {
    let affected = match text(entry, "status") {
        "affected" => true,
        "unaffected" => false,
        _ => return None,
    };
    if text(entry, "versionType").eq_ignore_ascii_case("git") {
        return None;
    }
    let version = text(entry, "version");
    let less = entry.get("lessThan").and_then(Value::as_str);
    let less_equal = entry.get("lessThanOrEqual").and_then(Value::as_str);
    if less.is_none() && less_equal.is_none() && version.trim_start().starts_with(['<', '>', '=']) {
        return constraint(version, affected);
    }
    let mut start = clean(version);
    let (end, end_inclusive) = match (less, less_equal) {
        (Some(bound), _) | (None, Some(bound)) if bound.trim() == "*" => (None, false),
        (Some(bound), _) => (Some(clean(bound)?), false),
        (None, Some(bound)) => (Some(clean(bound)?), true),
        // A single version.
        (None, None) => (Some(start.clone()?), true),
    };
    // Google writes "version X, lessThan X" for "below X".
    if less.is_some() && start == end {
        start = None;
    }
    Some(Span {
        affected,
        start,
        start_inclusive: true,
        end,
        end_inclusive,
    })
}

fn major(version: &str) -> Option<u64> {
    version
        .split(|c: char| !c.is_ascii_digit())
        .find(|part| !part.is_empty())?
        .parse()
        .ok()
}

/// Apple lists one "below X" range per release line ("< 13.7.5", "< 14.7.5",
/// "< 15.3"); without lower bounds a patched 14.7.5 would fall below 15.3.
fn branch_ranges(spans: &mut [Span]) {
    let open: Vec<usize> = (0..spans.len()).filter(|&i| spans[i].affected).collect();
    if open.len() < 2
        || open
            .iter()
            .any(|&i| spans[i].start.is_some() || spans[i].end.is_none())
    {
        return;
    }
    let mut ordered = open;
    ordered.sort_by(|&a, &b| {
        compare_versions(
            spans[a].end.as_deref().unwrap(),
            spans[b].end.as_deref().unwrap(),
        )
    });
    let mut previous = None;
    for index in ordered {
        let current = spans[index].end.as_deref().and_then(major);
        if let (Some(previous), Some(current)) = (previous, current) {
            if current > previous {
                spans[index].start = Some(current.to_string());
            }
        }
        previous = current.or(previous);
    }
}

/// Oracle's notation: each listed version is the newest affected version of
/// its release line, so "8u451" covers 8u0..=8u451 and "17.0.15" covers
/// 17.0.0..=17.0.15. Values may name several products ("Java SE: 7u251,
/// 8u241, 11.0.6", "Oracle Java SE:8u311", "Oracle GraalVM ...:21.3.0");
/// only Java SE ones count, without the separate "-perf" packs. Unlisted
/// lines are not affected: Oracle does not assess end-of-life releases.
fn latest_per_line(entry: &Value) -> Option<Vec<Span>> {
    let mut spans = Vec::new();
    for version in entry
        .get("versions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|version| text(version, "status") == "affected")
    {
        let raw = text(version, "version");
        let (prefix, list) = match raw.rsplit_once(':') {
            Some((prefix, list)) => (prefix.trim(), list),
            None => ("", raw),
        };
        let lower = prefix.to_ascii_lowercase();
        if !prefix.is_empty()
            && (!lower.contains("java se")
                || lower.contains("embedded")
                || lower.contains("graalvm"))
        {
            continue;
        }
        for value in list.split(',').map(str::trim) {
            if value.is_empty()
                || value.contains('-')
                || !value.starts_with(|c: char| c.is_ascii_digit())
            {
                continue;
            }
            // "8u451" -> "8u0"; "17.0.15" -> "17.0.0"; "27" -> just 27.
            let start = if let Some((release, _)) = value.split_once('u') {
                format!("{release}u0")
            } else {
                let parts: Vec<&str> = value.split('.').collect();
                if parts.len() >= 2 {
                    format!("{}.{}.0", parts[0], parts[1])
                } else {
                    value.to_string()
                }
            };
            spans.push(Span {
                affected: true,
                start: Some(start),
                start_inclusive: true,
                end: Some(value.to_string()),
                end_inclusive: true,
            });
        }
    }
    (!spans.is_empty()).then_some(spans)
}

/// Spans and default status of an "affected" entry; None when unusable.
fn entry_spans(
    entry: &Value,
    transform: &dyn Fn(&str) -> Option<String>,
) -> Option<(Vec<Span>, bool)> {
    let mut spans: Vec<Span> = entry
        .get("versions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(span)
        .filter_map(|mut span| {
            span.start = match span.start {
                Some(start) => Some(transform(&start)?),
                None => None,
            };
            span.end = match span.end {
                Some(end) => Some(transform(&end)?),
                None => None,
            };
            Some(span)
        })
        .collect();
    if spans.is_empty() {
        return None;
    }
    branch_ranges(&mut spans);
    // Some CNAs set defaultStatus "affected" next to explicit upper bounds;
    // honour it only for records that list nothing but fixed releases.
    let any_affected = spans.iter().any(|span| span.affected);
    let default_affected = !any_affected && text(entry, "defaultStatus") != "unaffected";
    Some((spans, default_affected))
}

/// The fixes worth showing: upper bounds of affected ranges, else the first
/// fixed release of each line.
pub fn fixed_text(spans: &[Span]) -> Option<String> {
    let mut fixes: Vec<&str> = spans
        .iter()
        .filter(|span| span.affected && !span.end_inclusive)
        .filter_map(|span| span.end.as_deref())
        .collect();
    if fixes.is_empty() {
        fixes = spans
            .iter()
            .filter(|span| !span.affected)
            .filter_map(|span| span.start.as_deref())
            .collect();
    }
    fixes.retain(|fix| !fix.contains('*'));
    fixes.sort_by(|a, b| compare_versions(b, a));
    fixes.dedup();
    fixes.truncate(3);
    (!fixes.is_empty()).then(|| fixes.join(", "))
}

/// Windows release named by Microsoft's CVE product and version, e.g.
/// ("Windows 11 Version 24H2", "10.0.26100.0") -> (false, 26100).
fn windows_release(vendor: &str, product: &str, version: &str) -> Option<(bool, u32, String)> {
    if !vendor.trim().eq_ignore_ascii_case("microsoft") {
        return None;
    }
    let lower = product.trim().to_ascii_lowercase();
    let server = lower.starts_with("windows server");
    if !(server || lower.starts_with("windows 10") || lower.starts_with("windows 11")) {
        return None;
    }
    let build = version
        .trim()
        .strip_prefix("10.0.")?
        .split('.')
        .next()?
        .parse()
        .ok()?;
    let name = product
        .trim()
        .replace(" (Server Core installation)", "")
        .replace(" version ", " Version ");
    Some((server, build, name))
}

fn windows_version(build: u32) -> impl Fn(&str) -> Option<String> {
    move |version: &str| {
        let rest = version.trim().strip_prefix("10.0.")?;
        (rest.split('.').next()?.parse::<u32>().ok()? == build).then(|| rest.to_string())
    }
}

fn scores(container: &Value, origin: ScoreOrigin, provider: &str) -> Vec<Score> {
    let mut scores = Vec::new();
    for metric in container
        .get("metrics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for (key, version) in [
            ("cvssV4_0", "4.0"),
            ("cvssV3_1", "3.1"),
            ("cvssV3_0", "3.0"),
            ("cvssV2_0", "2.0"),
        ] {
            let Some(cvss) = metric.get(key) else {
                continue;
            };
            let Some(base_score) = cvss.get("baseScore").and_then(Value::as_f64) else {
                continue;
            };
            let score = Score {
                origin,
                provider: provider.to_string(),
                version: version.into(),
                base_score: base_score as f32,
                vector: cvss
                    .get("vectorString")
                    .and_then(Value::as_str)
                    .map(|vector| truncate(vector, 200)),
            };
            if !scores.contains(&score) {
                scores.push(score);
            }
        }
    }
    scores
}

fn adp_extras(adp: &Value, ssvc: &mut Option<Ssvc>, kev: &mut Option<Kev>) {
    for metric in adp
        .get("metrics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(other) = metric.get("other") else {
            continue;
        };
        let content = other.get("content").unwrap_or(&Value::Null);
        match text(other, "type") {
            "ssvc" => {
                let option = |name: &str| {
                    content
                        .get("options")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .find_map(|option| option.get(name).and_then(Value::as_str))
                        .map(str::to_ascii_lowercase)
                };
                if let Some(exploitation) = option("Exploitation") {
                    *ssvc = Some(Ssvc {
                        exploitation,
                        automatable: option("Automatable").map(|value| value == "yes"),
                        technical_impact: option("Technical Impact"),
                    });
                }
            }
            "kev" => {
                if let Ok(added) = NaiveDate::parse_from_str(text(content, "dateAdded"), "%Y-%m-%d")
                {
                    kev.get_or_insert(Kev {
                        added,
                        due: None,
                        ransomware: false,
                    });
                }
            }
            _ => {}
        }
    }
}

fn references(containers: &[&Value]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for container in containers {
        for reference in container
            .get("references")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let url = text(reference, "url").trim();
            if (url.starts_with("https://") || url.starts_with("http://"))
                && url.len() <= 500
                && !urls.iter().any(|known| known == url)
            {
                urls.push(url.to_string());
            }
        }
    }
    urls.truncate(MAX_REFERENCES);
    urls
}

fn merge(
    affected: &mut Vec<Affected>,
    cve: &str,
    product: &str,
    spans: Vec<Span>,
    default_affected: bool,
) {
    match affected.iter_mut().find(|entry| entry.product == product) {
        Some(entry) => {
            for span in spans {
                if !entry.spans.contains(&span) {
                    entry.spans.push(span);
                }
            }
            entry.default_affected |= default_affected;
            entry.fixed = fixed_text(&entry.spans);
        }
        None => affected.push(Affected {
            cve: cve.to_string(),
            product: product.to_string(),
            fixed: fixed_text(&spans),
            spans,
            default_affected,
            fix_url: None,
            scheme: VersionScheme::Generic,
        }),
    }
}

/// Parses one CVE JSON 5 document. None for rejected or unrelated records.
#[cfg(test)]
pub fn parse(document: &Value, catalog: &Catalog) -> Option<Parsed> {
    parse_record(document, catalog, true)
}

fn parse_record(document: &Value, catalog: &Catalog, require_affected: bool) -> Option<Parsed> {
    let metadata = document.get("cveMetadata")?;
    if !text(metadata, "state").eq_ignore_ascii_case("PUBLISHED") {
        return None;
    }
    let id = text(metadata, "cveId").to_string();
    let containers = document.get("containers")?;
    let cna = containers.get("cna")?;
    let adps: Vec<&Value> = containers
        .get("adp")
        .and_then(Value::as_array)
        .map(|adps| adps.iter().collect())
        .unwrap_or_default();

    let mut affected: Vec<Affected> = Vec::new();
    let mut windows: Vec<Product> = Vec::new();
    // ADP entries (e.g. CISA's CPE-based ranges) fill in products the CNA
    // did not describe in comparable terms.
    for (source, container) in
        std::iter::once((true, cna)).chain(adps.iter().map(|adp| (false, *adp)))
    {
        let mut found: Vec<(String, Vec<Span>, bool)> = Vec::new();
        for entry in container
            .get("affected")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let vendor = text(entry, "vendor");
            let product = text(entry, "product");
            let cpes: Vec<String> = entry
                .get("cpes")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
            let selected = catalog.select(vendor, product, &cpes);
            for selected in &selected {
                let spans = match selected.versions {
                    Listing::Ranges => entry_spans(entry, &|v| Some(v.to_string())),
                    Listing::LatestPerLine => latest_per_line(entry).map(|spans| (spans, false)),
                };
                if let Some((spans, default_affected)) = spans {
                    found.push((selected.key.clone(), spans, default_affected));
                }
            }
            // Products the catalog does not curate: the CNA's or CISA's
            // versions under each application CPE named, for the inferred
            // products of the "main" channel (`crate::translate`).
            if selected.is_empty() {
                let mut named: Vec<String> = cpes
                    .iter()
                    .filter(|cpe| cpe.starts_with("cpe:2.3:a:"))
                    .filter_map(|cpe| crate::catalog::cpe_product(cpe))
                    .collect();
                named.sort();
                named.dedup();
                for vendor_product in named {
                    if let Some((spans, default_affected)) =
                        entry_spans(entry, &|v| Some(v.to_string()))
                    {
                        found.push((
                            crate::translate::product_key(&vendor_product),
                            spans,
                            default_affected,
                        ));
                    }
                }
            }
            for version in entry
                .get("versions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let Some((server, build, name)) =
                    windows_release(vendor, product, text(version, "version"))
                else {
                    continue;
                };
                let key = format!(
                    "windows-{}-{build}",
                    if server { "server" } else { "client" }
                );
                let single = serde_json::json!({"versions": [version]});
                if let Some((spans, default_affected)) =
                    entry_spans(&single, &windows_version(build))
                {
                    found.push((key.clone(), spans, default_affected));
                    if !windows.iter().any(|product| product.key == key) {
                        windows.push(Product {
                            key,
                            name,
                            matchers: vec![Matcher::Windows { server, build }],
                            confidence: Confidence::Curated,
                        });
                    }
                }
            }
        }
        for (product, spans, default_affected) in found {
            // The CNA's description of a product wins over ADP additions.
            if !source && affected.iter().any(|entry| entry.product == product) {
                continue;
            }
            merge(&mut affected, &id, &product, spans, default_affected);
        }
    }
    if require_affected && affected.is_empty() {
        return None;
    }

    let provider = cna
        .get("providerMetadata")
        .map(|metadata| text(metadata, "shortName"))
        .unwrap_or("")
        .to_string();
    let mut all_scores = scores(cna, ScoreOrigin::Cna, &provider);
    let mut ssvc = None;
    let mut kev = None;
    for adp in &adps {
        let provider = adp
            .get("providerMetadata")
            .map(|metadata| text(metadata, "shortName"))
            .unwrap_or("ADP");
        for score in scores(adp, ScoreOrigin::Adp, provider) {
            if !all_scores.contains(&score) {
                all_scores.push(score);
            }
        }
        adp_extras(adp, &mut ssvc, &mut kev);
    }
    let description = cna
        .get("descriptions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|description| {
            text(description, "lang")
                .to_ascii_lowercase()
                .starts_with("en")
        })
        .map(|description| truncate(text(description, "value"), MAX_DESCRIPTION_CHARS))
        .unwrap_or_default();
    let title = Some(truncate(text(cna, "title"), 300)).filter(|title| !title.is_empty());
    let mut containers = vec![cna];
    containers.extend(adps.iter().copied());
    let references = references(&containers);
    // Oracle names no fixed version: point to its Critical Patch Update.
    if let Some(advisory) = references
        .iter()
        .find(|url| url.contains("oracle.com/security-alerts/"))
    {
        for entry in affected.iter_mut().filter(|entry| {
            catalog.products.iter().any(|product| {
                product.key == entry.product && product.versions == Listing::LatestPerLine
            })
        }) {
            entry.fix_url = Some(advisory.clone());
        }
    }
    Some(Parsed {
        record: CveRecord {
            id,
            published: timestamp(text(metadata, "datePublished")),
            modified: timestamp(text(metadata, "dateUpdated")),
            title,
            description,
            scores: all_scores,
            epss: None,
            kev,
            ssvc,
            references,
        },
        affected,
        windows,
    })
}

fn parse_file(path: &Path, catalog: &Catalog, require_affected: bool) -> Result<Option<Parsed>> {
    let bytes = std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let document: Value = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(error) => {
            eprintln!("warning: skipping {}: {error}", path.display());
            return Ok(None);
        }
    };
    Ok(parse_record(&document, catalog, require_affected))
}

/// cves/2025/10xxx/CVE-2025-10585.json for CVE-2025-10585.
pub fn record_path(repo: &Path, id: &str) -> Option<PathBuf> {
    let mut parts = id.split('-');
    let (_, year, number) = (parts.next()?, parts.next()?, parts.next()?);
    let thousands = number.parse::<u64>().ok()? / 1000;
    Some(
        repo.join("cves")
            .join(year)
            .join(format!("{thousands}xxx"))
            .join(format!("{id}.json")),
    )
}

/// A published record by ID, even when the catalog selects none of its
/// products (MSRC, NVD or a distribution names the product instead).
pub fn load_any(repo: &Path, id: &str, catalog: &Catalog) -> Result<Option<Parsed>> {
    match record_path(repo, id) {
        Some(path) if path.exists() => parse_file(&path, catalog, false),
        _ => Ok(None),
    }
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn walk(directory: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("Cannot list {}", directory.display()))?
    {
        let path = entry?.path();
        if path.is_dir() {
            walk(&path, files)?;
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("CVE-") && name.ends_with(".json"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn id_of(path: &Path) -> Option<String> {
    path.file_stem()?.to_str().map(String::from)
}

/// Brings the index up to date. With a known previous commit only the files
/// `git diff` reports are reparsed; otherwise (first run, a non-git copy or a
/// catalog change) every record is. Records are kept when the catalog
/// selects one of their products or when another source (NVD, OSV) names
/// them in `wanted`.
pub fn update(
    repo: &Path,
    catalog: &Catalog,
    wanted: &HashSet<String>,
    index: &mut Index,
    full: bool,
) -> Result<usize> {
    let head = git(repo, &["rev-parse", "HEAD"]).map(|head| head.trim().to_string());
    let changed = match (&index.commit, &head) {
        _ if full => None,
        (Some(old), Some(new)) if old == new => Some(Vec::new()),
        (Some(old), Some(new)) => git(
            repo,
            &[
                "diff",
                "--name-only",
                "--no-renames",
                old,
                new,
                "--",
                "cves",
            ],
        )
        .map(|output| {
            output
                .lines()
                .map(|line| repo.join(line))
                .collect::<Vec<_>>()
        }),
        _ => None,
    };
    let files = match changed {
        Some(files) => files,
        None => {
            index.records.clear();
            let mut files = Vec::new();
            walk(&repo.join("cves"), &mut files)?;
            files
        }
    };
    let mut parsed = 0;
    for path in &files {
        let Some(id) = id_of(path) else { continue };
        let record = if path.exists() {
            parse_file(path, catalog, !wanted.contains(&id))?
        } else {
            None
        };
        match record {
            Some(record) => {
                index.records.insert(id, record);
            }
            None => {
                index.records.remove(&id);
            }
        }
        parsed += 1;
    }
    // Newly wanted records from unchanged files, and ones no longer wanted.
    for id in wanted {
        if !index.records.contains_key(id) {
            if let Some(record) = load_any(repo, id, catalog)? {
                index.records.insert(id.clone(), record);
                parsed += 1;
            }
        }
    }
    index.records.retain(|id, record| {
        wanted.contains(id) || !record.affected.is_empty() || !record.windows.is_empty()
    });
    index.commit = head;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml")).unwrap()
    }

    fn document(affected: Value) -> Value {
        serde_json::json!({
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2025-0001", "state": "PUBLISHED",
                "datePublished": "2025-01-02T03:04:05.000Z", "dateUpdated": "2025-02-01T00:00:00"},
            "containers": {
                "cna": {
                    "providerMetadata": {"shortName": "vendor"},
                    "title": "Example",
                    "descriptions": [{"lang": "en", "value": "Bug."}],
                    "affected": affected,
                    "metrics": [{"cvssV3_1": {"baseScore": 8.8, "vectorString": "CVSS:3.1/AV:N"}}],
                    "references": [{"url": "https://example.com/a"}, {"url": "javascript:alert(1)"}]
                },
                "adp": [{
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 9.8}},
                        {"other": {"type": "ssvc", "content": {"options": [
                            {"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}]}}},
                        {"other": {"type": "kev", "content": {"dateAdded": "2025-01-03"}}}
                    ]
                }]
            }
        })
    }

    fn spans_of(parsed: &Parsed, product: &str) -> Vec<Span> {
        parsed
            .affected
            .iter()
            .find(|a| a.product == product)
            .unwrap()
            .spans
            .clone()
    }

    #[test]
    fn records_carry_scores_ssvc_kev_and_safe_references() {
        let parsed = parse(
            &document(serde_json::json!([{"vendor": "Google", "product": "Chrome", "versions": [
                {"version": "140.0.7339.185", "status": "affected", "lessThan": "140.0.7339.185", "versionType": "custom"}]}])),
            &catalog(),
        )
        .unwrap();
        let record = &parsed.record;
        assert_eq!(record.title.as_deref(), Some("Example"));
        assert_eq!(record.scores.len(), 2);
        assert_eq!(record.scores[0].origin, ScoreOrigin::Cna);
        assert_eq!(record.ssvc.as_ref().unwrap().exploitation, "active");
        assert!(record.kev.is_some());
        assert_eq!(record.references, vec!["https://example.com/a"]);
        assert!(record.modified.is_some());
        let affected = &parsed.affected[0];
        assert_eq!(affected.product, "google-chrome");
        assert_eq!(affected.fixed.as_deref(), Some("140.0.7339.185"));
        assert_eq!(affected.affects("140.0.7339.80"), Some(true));
        assert_eq!(affected.affects("140.0.7339.185"), Some(false));
    }

    #[test]
    fn vendor_version_styles_become_comparable_spans() {
        let catalog = catalog();
        let parse_one = |vendor: &str, product: &str, versions: Value, default: Option<&str>| {
            let mut entry =
                serde_json::json!({"vendor": vendor, "product": product, "versions": versions});
            if let Some(default) = default {
                entry["defaultStatus"] = default.into();
            }
            parse(&document(serde_json::json!([entry])), &catalog)
        };

        // Mozilla: fixed release lines only.
        let firefox = parse_one("Mozilla", "Firefox", serde_json::json!([
            {"status": "unaffected", "version": "115.23.1", "lessThanOrEqual": "115.*", "versionType": "rpm"},
            {"status": "unaffected", "version": "138.0.4", "lessThanOrEqual": "*", "versionType": "rpm"}]), None).unwrap();
        let entry = &firefox.affected[0];
        assert!(entry.default_affected);
        assert_eq!(entry.affects("137.0.2"), Some(true));
        assert_eq!(entry.affects("115.23.1"), Some(false));
        assert_eq!(entry.fixed.as_deref(), Some("138.0.4, 115.23.1"));

        // GitHub: constraint expressions.
        let git = parse_one(
            "git",
            "git",
            serde_json::json!([
            {"version": "< 2.43.7", "status": "affected"},
            {"version": ">= 2.44.0-rc0, < 2.44.4", "status": "affected"}]),
            None,
        )
        .unwrap();
        let entry = &git.affected[0];
        assert_eq!(entry.affects("2.43.6"), Some(true));
        assert_eq!(entry.affects("2.43.7"), Some(false));
        assert_eq!(entry.affects("2.44.1"), Some(true));
        assert_eq!(entry.affects("2.44.4"), Some(false));

        // Adobe: defaultStatus "affected" next to an explicit bound is ignored.
        let adobe = parse_one("Adobe", "Acrobat Reader", serde_json::json!([
            {"lessThanOrEqual": "25.001.20428", "status": "affected", "version": "0", "versionType": "semver"}]), Some("affected")).unwrap();
        let entry = &adobe.affected[0];
        assert!(!entry.default_affected);
        assert_eq!(entry.affects("25.001.20428"), Some(true));
        assert_eq!(entry.affects("25.001.20474"), Some(false));

        // LibreOffice: operator inside lessThan; ZDI: exact versions with a suffix.
        let libreoffice = parse_one("The Document Foundation", "LibreOffice", serde_json::json!([
            {"lessThan": "< 24.8.5", "status": "affected", "version": "24.8", "versionType": "24.8 series"}]), Some("unknown")).unwrap();
        assert_eq!(libreoffice.affected[0].affects("24.8.4.2"), Some(true));
        assert_eq!(libreoffice.affected[0].affects("25.2.0"), Some(false));
        let zip = parse_one(
            "7-Zip",
            "7-Zip",
            serde_json::json!([{"version": "24.08 (x64)", "status": "affected"}]),
            Some("unknown"),
        )
        .unwrap();
        assert_eq!(zip.affected[0].affects("24.08"), Some(true));
        assert_eq!(zip.affected[0].affects("24.09"), Some(false));

        // Unusable versions and unrelated products yield nothing.
        assert!(parse_one(
            "Zoom Video Communications, Inc.",
            "Zoom",
            serde_json::json!([{"version": "see references", "status": "affected"}]),
            None
        )
        .is_none());
        assert!(parse_one(
            "Google",
            "Chrome",
            serde_json::json!([{"version": "n/a", "status": "affected"}]),
            None
        )
        .is_none());
    }

    #[test]
    fn apple_release_lines_get_lower_bounds() {
        let parsed = parse(
            &document(serde_json::json!([{"vendor": "Apple", "product": "macOS", "versions": [
                {"version": "0", "status": "affected", "lessThan": "13.7.5", "versionType": "custom"},
                {"version": "0", "status": "affected", "lessThan": "14.7.5", "versionType": "custom"},
                {"version": "0", "status": "affected", "lessThan": "15.3", "versionType": "custom"}]}])),
            &catalog(),
        )
        .unwrap();
        let entry = &parsed.affected[0];
        assert_eq!(
            entry.affects("14.7.5"),
            Some(false),
            "{:?}",
            spans_of(&parsed, "macos")
        );
        assert_eq!(entry.affects("14.7.4"), Some(true));
        assert_eq!(entry.affects("15.2"), Some(true));
        assert_eq!(entry.affects("15.3"), Some(false));
        assert_eq!(entry.affects("12.7"), Some(true));
        assert_eq!(entry.affects("13.7.6"), Some(false));
    }

    #[test]
    fn microsoft_windows_records_become_release_products() {
        let parsed = parse(
            &document(serde_json::json!([
                {"vendor": "Microsoft", "product": "Windows 11 version 24H2", "versions": [
                    {"version": "10.0.26100.0", "lessThan": "10.0.26100.6899", "versionType": "custom", "status": "affected"}]},
                {"vendor": "Microsoft", "product": "Windows Server 2025 (Server Core installation)", "versions": [
                    {"version": "10.0.26100.0", "lessThan": "10.0.26100.6899", "versionType": "custom", "status": "affected"}]},
                {"vendor": "Microsoft", "product": "Windows Server 2008 Service Pack 2", "versions": [
                    {"version": "6.0.6003.0", "lessThan": "6.0.6003.23070", "versionType": "custom", "status": "affected"}]}
            ])),
            &catalog(),
        )
        .unwrap();
        let keys: Vec<&str> = parsed.windows.iter().map(|p| p.key.as_str()).collect();
        assert_eq!(keys, vec!["windows-client-26100", "windows-server-26100"]);
        assert_eq!(parsed.windows[0].name, "Windows 11 Version 24H2");
        assert_eq!(parsed.windows[1].name, "Windows Server 2025");
        let client = parsed
            .affected
            .iter()
            .find(|a| a.product == "windows-client-26100")
            .unwrap();
        assert_eq!(client.affects("26100.6584"), Some(true));
        assert_eq!(client.affects("26100.6899"), Some(false));
        assert_eq!(client.fixed.as_deref(), Some("26100.6899"));
    }

    #[test]
    fn oracle_java_lists_the_newest_affected_version_per_line() {
        let java = |versions: Value| {
            parse(
                &document(serde_json::json!([{
                    "vendor": "Oracle Corporation", "product": "Oracle Java SE", "versions": versions
                }])),
                &catalog(),
            )
            .unwrap()
            .affected
            .remove(0)
        };
        // 2025: one version per entry.
        let entry = java(serde_json::json!([
            {"version": "8u451", "status": "affected"}, {"version": "8u451-perf", "status": "affected"},
            {"version": "17.0.15", "status": "affected"}, {"version": "21.0.7", "status": "affected"},
            {"version": "24.0.1", "status": "affected"}]));
        assert_eq!(entry.product, "oracle-java-se");
        assert_eq!(entry.affects("8u441"), Some(true));
        assert_eq!(entry.affects("8u451"), Some(true));
        assert_eq!(entry.affects("8u461"), Some(false));
        assert_eq!(entry.affects("17.0.14.0"), Some(true));
        assert_eq!(entry.affects("17.0.16.0"), Some(false));
        assert_eq!(entry.affects("24.0.1"), Some(true));
        // Lines not listed (11 here, end-of-life 22) are not assessed.
        assert_eq!(entry.affects("11.0.20"), Some(false));
        assert_eq!(entry.affects("22.0.2"), Some(false));
        // 2020-2024: product prefixes, several products and lists in one value.
        let entry = java(serde_json::json!([
            {"version": "Java SE: 7u251, 8u241, 11.0.6, 14", "status": "affected"},
            {"version": "Java SE Embedded: 8u241", "status": "affected"},
            {"version": "Oracle GraalVM Enterprise Edition:21.3.0", "status": "affected"}]));
        assert_eq!(entry.affects("8u241"), Some(true));
        assert_eq!(entry.affects("7u80"), Some(true));
        assert_eq!(entry.affects("14"), Some(true));
        assert_eq!(entry.affects("14.0.1"), Some(false));
        assert_eq!(entry.affects("21.3.0"), Some(false));
        let entry = java(
            serde_json::json!([{"version": "Oracle Java SE:21.0.12.1", "status": "affected"}]),
        );
        assert_eq!(entry.affects("21.0.12.0"), Some(true));
        assert_eq!(entry.affects("21.0.13.0"), Some(false));
        // Oracle names no fixed version: findings link to the patch update.
        let mut record = document(serde_json::json!([{
            "vendor": "Oracle Corporation", "product": "Oracle Java SE",
            "versions": [{"version": "17.0.15", "status": "affected"}]}]));
        record["containers"]["cna"]["references"] =
            serde_json::json!([{"url": "https://www.oracle.com/security-alerts/cpuapr2025.html"}]);
        let parsed = parse(&record, &catalog()).unwrap();
        assert_eq!(
            parsed.affected[0].fix_url.as_deref(),
            Some("https://www.oracle.com/security-alerts/cpuapr2025.html")
        );
    }

    #[test]
    fn uncurated_products_are_named_by_their_cpes() {
        let parsed = parse(
            &document(serde_json::json!([{
                "vendor": "TeamViewer", "product": "Remote Full Client",
                "cpes": ["cpe:2.3:a:teamviewer:teamviewer:*:*:*:*:*:*:*:*"],
                "versions": [{"version": "0", "lessThan": "15.70.3", "status": "affected", "versionType": "custom"}]
            }])),
            &catalog(),
        )
        .unwrap();
        assert_eq!(parsed.affected.len(), 1);
        assert_eq!(parsed.affected[0].product, "cpe:teamviewer:teamviewer");
        assert_eq!(parsed.affected[0].affects("15.70.2"), Some(true));
        // Curated products keep their catalog keys.
        let chrome = parse(
            &document(serde_json::json!([{
                "vendor": "Google", "product": "Chrome",
                "cpes": ["cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"],
                "versions": [{"version": "0", "lessThan": "141.0", "status": "affected"}]
            }])),
            &catalog(),
        )
        .unwrap();
        assert_eq!(chrome.affected[0].product, "google-chrome");
        assert_eq!(chrome.affected.len(), 1);
    }

    #[test]
    fn rejected_records_and_record_paths() {
        let mut rejected = document(
            serde_json::json!([{"vendor": "Google", "product": "Chrome", "versions": [{"version": "1.0", "status": "affected"}]}]),
        );
        rejected["cveMetadata"]["state"] = "REJECTED".into();
        assert!(parse(&rejected, &catalog()).is_none());
        assert_eq!(
            record_path(Path::new("/repo"), "CVE-2025-10585").unwrap(),
            Path::new("/repo/cves/2025/10xxx/CVE-2025-10585.json")
        );
        assert_eq!(
            record_path(Path::new("/repo"), "CVE-2025-0411").unwrap(),
            Path::new("/repo/cves/2025/0xxx/CVE-2025-0411.json")
        );
    }
}
