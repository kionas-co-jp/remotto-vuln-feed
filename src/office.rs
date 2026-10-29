//! Microsoft 365 Apps and Click-to-Run Office fixes from Microsoft's
//! "Release notes for Microsoft 365 Apps Security Updates": each Patch
//! Tuesday lists the fixed build of every update channel and edition
//! ("Current Channel: Version 2609 (Build 20430.20182)") and the CVEs it
//! fixes. MSRC names no builds for these products.
use crate::catalog::Catalog;
use crate::feed::{Affected, Span, VersionScheme};
use anyhow::Result;
use chrono::NaiveDate;
use std::{collections::BTreeMap, path::Path};

pub const RELEASE_NOTES_URL: &str =
    "https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates";

/// One monthly security release.
#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub date: NaiveDate,
    /// (channel or edition, build major, build minor): "16.0.<major>.<minor>".
    pub builds: Vec<(String, u32, u32)>,
    pub cves: Vec<String>,
}

/// The page's text, one line per element.
fn text_lines(html: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        current.push_str(&rest[..start]);
        let tag = &rest[start..];
        let lower = tag.get(..8).unwrap_or(tag).to_ascii_lowercase();
        // Skip script and style bodies entirely.
        let close = if lower.starts_with("<script") {
            "</script>"
        } else if lower.starts_with("<style") {
            "</style>"
        } else {
            ">"
        };
        let end = tag
            .to_ascii_lowercase()
            .find(close)
            .map_or(tag.len(), |end| end + close.len());
        lines.push(std::mem::take(&mut current));
        rest = &tag[end..];
    }
    current.push_str(rest);
    lines.push(current);
    lines
        .into_iter()
        .map(|line| {
            line.replace("&nbsp;", " ")
                .replace("&amp;", "&")
                .replace("&#39;", "'")
                .replace("&quot;", "\"")
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .trim()
                .to_string()
        })
        .filter(|line| !line.is_empty())
        .collect()
}

/// "Current Channel: Version 2609 (Build 20430.20182)".
fn build_line(line: &str) -> Option<(String, u32, u32)> {
    let (label, rest) = line.split_once(": Version ")?;
    let build = rest.split_once("(Build ")?.1.strip_suffix(')')?;
    let (major, minor) = build.split_once('.')?;
    Some((
        label.trim().to_string(),
        major.parse().ok()?,
        minor.parse().ok()?,
    ))
}

fn is_cve(line: &str) -> bool {
    line.strip_prefix("CVE-").is_some_and(|rest| {
        let mut parts = rest.split('-');
        let (year, number) = (parts.next(), parts.next());
        parts.next().is_none()
            && [year, number].iter().all(|part| {
                part.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            })
    })
}

pub fn parse(html: &str) -> Vec<Release> {
    let mut releases: Vec<Release> = Vec::new();
    for line in text_lines(html) {
        if let Ok(date) = NaiveDate::parse_from_str(&line, "%B %d, %Y") {
            releases.push(Release {
                date,
                builds: Vec::new(),
                cves: Vec::new(),
            });
        } else if let Some(release) = releases.last_mut() {
            if let Some(build) = build_line(&line) {
                release.builds.push(build);
            } else if is_cve(&line) {
                release.cves.push(line);
            }
        }
    }
    releases.retain(|release| !release.builds.is_empty() && !release.cves.is_empty());
    releases
}

fn build(major: u32, minor: &str) -> String {
    format!("16.0.{major}.{minor}")
}

/// Whether a release notes label ("Semi-Annual Enterprise Channel
/// (Preview)") is one of a product's channels ("Semi-Annual").
fn listed(channels: &[String], label: &str) -> bool {
    channels
        .iter()
        .any(|channel| label.starts_with(channel.as_str()))
}

/// Versions a release leaves affected on the given channels: every build
/// before the newest fixed build, except each line's fixed build and later.
/// Builds of lines the release does not list (out of support, superseded)
/// count as affected; newer lines (previews) as fixed.
fn spans(release: &Release, channels: &[String]) -> Vec<Span> {
    let mut fixed: BTreeMap<u32, u32> = BTreeMap::new();
    for (_, major, minor) in release
        .builds
        .iter()
        .filter(|(label, _, _)| listed(channels, label))
    {
        // Channels on one line may differ ("20228.20274" Semi-Annual,
        // "20228.20276" Monthly Enterprise): the earliest fix counts.
        let entry = fixed.entry(*major).or_insert(*minor);
        *entry = (*entry).min(*minor);
    }
    let Some((&newest, &newest_minor)) = fixed.iter().next_back() else {
        return Vec::new();
    };
    let mut spans: Vec<Span> = fixed
        .iter()
        .map(|(major, minor)| Span {
            affected: false,
            start: Some(build(*major, &minor.to_string())),
            start_inclusive: true,
            end: Some(build(*major, "*")),
            end_inclusive: true,
        })
        .collect();
    spans.push(Span {
        affected: true,
        start: None,
        start_inclusive: true,
        end: Some(build(newest, &newest_minor.to_string())),
        end_inclusive: false,
    });
    spans
}

/// Fixes of every CVE for the catalog products with `office_channels`,
/// from the first release listing it.
pub fn affected(catalog: &Catalog, releases: &[Release]) -> Vec<Affected> {
    let products: Vec<(&str, &[String])> = catalog
        .products
        .iter()
        .filter(|entry| !entry.office_channels.is_empty())
        .map(|entry| (entry.key.as_str(), entry.office_channels.as_slice()))
        .collect();
    let mut first: BTreeMap<&str, &Release> = BTreeMap::new();
    for release in releases {
        for cve in &release.cves {
            let known = first.entry(cve.as_str()).or_insert(release);
            if release.date < known.date {
                *known = release;
            }
        }
    }
    let mut affected = Vec::new();
    for (cve, release) in first {
        for (product, channels) in &products {
            let spans = spans(release, channels);
            if spans.is_empty() {
                continue;
            }
            let mut fixes: Vec<(u32, u32)> = release
                .builds
                .iter()
                .filter(|(label, _, _)| listed(channels, label))
                .map(|(_, major, minor)| (*major, *minor))
                .collect();
            fixes.sort_unstable_by(|a, b| b.cmp(a));
            fixes.dedup_by_key(|(major, _)| *major);
            let fixed = fixes
                .iter()
                .take(3)
                .map(|(major, minor)| format!("{major}.{minor}"))
                .collect::<Vec<_>>()
                .join(", ");
            affected.push(Affected {
                cve: cve.to_string(),
                product: product.to_string(),
                spans,
                default_affected: false,
                fixed: Some(fixed),
                fix_url: Some(RELEASE_NOTES_URL.into()),
                scheme: VersionScheme::Generic,
            });
        }
    }
    affected
}

/// Fixes from the release notes, read from the cached copy when offline;
/// offline runs without a cached copy skip them.
pub async fn update(
    client: &reqwest::Client,
    cache: &Path,
    catalog: &Catalog,
    offline: bool,
) -> Result<Vec<Affected>> {
    let path = cache.join("office-security-updates.html");
    if offline && !path.exists() {
        eprintln!("warning: no cached Microsoft 365 Apps release notes");
        return Ok(Vec::new());
    }
    let html = crate::sources::cached(client, RELEASE_NOTES_URL, &path, offline).await?;
    let releases = parse(&String::from_utf8_lossy(&html));
    if releases.is_empty() {
        anyhow::bail!("No releases in the Microsoft 365 Apps security release notes");
    }
    let affected = affected(catalog, &releases);
    eprintln!(
        "Microsoft 365 Apps: {} releases, {} CVEs",
        releases.len(),
        affected.len()
    );
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<html><head><script>var x = "<h2>October 1, 2000</h2>";</script></head><body>
<h2 id="october-13-2026">October 13, 2026</h2>
<p>Current Channel: Version 2609 (Build 20430.20182)<br>
Monthly Enterprise Channel: Version 2608 (Build 20326.20232)<br>
Semi-Annual Enterprise Channel (receives Monthly Enterprise Channel builds): Version 2607 (Build 20228.20274)<br>
Monthly Enterprise Channel: Version 2607 (Build 20228.20276)<br>
Office LTSC 2021 Volume Licensed: Version 2108 (Build 14334.20974)</p>
<h3>Excel</h3><p>CVE-2026-97003<br>CVE-2026-97004</p>
<h2>September 8, 2026</h2>
<p>Current Channel: Version 2608 (Build 20326.20200)</p>
<p>CVE-2026-90001<br>CVE-2026-97003</p>
</body></html>"#;

    #[test]
    fn release_notes_list_builds_and_cves_per_month() {
        let releases = parse(PAGE);
        assert_eq!(releases.len(), 2);
        assert_eq!(
            releases[0].date,
            NaiveDate::from_ymd_opt(2026, 10, 13).unwrap()
        );
        assert_eq!(releases[0].builds.len(), 5);
        assert_eq!(
            releases[0].builds[2],
            (
                "Semi-Annual Enterprise Channel (receives Monthly Enterprise Channel builds)"
                    .into(),
                20228,
                20274
            )
        );
        assert_eq!(releases[0].cves, vec!["CVE-2026-97003", "CVE-2026-97004"]);
    }

    fn channels() -> Vec<String> {
        [
            "Current Channel",
            "Monthly Enterprise Channel",
            "Semi-Annual",
        ]
        .map(String::from)
        .to_vec()
    }

    #[test]
    fn builds_before_each_lines_fix_are_affected() {
        let releases = parse(PAGE);
        let entry = Affected {
            cve: "CVE-2026-97004".into(),
            product: "office".into(),
            spans: spans(&releases[0], &channels()),
            default_affected: false,
            fixed: None,
            fix_url: None,
            scheme: VersionScheme::Generic,
        };
        for (version, affected) in [
            ("16.0.20430.20160", true),
            ("16.0.20430.20182", false),
            ("16.0.20430.20200", false),
            ("16.0.20326.20230", true),
            ("16.0.20326.20232", false),
            // Semi-Annual's fix on the shared line counts for both channels.
            ("16.0.20228.20274", false),
            // Out-of-support lines.
            ("16.0.19725.20100", true),
            // Previews newer than the newest fix.
            ("16.0.20527.20000", false),
        ] {
            assert_eq!(entry.affects(version), Some(affected), "{version}");
        }
    }

    #[test]
    fn editions_are_judged_by_their_own_lines() {
        // A volume edition whose line moved on (14332 -> 14334) is fixed by
        // its newer line, not mistaken for an old line of another edition.
        let page = r#"<h2>March 10, 2026</h2><p>Office LTSC 2021 Volume Licensed: Version 2108 (Build 14332.20900)</p>
<p>Current Channel: Version 2602 (Build 19725.20100)</p><p>CVE-2026-1</p>"#;
        let release = &parse(page)[0];
        let entry = |channels: &[&str]| Affected {
            cve: "CVE-2026-1".into(),
            product: "office".into(),
            spans: spans(
                release,
                &channels.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ),
            default_affected: false,
            fixed: None,
            fix_url: None,
            scheme: VersionScheme::Generic,
        };
        let ltsc = entry(&["Office LTSC 2021 Volume Licensed"]);
        assert_eq!(ltsc.affects("16.0.14334.20974"), Some(false));
        assert_eq!(ltsc.affects("16.0.14332.20800"), Some(true));
        let apps = entry(&["Current Channel"]);
        assert_eq!(apps.affects("16.0.19725.20000"), Some(true));
        assert_eq!(apps.affects("16.0.20430.20182"), Some(false));
    }

    #[test]
    fn a_cve_counts_from_its_first_release() {
        let catalog =
            Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml")).unwrap();
        let entries = affected(&catalog, &parse(PAGE));
        let cve = entries
            .iter()
            .find(|entry| entry.cve == "CVE-2026-97003")
            .unwrap();
        assert_eq!(cve.product, "microsoft-365-apps");
        assert_eq!(cve.fixed.as_deref(), Some("20326.20200"));
        assert_eq!(cve.affects("16.0.20326.20100"), Some(true));
        assert_eq!(cve.affects("16.0.20430.20182"), Some(false));
        // Microsoft 365 Apps on all three; the 2019 volume edition is not in
        // these releases.
        assert_eq!(entries.len(), 3);
    }
}
