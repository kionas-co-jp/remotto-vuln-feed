//! Product catalog (catalog.toml): curated products with their endpoint
//! matchers and CVE selectors, overrides of products inferred from CPE names,
//! and the Linux releases published.
use crate::feed::{Confidence, Matcher, Product};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Selector {
    pub vendor: String,
    pub product: String,
}

/// How a CNA writes the affected versions of a product.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Listing {
    /// CVE JSON 5 versions and ranges.
    #[default]
    Ranges,
    /// Oracle's "supported versions that are affected": the newest affected
    /// version of each release line ("8u451", "17.0.15"); older versions of
    /// that line are affected too.
    LatestPerLine,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    pub key: String,
    pub name: String,
    #[serde(default)]
    pub cve: Vec<Selector>,
    #[serde(default)]
    pub versions: Listing,
    #[serde(default)]
    pub cpe: Vec<String>,
    #[serde(default)]
    pub msrc: Vec<String>,
    /// Channels and editions whose fixed builds the Microsoft 365 Apps
    /// security release notes list for this product ("Current Channel").
    #[serde(default)]
    pub office_channels: Vec<String>,
    #[serde(rename = "match")]
    pub matchers: Vec<Matcher>,
}

/// Adjusts a product inferred from CPE names (`translate`).
#[derive(Debug, Clone, Deserialize)]
pub struct Override {
    /// CPE "vendor:product", escaped as in CPE names.
    pub cpe: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Program names added to the inferred ones (any spelling; normalized).
    #[serde(default)]
    pub names: Vec<String>,
    /// Publishers accepted instead of the CPE vendor.
    #[serde(default)]
    pub publishers: Vec<String>,
    /// Stop matching the product, e.g. after false positives.
    #[serde(default)]
    pub disabled: bool,
    /// Reviewed: findings are no longer shown as inferred.
    #[serde(default)]
    pub curated: bool,
}

/// Linux releases whose distribution data is published.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Linux {
    #[serde(default)]
    pub debian: Vec<String>,
    #[serde(default)]
    pub ubuntu: Vec<String>,
    /// RHEL major releases, also published for AlmaLinux and Rocky Linux.
    #[serde(default)]
    pub rhel: Vec<String>,
}

impl Entry {
    pub fn product(&self) -> Product {
        Product {
            key: self.key.clone(),
            name: self.name.clone(),
            matchers: self.matchers.clone(),
            confidence: Confidence::Curated,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Catalog {
    #[serde(rename = "product")]
    pub products: Vec<Entry>,
    #[serde(default, rename = "override")]
    pub overrides: Vec<Override>,
    #[serde(default)]
    pub linux: Linux,
}

fn same(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

impl Catalog {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read catalog {}", path.display()))?;
        let catalog: Catalog =
            toml::from_str(&text).with_context(|| format!("Invalid catalog {}", path.display()))?;
        let mut keys = std::collections::HashSet::new();
        for entry in &catalog.products {
            if !keys.insert(entry.key.as_str()) {
                bail!("Duplicate catalog product {}", entry.key);
            }
            if entry.key.starts_with("windows-") {
                bail!(
                    "{}: windows-* keys are reserved for derived Windows releases",
                    entry.key
                );
            }
            if entry.matchers.is_empty() {
                bail!("{}: no endpoint matcher", entry.key);
            }
        }
        Ok(catalog)
    }

    /// The curated product that claims a CPE "vendor:product".
    pub fn curated_cpe(&self, vendor_product: &str) -> Option<&Entry> {
        self.products
            .iter()
            .find(|entry| entry.cpe.iter().any(|wanted| same(wanted, vendor_product)))
    }

    pub fn override_for(&self, vendor_product: &str) -> Option<&Override> {
        self.overrides
            .iter()
            .find(|entry| same(&entry.cpe, vendor_product))
    }

    /// Catalog products selected by a CVE "affected" entry.
    pub fn select(&self, vendor: &str, product: &str, cpes: &[String]) -> Vec<&Entry> {
        self.products
            .iter()
            .filter(|entry| {
                entry
                    .cve
                    .iter()
                    .any(|wanted| same(&wanted.vendor, vendor) && same(&wanted.product, product))
                    || entry.cpe.iter().any(|wanted| {
                        same(wanted, &format!("{vendor}:{product}"))
                            || cpes
                                .iter()
                                .any(|cpe| cpe_product(cpe).is_some_and(|name| same(wanted, &name)))
                    })
            })
            .collect()
    }
}

/// "vendor:product" of a CPE 2.3 name such as cpe:2.3:a:google:chrome:*:...
pub fn cpe_product(cpe: &str) -> Option<String> {
    let parts = cpe_fields(cpe)?;
    (parts.len() >= 5).then(|| format!("{}:{}", parts[3], parts[4]))
}

/// Fields of a CPE 2.3 name split on unescaped colons, escapes kept:
/// ["cpe", "2.3", part, vendor, product, version, update, ...].
pub fn cpe_fields(cpe: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in cpe.chars() {
        if escaped {
            current.push('\\');
            current.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ':' {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    parts.push(current);
    (parts.len() >= 5 && parts[0] == "cpe" && parts[1] == "2.3").then_some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_catalog_is_valid_and_selects_by_name_or_cpe() {
        let catalog =
            Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml")).unwrap();
        let keys = |entries: Vec<&Entry>| entries.iter().map(|e| e.key.clone()).collect::<Vec<_>>();
        assert_eq!(
            keys(catalog.select("Google", "Chrome", &[])),
            vec!["google-chrome"]
        );
        assert_eq!(
            keys(catalog.select("mozilla", "firefox", &[])),
            vec!["mozilla-firefox"]
        );
        assert_eq!(
            keys(catalog.select(
                "n/a",
                "n/a",
                &["cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*".into()]
            )),
            vec!["vlc"]
        );
        assert_eq!(keys(catalog.select("putty", "putty", &[])), vec!["putty"]);
        assert_eq!(
            keys(catalog.select(
                "x",
                "y",
                &["cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:8.0:*:*:*:*:*:*:*".into()]
            )),
            vec!["notepad-plus-plus"]
        );
        assert!(catalog.select("Siemens", "CADRA", &[]).is_empty());
    }

    #[test]
    fn cpe_names_split_on_unescaped_colons() {
        assert_eq!(
            cpe_product("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*").as_deref(),
            Some("google:chrome")
        );
        assert_eq!(
            cpe_product("cpe:2.3:a:vendor\\:x:prod:1").as_deref(),
            Some("vendor\\:x:prod")
        );
        assert_eq!(cpe_product("cpe:/a:google:chrome"), None);
    }
}
