//! Products inferred from CPE names, a translation dictionary from CPE names
//! to program names: each CPE "vendor:product" with affected versions becomes
//! a product whose Alias matcher recognises the program names its NVD
//! dictionary titles use, published by the CPE vendor. `[[override]]` entries
//! in the catalog stop, extend or promote them.
use crate::catalog::Catalog;
use crate::feed::{publisher_key, software_key, Confidence, Matcher, Product};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::Read,
    path::Path,
};

pub const DICTIONARY_URL: &str = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz";
/// The dictionary is large and changes slowly.
const DICTIONARY_REFRESH: Duration = Duration::days(7);
/// Names in this share of a product's titles (or the most common one).
const NAME_SHARE: f64 = 0.2;
const MAX_NAMES: usize = 4;

/// Program names per CPE "vendor:product", from dictionary titles.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Names {
    pub fetched_at: Option<DateTime<Utc>>,
    /// vendor:product -> (display name, software keys)
    pub products: BTreeMap<String, (String, Vec<String>)>,
}

#[derive(Deserialize)]
struct Chunk {
    #[serde(default)]
    products: Vec<DictionaryItem>,
}

#[derive(Deserialize)]
struct DictionaryItem {
    cpe: DictionaryEntry,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DictionaryEntry {
    cpe_name: String,
    #[serde(default)]
    titles: Vec<Title>,
}

#[derive(Deserialize)]
struct Title {
    title: String,
    #[serde(default)]
    lang: String,
}

fn unescape(value: &str) -> String {
    value.replace('\\', "")
}

/// Platform notes of dictionary titles ("Zoom 5.0 for Windows").
const PLATFORM_SUFFIXES: &[&str] = &[
    " for windows",
    " for microsoft windows",
    " for mac os x",
    " for macos",
    " for mac",
    " for linux",
];

/// The title without a platform note; None for mobile editions.
fn desktop_title(title: &str) -> Option<String> {
    let lower = title.to_lowercase();
    if ["android", "iphone os", " ios", "ipad"]
        .iter()
        .any(|mobile| lower.contains(mobile))
    {
        return None;
    }
    let cut = PLATFORM_SUFFIXES
        .iter()
        .filter_map(|suffix| lower.find(suffix))
        .min()
        .unwrap_or(title.len());
    Some(title[..cut].trim().to_string()).filter(|title| !title.is_empty())
}

/// "Google Chrome 110.0.5481.77" -> "Google Chrome": the title without its
/// trailing words that carry digits (versions, builds).
fn display_name(title: &str) -> String {
    let mut words: Vec<&str> = title.split_whitespace().collect();
    while words.len() > 1
        && words
            .last()
            .is_some_and(|word| word.chars().any(|c| c.is_ascii_digit()))
    {
        words.pop();
    }
    words.join(" ")
}

/// Program names of a CPE product: its dictionary titles, "vendor product"
/// spelled out and, when specific enough, the product name alone.
fn names_of(vendor_product: &str, titles: &[String]) -> (String, Vec<String>) {
    let (vendor, product) = vendor_product
        .split_once(':')
        .unwrap_or(("", vendor_product));
    let spelled = |value: &str| unescape(value).replace('_', " ");
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut display: HashMap<String, String> = HashMap::new();
    for title in titles.iter().filter_map(|title| desktop_title(title)) {
        let title = title.as_str();
        let key = software_key(title);
        if key.is_empty() {
            continue;
        }
        *counts.entry(key.clone()).or_default() += 1;
        display.entry(key).or_insert_with(|| display_name(title));
    }
    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let total: usize = ranked.iter().map(|(_, count)| count).sum();
    let mut names: BTreeSet<String> = ranked
        .iter()
        .enumerate()
        .filter(|(rank, (_, count))| *rank == 0 || *count as f64 >= total as f64 * NAME_SHARE)
        .take(MAX_NAMES)
        .map(|(_, (key, _))| key.clone())
        .collect();
    names.insert(software_key(&format!(
        "{} {}",
        spelled(vendor),
        spelled(product)
    )));
    // A bare product phrase ("pdf reader" for foxit:pdf_reader) names other
    // vendors' programs too, and macOS matching has no publisher to check:
    // only when no title names the product, when it carries the vendor or
    // when it is one word ("itunes", "forticlient").
    let bare = software_key(&spelled(product));
    if titles.is_empty() || bare.contains(&software_key(&spelled(vendor))) || !bare.contains(' ') {
        names.insert(bare);
    }
    // One- or two-letter and numeric names match far too much.
    names.retain(|name| name.len() >= 3 && name.chars().any(char::is_alphabetic));
    let name = ranked
        .first()
        .and_then(|(key, _)| display.get(key).cloned())
        .unwrap_or_else(|| spelled(product));
    (name, names.into_iter().collect())
}

/// Reads dictionary titles for the wanted products from the tar.gz archive
/// of JSON chunks.
pub fn parse_dictionary(
    archive: &[u8],
    wanted: &BTreeSet<String>,
) -> Result<BTreeMap<String, (String, Vec<String>)>> {
    let mut titles: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    for entry in tar.entries().context("Invalid CPE dictionary")? {
        let mut entry = entry.context("Invalid CPE dictionary")?;
        if !entry.path()?.to_string_lossy().ends_with(".json") {
            continue;
        }
        let mut json = Vec::new();
        entry.read_to_end(&mut json)?;
        let chunk: Chunk = serde_json::from_slice(&json).context("Invalid CPE dictionary chunk")?;
        for DictionaryItem { cpe } in chunk.products {
            let Some(key) = crate::catalog::cpe_product(&cpe.cpe_name) else {
                continue;
            };
            if !cpe.cpe_name.starts_with("cpe:2.3:a:") || !wanted.contains(&key) {
                continue;
            }
            if let Some(title) = cpe
                .titles
                .iter()
                .find(|title| title.lang.to_ascii_lowercase().starts_with("en"))
                .or(cpe.titles.first())
            {
                titles.entry(key).or_default().push(title.title.clone());
            }
        }
    }
    Ok(wanted
        .iter()
        .map(|key| {
            let titles = titles.remove(key).unwrap_or_default();
            (key.clone(), names_of(key, &titles))
        })
        .collect())
}

/// Refreshes names from the dictionary weekly, or when products appear that
/// the cached names do not cover.
pub async fn update(
    client: &reqwest::Client,
    cache: &Path,
    names: &mut Names,
    wanted: &BTreeSet<String>,
    offline: bool,
) -> Result<()> {
    let stale = names
        .fetched_at
        .is_none_or(|fetched| Utc::now() - fetched > DICTIONARY_REFRESH);
    let missing = wanted.iter().any(|key| !names.products.contains_key(key));
    if !stale && !missing {
        return Ok(());
    }
    let path = cache.join("nvdcpe-2.0.tar.gz");
    if offline && !path.exists() {
        eprintln!("warning: no cached CPE dictionary; inferred names come from CPE names only");
        names.products = wanted
            .iter()
            .map(|key| (key.clone(), names_of(key, &[])))
            .collect();
        return Ok(());
    }
    let archive = if stale || !path.exists() {
        crate::sources::cached(client, DICTIONARY_URL, &path, offline).await?
    } else {
        std::fs::read(&path)?
    };
    names.products = parse_dictionary(&archive, wanted)?;
    if stale && !offline {
        names.fetched_at = Some(Utc::now());
    }
    Ok(())
}

/// Inferred products for CPE "vendor:product" names that no curated product
/// claims, with their overrides applied. A program name an override adds
/// names that product only: other products lose it from their dictionary
/// names, so a "Docker" app (Docker Desktop on macOS) is not also taken for
/// the Docker Engine, whose versions are numbered differently.
pub fn products(catalog: &Catalog, names: &Names, wanted: &BTreeSet<String>) -> Vec<Product> {
    let mut claimed: HashMap<String, Vec<&str>> = HashMap::new();
    for adjustment in catalog
        .overrides
        .iter()
        .filter(|adjustment| !adjustment.disabled)
    {
        for name in &adjustment.names {
            claimed
                .entry(software_key(name))
                .or_default()
                .push(&adjustment.cpe);
        }
    }
    let mut products = Vec::new();
    for vendor_product in wanted {
        if catalog.curated_cpe(vendor_product).is_some() {
            continue;
        }
        let adjustment = catalog.override_for(vendor_product);
        if adjustment.is_some_and(|adjustment| adjustment.disabled) {
            continue;
        }
        let (name, mut aliases) = names
            .products
            .get(vendor_product)
            .cloned()
            .unwrap_or_else(|| names_of(vendor_product, &[]));
        aliases.retain(|alias| {
            claimed.get(alias).map_or(true, |owners| {
                owners
                    .iter()
                    .any(|owner| crate::catalog::same(owner, vendor_product))
            })
        });
        let vendor = vendor_product.split(':').next().unwrap_or("");
        let mut publishers = vec![publisher_key(&unescape(vendor).replace('_', " "))];
        let mut name = name;
        let mut confidence = Confidence::Inferred;
        if let Some(adjustment) = adjustment {
            aliases.extend(adjustment.names.iter().map(|name| software_key(name)));
            publishers.extend(adjustment.publishers.iter().map(|p| publisher_key(p)));
            if let Some(display) = &adjustment.name {
                name = display.clone();
            }
            if adjustment.curated {
                confidence = Confidence::Curated;
            }
        }
        aliases.sort();
        aliases.dedup();
        publishers.retain(|publisher| !publisher.is_empty());
        publishers.sort();
        publishers.dedup();
        if aliases.is_empty() {
            continue;
        }
        products.push(Product {
            key: product_key(vendor_product),
            name,
            matchers: vec![Matcher::Alias {
                platforms: vec![],
                names: aliases,
                publishers,
            }],
            confidence,
        });
    }
    products
}

/// Feed key of an inferred product.
pub fn product_key(vendor_product: &str) -> String {
    format!("cpe:{vendor_product}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn catalog(extra: &str) -> Catalog {
        let text =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml"))
                .unwrap();
        toml::from_str(&format!("{text}\n{extra}")).unwrap()
    }

    fn archive(products: serde_json::Value) -> Vec<u8> {
        let json = serde_json::json!({"products": products}).to_string();
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "nvdcpe-2.0-chunks/nvdcpe-2.0-chunk-00001.json",
                json.as_bytes(),
            )
            .unwrap();
        let tar = builder.into_inner().unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&tar).unwrap();
        gzip.finish().unwrap()
    }

    #[test]
    fn dictionary_titles_become_program_names() {
        let item = |name: &str, title: &str| {
            serde_json::json!({"cpe": {"cpeName": name, "titles": [
                {"title": "タイトル", "lang": "ja"}, {"title": title, "lang": "en"}]}})
        };
        let bytes = archive(serde_json::json!([
            item(
                "cpe:2.3:a:keepass:keepass:2.55:*:*:*:*:*:*:*",
                "KeePass Password Safe 2.55"
            ),
            item(
                "cpe:2.3:a:keepass:keepass:2.56:*:*:*:*:*:*:*",
                "KeePass Password Safe 2.56"
            ),
            item("cpe:2.3:a:keepass:keepass:1.0:*:*:*:*:*:*:*", "KeePass 1.0"),
            item("cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*", "Other Thing 1.0"),
        ]));
        let wanted: BTreeSet<String> = ["keepass:keepass".to_string(), "x:no_titles".to_string()]
            .into_iter()
            .collect();
        let names = parse_dictionary(&bytes, &wanted).unwrap();
        assert_eq!(names.len(), 2);
        let (display, keys) = &names["keepass:keepass"];
        // Titles name it, so no bare "pdf reader"-like alias is added
        // unless it carries the vendor (as "keepass" does).
        assert_eq!(display, "KeePass Password Safe");
        assert_eq!(
            keys,
            &vec![
                "keepass".to_string(),
                "keepass keepass".to_string(),
                "keepass password safe".to_string()
            ]
        );
        assert_eq!(names["x:no_titles"].1, vec!["no titles", "x no titles"]);
    }

    #[test]
    fn platform_notes_and_mobile_titles_are_left_out() {
        let titles = vec![
            "Zoom 0.9.10042.0911 for Windows".to_string(),
            "Zoom 5.0 for Mac OS X".to_string(),
            "ZOOM Cloud Meetings for Android".to_string(),
        ];
        let (name, names) = names_of("zoom:zoom", &titles);
        assert_eq!(name, "Zoom");
        assert_eq!(names, vec!["zoom", "zoom zoom"]);
        let (_, names) = names_of("apple:itunes", &["Apple iTunes 12.0".to_string()]);
        assert_eq!(names, vec!["apple itunes", "itunes"]);
    }

    #[test]
    fn bare_product_names_need_the_vendor_or_missing_titles() {
        let titles = vec!["Foxit PDF Reader 2024.1".to_string()];
        let (_, names) = names_of("foxit:pdf_reader", &titles);
        assert_eq!(names, vec!["foxit pdf reader"]);
        let (_, names) = names_of("foxit:pdf_reader", &[]);
        assert_eq!(names, vec!["foxit pdf reader", "pdf reader"]);
    }

    #[test]
    fn curated_and_disabled_products_are_not_inferred() {
        let catalog = catalog(
            r#"
[[override]]
cpe = "acme:noisy"
disabled = true

[[override]]
cpe = "keepass:keepass"
names = ["KeePass 2"]
publishers = ["Dominik Reichl"]
curated = true
"#,
        );
        let wanted: BTreeSet<String> = [
            "google:chrome",
            "python:python",
            "acme:noisy",
            "keepass:keepass",
            "videolan:vlc_media_player",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let products = products(&catalog, &Names::default(), &wanted);
        // Chrome and VLC are curated catalog products; acme:noisy is disabled.
        assert_eq!(products.len(), 1);
        let keepass = &products[0];
        assert_eq!(keepass.key, "cpe:keepass:keepass");
        assert_eq!(keepass.confidence, Confidence::Curated);
        let Matcher::Alias {
            names, publishers, ..
        } = &keepass.matchers[0]
        else {
            panic!()
        };
        assert!(names.contains(&"keepass 2".to_string()));
        assert_eq!(publishers, &vec!["dominik reichl", "keepass"]);
    }

    #[test]
    fn names_an_override_adds_belong_to_that_product_only() {
        let mut names = Names::default();
        for (cpe, display, keys) in [
            (
                "docker:docker",
                "Docker",
                vec!["docker", "docker community edition"],
            ),
            ("docker:desktop", "Docker Desktop", vec!["docker desktop"]),
            (
                "synology:docker",
                "Synology Docker",
                vec!["docker", "synology docker"],
            ),
        ] {
            names.products.insert(
                cpe.into(),
                (display.into(), keys.into_iter().map(String::from).collect()),
            );
        }
        let wanted: BTreeSet<String> = names.products.keys().cloned().collect();
        let products = products(&catalog(""), &names, &wanted);
        let aliases = |key: &str| {
            let product = products.iter().find(|product| product.key == key).unwrap();
            let Matcher::Alias { names, .. } = &product.matchers[0] else {
                panic!()
            };
            names.clone()
        };
        // catalog.toml gives "Docker" to Docker Desktop.
        assert_eq!(aliases("cpe:docker:desktop"), ["docker", "docker desktop"]);
        assert_eq!(aliases("cpe:docker:docker"), ["docker community edition"]);
        assert_eq!(aliases("cpe:synology:docker"), ["synology docker"]);
    }
}
