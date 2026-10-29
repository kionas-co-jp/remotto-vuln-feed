//! Downloads shared by all sources, and CISA KEV, FIRST EPSS and MSRC CVRF.
//! Each download is cached so a failed fetch falls back to the previous copy.
use crate::catalog::Catalog;
use crate::feed::{Affected, Kev, Span, VersionScheme};
use anyhow::{bail, Context, Result};
use chrono::{Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    io::Read,
    path::{Path, PathBuf},
};

pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const EPSS_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
pub const MSRC_UPDATES_URL: &str = "https://api.msrc.microsoft.com/cvrf/v3.0/updates";

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(600))
        // Lets data providers see who is downloading and how to reach us.
        .user_agent(concat!(
            "remotto-vuln-feed/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/kionas-co-jp/remotto-vuln-feed)"
        ))
        .build()?)
}

/// HTTP validators of a cached download, so that an unchanged file is not
/// sent again: the server answers a conditional request with 304.
#[derive(Default, Serialize, Deserialize)]
struct Validators {
    etag: Option<String>,
    last_modified: Option<String>,
}

fn validators_path(cache: &Path) -> PathBuf {
    let mut name = cache.as_os_str().to_owned();
    name.push(".http");
    PathBuf::from(name)
}

/// A conditional GET against the cached copy; None when it is current.
async fn fetch(
    client: &reqwest::Client,
    url: &str,
    cache: &Path,
) -> Result<Option<reqwest::Response>> {
    use reqwest::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
    let mut request = client.get(url);
    let known: Validators = std::fs::read(validators_path(cache))
        .ok()
        .filter(|_| cache.exists())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    if let Some(etag) = &known.etag {
        request = request.header(IF_NONE_MATCH, etag);
    }
    if let Some(modified) = &known.last_modified {
        request = request.header(IF_MODIFIED_SINCE, modified);
    }
    let response = request.send().await?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    Ok(Some(response.error_for_status()?))
}

/// Remembers the validators of a response once its body is in `cache`.
fn save_validators(headers: &reqwest::header::HeaderMap, cache: &Path) -> Result<()> {
    use reqwest::header::{ETAG, LAST_MODIFIED};
    let value = |name| {
        headers
            .get(name)
            .and_then(|value: &reqwest::header::HeaderValue| value.to_str().ok())
            .map(String::from)
    };
    let validators = Validators {
        etag: value(ETAG),
        last_modified: value(LAST_MODIFIED),
    };
    std::fs::write(validators_path(cache), serde_json::to_vec(&validators)?)?;
    Ok(())
}

pub async fn get(client: &reqwest::Client, url: &str, accept_json: bool) -> Result<Vec<u8>> {
    let mut request = client.get(url);
    if accept_json {
        request = request.header(reqwest::header::ACCEPT, "application/json");
    }
    let response = request.send().await?.error_for_status()?;
    Ok(response.bytes().await?.to_vec())
}

/// Downloads `url` into `cache` when it changed, or reuses the cached copy
/// when it did not, when offline or when the download fails.
pub async fn cached(
    client: &reqwest::Client,
    url: &str,
    cache: &Path,
    offline: bool,
) -> Result<Vec<u8>> {
    if !offline {
        let result: Result<Option<Vec<u8>>> = async {
            let Some(response) = fetch(client, url, cache).await? else {
                return Ok(None);
            };
            let headers = response.headers().clone();
            let bytes = response.bytes().await?.to_vec();
            std::fs::write(cache, &bytes)
                .with_context(|| format!("Cannot write {}", cache.display()))?;
            save_validators(&headers, cache)?;
            Ok(Some(bytes))
        }
        .await;
        match result {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => {}
            Err(error) => eprintln!("warning: {url}: {error}; using the cached copy"),
        }
    }
    std::fs::read(cache).with_context(|| format!("No cached copy of {url} at {}", cache.display()))
}

/// Streams a large download into `path` (replaced only when complete) when
/// it changed, or keeps the existing copy when it did not, when offline or
/// when the download fails.
pub async fn download(
    client: &reqwest::Client,
    url: &str,
    path: &Path,
    offline: bool,
) -> Result<()> {
    if !offline {
        let partial = path.with_extension("partial");
        let result: Result<()> = async {
            let Some(mut response) = fetch(client, url, path).await? else {
                return Ok(());
            };
            let headers = response.headers().clone();
            let mut file = std::fs::File::create(&partial)?;
            while let Some(chunk) = response.chunk().await? {
                std::io::Write::write_all(&mut file, &chunk)?;
            }
            file.sync_all()?;
            std::fs::rename(&partial, path)?;
            save_validators(&headers, path)?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) => eprintln!("warning: {url}: {error}; using the cached copy"),
        }
    }
    if path.exists() {
        Ok(())
    } else {
        bail!("No cached copy of {url} at {}", path.display())
    }
}

pub fn parse_kev(bytes: &[u8]) -> Result<HashMap<String, Kev>> {
    let document: Value = serde_json::from_slice(bytes).context("Invalid KEV catalog")?;
    let mut kev = HashMap::new();
    for entry in document
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .context("Invalid KEV catalog")?
    {
        let date = |key: &str| {
            entry
                .get(key)
                .and_then(Value::as_str)
                .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
        };
        let (Some(id), Some(added)) = (
            entry.get("cveID").and_then(Value::as_str),
            date("dateAdded"),
        ) else {
            continue;
        };
        kev.insert(
            id.to_string(),
            Kev {
                added,
                due: date("dueDate"),
                ransomware: entry
                    .get("knownRansomwareCampaignUse")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case("known")),
            },
        );
    }
    if kev.is_empty() {
        bail!("The KEV catalog is empty");
    }
    Ok(kev)
}

pub async fn kev(
    client: &reqwest::Client,
    cache: &Path,
    offline: bool,
) -> Result<HashMap<String, Kev>> {
    parse_kev(&cached(client, KEV_URL, &cache.join("kev.json"), offline).await?)
}

pub fn parse_epss(gzip: &[u8]) -> Result<HashMap<String, f32>> {
    let mut text = String::new();
    flate2::read::GzDecoder::new(gzip)
        .read_to_string(&mut text)
        .context("Invalid EPSS file")?;
    let mut reader = csv::ReaderBuilder::new()
        .comment(Some(b'#'))
        .from_reader(text.as_bytes());
    let mut scores = HashMap::new();
    for row in reader.records() {
        let row = row.context("Invalid EPSS file")?;
        if let (Some(id), Some(score)) =
            (row.get(0), row.get(1).and_then(|score| score.parse().ok()))
        {
            scores.insert(id.to_string(), score);
        }
    }
    if scores.is_empty() {
        bail!("The EPSS file is empty");
    }
    Ok(scores)
}

pub async fn epss(
    client: &reqwest::Client,
    cache: &Path,
    offline: bool,
) -> Result<HashMap<String, f32>> {
    parse_epss(&cached(client, EPSS_URL, &cache.join("epss.csv.gz"), offline).await?)
}

/// MSRC monthly release IDs such as "2025-Oct" within the last `months`.
fn recent(id: &str, months: u32) -> bool {
    let Ok(date) = NaiveDate::parse_from_str(&format!("{id}-01"), "%Y-%b-%d") else {
        return false;
    };
    let today = Utc::now().date_naive();
    let age = (today.year() - date.year()) * 12 + today.month() as i32 - date.month() as i32;
    (0..months as i32).contains(&age)
}

/// Fixed builds MSRC publishes for catalog products with `msrc` names; Edge,
/// for one, ships Chromium fixes under its own build numbers.
pub fn parse_msrc(document: &Value, catalog: &Catalog) -> Vec<Affected> {
    let names: HashMap<&str, &str> = document
        .pointer("/ProductTree/FullProductName")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|product| {
            Some((
                product.get("ProductID")?.as_str()?,
                product.get("Value")?.as_str()?,
            ))
        })
        .collect();
    let product_key = |id: &str| {
        let name = names.get(id)?;
        catalog
            .products
            .iter()
            .find(|entry| {
                entry
                    .msrc
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(name.trim()))
            })
            .map(|entry| entry.key.clone())
    };
    let mut affected: Vec<Affected> = Vec::new();
    for vulnerability in document
        .get("Vulnerability")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(cve) = vulnerability
            .get("CVE")
            .and_then(Value::as_str)
            .filter(|cve| cve.starts_with("CVE-"))
        else {
            continue;
        };
        for remediation in vulnerability
            .get("Remediations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(fixed) = remediation
                .get("FixedBuild")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|fixed| fixed.chars().next().is_some_and(|c| c.is_ascii_digit()))
            else {
                continue;
            };
            for id in remediation
                .get("ProductID")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let Some(product) = product_key(id) else {
                    continue;
                };
                if affected
                    .iter()
                    .any(|entry| entry.cve == cve && entry.product == product)
                {
                    continue;
                }
                affected.push(Affected {
                    cve: cve.to_string(),
                    product,
                    spans: vec![Span {
                        affected: true,
                        start: None,
                        start_inclusive: true,
                        end: Some(fixed.to_string()),
                        end_inclusive: false,
                    }],
                    default_affected: false,
                    fixed: Some(fixed.to_string()),
                    fix_url: None,
                    scheme: VersionScheme::Generic,
                });
            }
        }
    }
    affected
}

/// Downloads changed monthly CVRF documents only; unchanged months are read
/// from the cache keyed by MSRC's CurrentReleaseDate.
pub async fn msrc(
    client: &reqwest::Client,
    cache: &Path,
    months: u32,
    catalog: &Catalog,
    offline: bool,
) -> Result<Vec<Affected>> {
    let directory = cache.join("msrc");
    std::fs::create_dir_all(&directory)?;
    let updates: Value = serde_json::from_slice(
        &cached(
            client,
            MSRC_UPDATES_URL,
            &directory.join("updates.json"),
            offline,
        )
        .await?,
    )
    .context("Invalid MSRC update list")?;
    let index_path = directory.join("index.json");
    let mut index: BTreeMap<String, String> = std::fs::read(&index_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    let mut affected = Vec::new();
    for update in updates
        .get("value")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = update.get("ID").and_then(Value::as_str).unwrap_or("");
        let (Some(url), Some(revision)) = (
            update.get("CvrfUrl").and_then(Value::as_str),
            update.get("CurrentReleaseDate").and_then(Value::as_str),
        ) else {
            continue;
        };
        if !recent(id, months) || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            continue;
        }
        let path = directory.join(format!("{id}.json"));
        let fresh = index.get(id).is_some_and(|known| known == revision) && path.exists();
        if !fresh && !offline {
            match get(client, url, true).await {
                Ok(bytes) => {
                    std::fs::write(&path, bytes)?;
                    index.insert(id.to_string(), revision.to_string());
                }
                Err(error) => eprintln!("warning: MSRC {id}: {error}; using the cached copy"),
            }
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let document: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("Invalid MSRC document {id}"))?;
        for entry in parse_msrc(&document, catalog) {
            // A later revision of the same CVE in another month replaces it.
            affected.retain(|known: &Affected| {
                !(known.cve == entry.cve && known.product == entry.product)
            });
            affected.push(entry);
        }
    }
    std::fs::write(&index_path, serde_json::to_vec_pretty(&index)?)?;
    Ok(affected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn kev_and_epss_files_are_parsed() {
        let kev = parse_kev(br#"{"vulnerabilities":[{"cveID":"CVE-2025-1","dateAdded":"2025-01-02","dueDate":"2025-01-23","knownRansomwareCampaignUse":"Known"},{"cveID":"CVE-2025-2","dateAdded":"bad"}]}"#).unwrap();
        assert_eq!(kev.len(), 1);
        assert!(kev["CVE-2025-1"].ransomware);
        assert!(kev["CVE-2025-1"].due.is_some());

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"#model_version:v2026.06.15,score_date:2026-10-27\ncve,epss,percentile\nCVE-2025-1,0.04753,0.91\nCVE-2025-2,0.9,0.99\n").unwrap();
        let epss = parse_epss(&gzip.finish().unwrap()).unwrap();
        assert_eq!(epss.len(), 2);
        assert!((epss["CVE-2025-1"] - 0.04753).abs() < 1e-6);
    }

    #[test]
    fn msrc_fixed_builds_map_to_catalog_products() {
        let catalog =
            Catalog::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml")).unwrap();
        let document = serde_json::json!({
            "ProductTree": {"FullProductName": [
                {"ProductID": "11655", "Value": "Microsoft Edge (Chromium-based)"},
                {"ProductID": "12390", "Value": "Windows 11 Version 24H2 for x64-based Systems"}]},
            "Vulnerability": [{"CVE": "CVE-2025-11756", "Remediations": [
                {"Type": 2, "ProductID": ["11655"], "FixedBuild": "141.0.3537.71"},
                {"Type": 2, "ProductID": ["12390"], "FixedBuild": "10.0.26100.6899"},
                {"Type": 3, "ProductID": ["11655"], "URL": "https://example.com"}]}]
        });
        let affected = parse_msrc(&document, &catalog);
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0].product, "microsoft-edge");
        assert_eq!(affected[0].affects("141.0.3537.57"), Some(true));
        assert_eq!(affected[0].affects("141.0.3537.71"), Some(false));
    }

    #[test]
    fn only_recent_msrc_months_are_fetched() {
        let now = Utc::now().date_naive();
        let current = now.format("%Y-%b").to_string();
        assert!(recent(&current, 1));
        assert!(!recent("1999-Sep", 24));
        assert!(!recent("Mariner", 24));
    }

    /// Serves `responses` in order on a local port, recording the requests.
    fn serve(responses: Vec<&'static str>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/feed", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0u8; 4096];
                let read = std::io::Read::read(&mut stream, &mut buffer).unwrap();
                requests.push(String::from_utf8_lossy(&buffer[..read]).to_lowercase());
                std::io::Write::write_all(&mut stream, response.as_bytes()).unwrap();
            }
            requests
        });
        (url, handle)
    }

    #[tokio::test]
    async fn unchanged_downloads_are_not_sent_again() {
        let (url, server) = serve(vec![
            "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Length: 3\r\nConnection: close\r\n\r\none",
            "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n",
        ]);
        let directory =
            std::env::temp_dir().join(format!("vuln-feed-http-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let cache = directory.join("feed.json");
        let client = client().unwrap();
        assert_eq!(cached(&client, &url, &cache, false).await.unwrap(), b"one");
        // The second request is conditional; the 304 keeps the cached copy.
        assert_eq!(cached(&client, &url, &cache, false).await.unwrap(), b"one");
        let requests = server.join().unwrap();
        assert!(!requests[0].contains("if-none-match"));
        assert!(requests[1].contains("if-none-match: \"v1\""));
        assert!(requests[0].contains("user-agent: remotto-vuln-feed/"));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
