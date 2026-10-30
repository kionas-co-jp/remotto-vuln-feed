//! Builds the signed vulnerability feed that Remotto Server imports.
//!
//! Run four times a day by the GitHub Actions workflow in this repository,
//! never on customer servers. Each run gathers CVE records (cvelistV5), KEV,
//! EPSS, NVD, Microsoft and Linux distribution data, matches them to the
//! products of `catalog.toml` and of the CPE dictionary, and publishes every
//! feed channel whose records changed: a delta against its previous version,
//! a fresh snapshot and the signed manifest. Source indexes are kept between
//! runs, so each run downloads only what changed upstream.
#[allow(dead_code)]
mod feed;

mod catalog;
mod cvelist;
mod nvd;
mod office;
mod osv;
mod sources;
mod translate;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use feed::{Affected, DeltaRef, FileRef, Kind, Manifest, Op, Record, RecordKind};
use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const EMBEDDED_PUBLIC_KEY: &str = include_str!("../vuln_feed_public_key.pem");
const KEY_BITS: usize = 3072;

#[derive(Parser)]
#[command(
    name = "remotto-vuln-feed",
    about = "Builds the signed Remotto vulnerability feed"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a feed signing key pair (keep the private key offline)
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Build and publish the next feed version
    Build(BuildArgs),
    /// Verify a feed file or manifest and print its header
    Verify {
        file: PathBuf,
        /// Defaults to the key embedded in Remotto Server
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct BuildArgs {
    /// Checkout of https://github.com/CVEProject/cvelistV5
    #[arg(long)]
    cvelist: PathBuf,
    /// Run `git pull --ff-only` in the checkout first
    #[arg(long)]
    pull: bool,
    /// Product catalog (catalog.toml)
    #[arg(long)]
    catalog: PathBuf,
    /// Private working state (index, previous records, source caches)
    #[arg(long)]
    state: PathBuf,
    /// Published directory served at the manifest URL's location
    #[arg(long)]
    out: PathBuf,
    /// PKCS#8 PEM signing key
    #[arg(long)]
    key: PathBuf,
    /// Add Microsoft fix builds from MSRC CVRF and the Microsoft 365 Apps
    /// security release notes
    #[arg(long)]
    msrc: bool,
    /// Skip NVD data and the CPE dictionary (offline tests)
    #[arg(long)]
    no_nvd: bool,
    /// Skip the Linux channels
    #[arg(long)]
    no_linux: bool,
    /// Monthly MSRC releases read
    #[arg(long, default_value_t = 24)]
    msrc_months: u32,
    /// Use cached downloads only
    #[arg(long)]
    offline: bool,
    /// Deltas listed in the manifest (120 = 30 days at four builds a day)
    #[arg(long, default_value_t = 120)]
    keep_deltas: usize,
    /// Start a new lineage; servers then download the snapshot
    #[arg(long)]
    new_lineage: bool,
    /// Publish as GitHub Releases tagged PREFIX + version (e.g. "feed-"):
    /// files go flat into --out and the manifest points into the releases
    #[arg(long, value_parser = parse_tag_prefix)]
    release_tag_prefix: Option<String>,
}

fn parse_tag_prefix(value: &str) -> Result<String, String> {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        Ok(value.to_string())
    } else {
        Err("use letters, digits, '-', '_' or '.'".into())
    }
}

/// Where one feed lineage stands.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct ChannelState {
    feed_id: Option<String>,
    version: Option<u64>,
    generated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    deltas: Vec<DeltaRef>,
    #[serde(default)]
    snapshots: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<FileRef>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FeedState {
    catalog_sha256: Option<String>,
    /// Channels by name.
    #[serde(default)]
    channels: BTreeMap<String, ChannelState>,
    /// Last release number.
    #[serde(default)]
    release: Option<u64>,
    /// Version of the single feed published before channels; release
    /// numbers continue after it so that tags stay unique.
    #[serde(default, skip_serializing)]
    version: Option<u64>,
}

/// Published file names of a channel.
struct Layout<'a> {
    channel: &'a str,
    release: bool,
}

impl Layout<'_> {
    fn manifest(&self) -> String {
        format!("manifest-v2-{}.rvf", self.channel)
    }

    /// A stable name for packaging the installer's bundled data.
    fn stable_snapshot(&self) -> String {
        format!("snapshot-v2-{}.rvf", self.channel)
    }

    fn snapshot(&self, version: u64) -> String {
        if self.release {
            self.stable_snapshot()
        } else {
            format!("v2/{}/snapshots/snapshot-{version}.rvf", self.channel)
        }
    }

    fn delta(&self, base: u64, version: u64) -> String {
        if self.release {
            format!("delta-v2-{}-{base}-{version}.rvf", self.channel)
        } else {
            format!("v2/{}/deltas/{base}-{version}.rvf", self.channel)
        }
    }

    fn published(&self) -> String {
        format!("published-{}.json.gz", self.channel)
    }
}

fn read_gzip_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(T::default());
    };
    let mut text = Vec::new();
    flate2::read::GzDecoder::new(file)
        .read_to_end(&mut text)
        .with_context(|| format!("Cannot read {}", path.display()))?;
    serde_json::from_slice(&text).with_context(|| format!("Invalid {}", path.display()))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    std::fs::write(&temporary, bytes)
        .with_context(|| format!("Cannot write {}", temporary.display()))?;
    std::fs::rename(&temporary, path).with_context(|| format!("Cannot replace {}", path.display()))
}

fn write_gzip_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    serde_json::to_writer(&mut encoder, value)?;
    write_atomic(path, &encoder.finish()?)
}

fn load_private_key(path: &Path) -> Result<RsaPrivateKey> {
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    RsaPrivateKey::from_pkcs8_pem(&pem).context("The signing key must be a PKCS#8 PEM RSA key")
}

fn record_key(kind: RecordKind, id: &str) -> String {
    let prefix = match kind {
        RecordKind::Product => "product",
        RecordKind::Cve => "cve",
        RecordKind::Affected => "affected",
    };
    format!("{prefix}:{id}")
}

fn parse_record_key(key: &str) -> Option<(RecordKind, &str)> {
    let (prefix, id) = key.split_once(':')?;
    let kind = match prefix {
        "product" => RecordKind::Product,
        "cve" => RecordKind::Cve,
        "affected" => RecordKind::Affected,
        _ => return None,
    };
    Some((kind, id))
}

/// Affected entries of a channel by (CVE, product key).
type Entries = BTreeMap<(String, String), Affected>;

/// Where CVE records come from: cvelist, KEV, EPSS and NVD scores.
struct CveSources<'a> {
    index: &'a cvelist::Index,
    extra: &'a BTreeMap<String, cvelist::Parsed>,
    kev: &'a HashMap<String, feed::Kev>,
    epss: &'a HashMap<String, f32>,
    nvd: &'a nvd::Index,
}

impl CveSources<'_> {
    /// The record of `id`; distributions also track CVEs that cvelist does
    /// not publish yet, which get a `placeholder` record.
    fn record(&self, id: &str, placeholder: bool) -> Option<feed::CveRecord> {
        let mut record = match self.index.records.get(id).or_else(|| self.extra.get(id)) {
            Some(parsed) => parsed.record.clone(),
            None if placeholder => feed::CveRecord {
                id: id.to_string(),
                published: None,
                modified: None,
                title: None,
                description: String::new(),
                scores: vec![],
                epss: None,
                kev: None,
                ssvc: None,
                references: vec![],
            },
            None => return None,
        };
        if let Some(entry) = self.kev.get(id) {
            record.kev = Some(entry.clone());
        }
        record.epss = self.epss.get(id).copied().and_then(feed::quantize_epss);
        for score in self
            .nvd
            .records
            .get(id)
            .into_iter()
            .flat_map(|nvd| &nvd.scores)
        {
            if !record.scores.contains(score) {
                record.scores.push(score.clone());
            }
        }
        Some(record)
    }
}

/// Every record of a channel's next version, keyed by kind and id: the
/// affected entries whose CVE is known, their CVE records, the `listed`
/// products and the `optional` ones that some entry refers to.
fn channel_records(
    sources: &CveSources<'_>,
    affected: Entries,
    listed: Vec<feed::Product>,
    optional: Vec<feed::Product>,
    placeholders: bool,
) -> BTreeMap<String, Record> {
    let mut records = BTreeMap::new();
    for ((cve, product), entry) in affected {
        if let std::collections::btree_map::Entry::Vacant(slot) =
            records.entry(record_key(RecordKind::Cve, &cve))
        {
            let Some(record) = sources.record(&cve, placeholders) else {
                continue;
            };
            slot.insert(Record::Cve(record));
        }
        records.insert(
            record_key(RecordKind::Affected, &feed::affected_id(&cve, &product)),
            Record::Affected(entry),
        );
    }
    let used: std::collections::HashSet<String> = records
        .values()
        .filter_map(|record| match record {
            Record::Affected(entry) => Some(entry.product.clone()),
            _ => None,
        })
        .collect();
    for product in listed.into_iter().chain(
        optional
            .into_iter()
            .filter(|product| used.contains(&product.key)),
    ) {
        records.insert(
            record_key(RecordKind::Product, &product.key),
            Record::Product(product),
        );
    }
    records
}

/// Curated affected entries (cvelist, then MSRC and the Microsoft 365 Apps
/// release notes) and the Windows releases they name.
fn curated_affected(
    index: &cvelist::Index,
    microsoft: &[Affected],
) -> (Entries, Vec<feed::Product>) {
    let mut affected: Entries = BTreeMap::new();
    let mut windows = BTreeMap::new();
    for parsed in index.records.values() {
        for entry in parsed.affected.iter().filter(|entry| !is_inferred(entry)) {
            affected.insert((entry.cve.clone(), entry.product.clone()), entry.clone());
        }
        // Later (higher) CVE IDs carry Microsoft's current release names.
        for product in &parsed.windows {
            windows.insert(product.key.clone(), product.clone());
        }
    }
    // Microsoft's own fix builds are more precise for the products it covers.
    for entry in microsoft {
        affected.insert((entry.cve.clone(), entry.product.clone()), entry.clone());
    }
    (affected, windows.into_values().collect())
}

/// Entries cvelist records under a CPE name the catalog does not curate.
fn is_inferred(entry: &Affected) -> bool {
    entry.product.starts_with("cpe:")
}

/// The CNA's or CISA's versions for inferred products, which come before
/// NVD's: NVD analyses CVEs weeks later, or not at all.
fn add_inferred_cna(
    affected: &mut Entries,
    index: &cvelist::Index,
    inferred: &std::collections::HashSet<String>,
) {
    for entry in index
        .records
        .values()
        .flat_map(|parsed| &parsed.affected)
        .filter(|entry| is_inferred(entry) && inferred.contains(&entry.product))
    {
        affected
            .entry((entry.cve.clone(), entry.product.clone()))
            .or_insert_with(|| entry.clone());
    }
}

/// NVD ranges for CVE and product pairs no CNA or ADP described: on the
/// curated product claiming the CPE name, else on its inferred product.
fn add_nvd(
    affected: &mut Entries,
    catalog: &catalog::Catalog,
    nvd: &nvd::Index,
    inferred: &std::collections::HashSet<String>,
) {
    for (cve, record) in &nvd.records {
        for (vendor_product, spans) in &record.products {
            let product = match catalog.curated_cpe(vendor_product) {
                Some(entry) => entry.key.clone(),
                None => {
                    let key = translate::product_key(vendor_product);
                    if !inferred.contains(&key) {
                        continue;
                    }
                    key
                }
            };
            affected
                .entry((cve.clone(), product.clone()))
                .or_insert_with(|| Affected {
                    cve: cve.clone(),
                    product,
                    fixed: cvelist::fixed_text(spans),
                    spans: spans.clone(),
                    default_affected: false,
                    fix_url: None,
                    scheme: feed::VersionScheme::Generic,
                });
        }
    }
}

/// Linux channel of a Linux product key ("deb:debian:12:openssl").
fn linux_channel(product: &str) -> &'static str {
    let distro = product.split(':').nth(1).unwrap_or("");
    feed::linux_channel(distro).unwrap_or("linux-rhel")
}

fn order(kind: RecordKind) -> u8 {
    match kind {
        RecordKind::Product => 0,
        RecordKind::Cve => 1,
        RecordKind::Affected => 2,
    }
}

fn snapshot_ops(records: &BTreeMap<String, Record>) -> Vec<Op> {
    let mut ops: Vec<Op> = records
        .values()
        .map(|record| Op::Put {
            record: record.clone(),
        })
        .collect();
    ops.sort_by_key(|op| match op {
        Op::Put { record } => order(record.kind()),
        Op::Delete { kind, .. } => 3 + order(*kind),
    });
    ops
}

/// Puts for new or changed records and deletes for vanished ones.
fn delta_ops(
    previous: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
    records: &BTreeMap<String, Record>,
) -> Vec<Op> {
    let mut ops: Vec<Op> = current
        .iter()
        .filter(|(key, json)| previous.get(*key) != Some(*json))
        .map(|(key, _)| Op::Put {
            record: records[key].clone(),
        })
        .collect();
    ops.extend(
        previous
            .keys()
            .filter(|key| !current.contains_key(*key))
            .filter_map(|key| {
                let (kind, id) = parse_record_key(key)?;
                Some(Op::Delete {
                    kind,
                    id: id.to_string(),
                })
            }),
    );
    ops.sort_by_key(|op| match op {
        Op::Put { record } => order(record.kind()),
        Op::Delete { kind, .. } => 3 + order(*kind),
    });
    ops
}

fn file_ref(path: &str, bytes: &[u8]) -> FileRef {
    FileRef {
        path: path.to_string(),
        sha256: feed::sha256_hex(bytes),
        bytes: bytes.len() as u64,
    }
}

/// What every channel of one run shares.
struct Run<'a> {
    key: &'a RsaPrivateKey,
    out: &'a Path,
    state: &'a Path,
    /// The release this run creates when anything changed.
    release_tag: Option<String>,
    generated_at: DateTime<Utc>,
    new_lineage: bool,
    keep_deltas: usize,
}

impl Run<'_> {
    fn published(&self, name: &str) -> String {
        match &self.release_tag {
            Some(tag) => format!("../../download/{tag}/{name}"),
            None => name.to_string(),
        }
    }

    fn saved_manifest(&self, layout: &Layout<'_>) -> PathBuf {
        self.state.join("manifests").join(layout.manifest())
    }

    /// Writes the channel's next version when its records changed (or a
    /// new lineage starts) and reports whether it did.
    fn publish(
        &self,
        layout: &Layout<'_>,
        channel: &mut ChannelState,
        records: &BTreeMap<String, Record>,
    ) -> Result<bool> {
        let current: BTreeMap<String, String> = records
            .iter()
            .map(|(key, record)| Ok((key.clone(), serde_json::to_string(record)?)))
            .collect::<Result<_>>()?;
        let published_path = self.state.join(layout.published());
        let previous: BTreeMap<String, String> = read_gzip_json(&published_path)?;
        let changes = delta_ops(&previous, &current, records);
        // Without the saved manifest an unchanged channel cannot be republished.
        let new_lineage = self.new_lineage
            || channel.feed_id.is_none()
            || (self.release_tag.is_some() && !self.saved_manifest(layout).exists());
        if changes.is_empty() && !new_lineage {
            return Ok(false);
        }
        let version = channel.version.unwrap_or(0) + 1;
        let base = if new_lineage { None } else { channel.version };
        let feed_id = match (&channel.feed_id, new_lineage) {
            (Some(feed_id), false) => feed_id.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        };

        let snapshot = feed::build_data(
            self.key,
            Kind::Snapshot,
            layout.channel,
            &feed_id,
            None,
            version,
            self.generated_at,
            &snapshot_ops(records),
        );
        let snapshot_path = layout.snapshot(version);
        write_atomic(&self.out.join(&snapshot_path), &snapshot)?;
        if !layout.release {
            write_atomic(&self.out.join(layout.stable_snapshot()), &snapshot)?;
        }
        if new_lineage {
            channel.deltas.clear();
        }
        if let Some(base) = base {
            let delta = feed::build_data(
                self.key,
                Kind::Delta,
                layout.channel,
                &feed_id,
                Some(base),
                version,
                self.generated_at,
                &changes,
            );
            let path = layout.delta(base, version);
            write_atomic(&self.out.join(&path), &delta)?;
            channel.deltas.push(DeltaRef {
                base_version: base,
                version,
                file: file_ref(&self.published(&path), &delta),
            });
        }
        let expired = channel.deltas.len().saturating_sub(self.keep_deltas);
        for delta in channel.deltas.drain(..expired) {
            if !layout.release {
                let _ = std::fs::remove_file(self.out.join(&delta.file.path));
            }
        }
        let snapshot_ref = file_ref(&self.published(&snapshot_path), &snapshot);
        let manifest = feed::build_manifest(
            self.key,
            &Manifest {
                format: feed::FORMAT,
                kind: Kind::Manifest,
                channel: layout.channel.into(),
                feed_id: feed_id.clone(),
                version,
                generated_at: self.generated_at,
                snapshot: snapshot_ref.clone(),
                deltas: channel.deltas.clone(),
            },
        );
        write_atomic(&self.out.join(layout.manifest()), &manifest)?;
        write_atomic(&self.saved_manifest(layout), &manifest)?;
        if !layout.release {
            // Keep the previous snapshot for servers still reading the old manifest.
            channel.snapshots.push(snapshot_path);
            let stale = channel.snapshots.len().saturating_sub(2);
            for path in channel.snapshots.drain(..stale) {
                let _ = std::fs::remove_file(self.out.join(path));
            }
        }
        write_gzip_json(&published_path, &current)?;
        println!(
            "Published {} version {version}: {} records, {} changes, snapshot {} bytes",
            layout.channel,
            records.len(),
            changes.len(),
            snapshot.len()
        );
        channel.feed_id = Some(feed_id);
        channel.version = Some(version);
        channel.generated_at = Some(self.generated_at);
        channel.snapshot = Some(snapshot_ref);
        Ok(true)
    }
}

/// The release tag in a published path "../../download/<tag>/<file>".
fn release_of(path: &str) -> Option<&str> {
    path.strip_prefix("../../download/")?.split('/').next()
}

/// Everything the channels are assembled from, with each source's index up
/// to date in the state directory.
struct Gathered {
    kev: HashMap<String, feed::Kev>,
    epss: HashMap<String, f32>,
    /// Fixed builds from MSRC and the Microsoft 365 Apps release notes.
    microsoft: Vec<Affected>,
    nvd: nvd::Index,
    /// Affected versions of Linux packages per (CVE, product).
    linux: BTreeMap<(String, String), Vec<feed::Span>>,
    index: cvelist::Index,
    /// Records of CVEs that only Microsoft's data names.
    extra: BTreeMap<String, cvelist::Parsed>,
    /// CPE "vendor:product" names with affected versions.
    vendor_products: BTreeSet<String>,
    names: translate::Names,
}

fn pull(cvelist: &Path) -> Result<()> {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(cvelist)
        .args(["pull", "--ff-only", "--quiet"])
        .status()
        .context("Cannot run git")?;
    if !status.success() {
        bail!("git pull failed in {}", cvelist.display());
    }
    Ok(())
}

/// Downloads what changed in every source. A catalog change (`full`)
/// reparses CVE records and distribution archives from scratch.
async fn gather(args: &BuildArgs, catalog: &catalog::Catalog, full: bool) -> Result<Gathered> {
    if args.pull {
        pull(&args.cvelist)?;
    }
    let client = sources::client()?;
    let cache = args.state.join("sources");
    std::fs::create_dir_all(&cache)?;
    let kev = sources::kev(&client, &cache, args.offline).await?;
    let epss = sources::epss(&client, &cache, args.offline).await?;
    let mut microsoft = Vec::new();
    if args.msrc {
        microsoft = sources::msrc(&client, &cache, args.msrc_months, catalog, args.offline).await?;
        microsoft.extend(office::update(&client, &cache, catalog, args.offline).await?);
    }

    let nvd_path = args.state.join("nvd-index.json.gz");
    let mut nvd: nvd::Index = read_gzip_json(&nvd_path)?;
    if !args.no_nvd {
        nvd::update(&client, &cache, &mut nvd, args.offline).await?;
        write_gzip_json(&nvd_path, &nvd)?;
    }
    let mut linux = BTreeMap::new();
    if !args.no_linux {
        let mut indexes = Vec::new();
        for source in osv::SOURCES {
            indexes.push(
                osv::update(
                    &client,
                    &cache,
                    &args.state,
                    source,
                    catalog,
                    full,
                    args.offline,
                )
                .await?,
            );
        }
        linux = osv::merge(&indexes.iter().collect::<Vec<_>>());
    }

    // CVE records that NVD or a distribution names, beyond the catalog's.
    let mut wanted: HashSet<String> = nvd
        .records
        .iter()
        .filter(|(_, record)| !record.products.is_empty())
        .map(|(id, _)| id.clone())
        .collect();
    wanted.extend(linux.keys().map(|(cve, _)| cve.clone()));
    let index_path = args.state.join("cvelist-index.json.gz");
    let mut index: cvelist::Index = read_gzip_json(&index_path)?;
    let parsed = cvelist::update(&args.cvelist, catalog, &wanted, &mut index, full)?;
    eprintln!(
        "CVE records reparsed: {parsed}{}; kept: {}",
        if full { " (full scan)" } else { "" },
        index.records.len()
    );
    write_gzip_json(&index_path, &index)?;
    let mut extra = BTreeMap::new();
    for entry in &microsoft {
        if !index.records.contains_key(&entry.cve) && !extra.contains_key(&entry.cve) {
            if let Some(parsed) = cvelist::load_any(&args.cvelist, &entry.cve, catalog)? {
                extra.insert(entry.cve.clone(), parsed);
            }
        }
    }

    let vendor_products: BTreeSet<String> = nvd
        .records
        .values()
        .flat_map(|record| record.products.keys().cloned())
        .chain(
            index
                .records
                .values()
                .flat_map(|parsed| &parsed.affected)
                .filter_map(|entry| entry.product.strip_prefix("cpe:").map(String::from)),
        )
        .collect();
    let names_path = args.state.join("cpe-names.json.gz");
    let mut names: translate::Names = read_gzip_json(&names_path)?;
    if !args.no_nvd {
        translate::update(&client, &cache, &mut names, &vendor_products, args.offline).await?;
        write_gzip_json(&names_path, &names)?;
    }
    Ok(Gathered {
        kev,
        epss,
        microsoft,
        nvd,
        linux,
        index,
        extra,
        vendor_products,
        names,
    })
}

/// Records of every channel's next version: "main" and, unless skipped, the
/// Linux channels, which servers read for the distributions they manage.
fn assemble(
    catalog: &catalog::Catalog,
    gathered: &Gathered,
    with_linux: bool,
) -> BTreeMap<&'static str, BTreeMap<String, Record>> {
    let sources = CveSources {
        index: &gathered.index,
        extra: &gathered.extra,
        kev: &gathered.kev,
        epss: &gathered.epss,
        nvd: &gathered.nvd,
    };
    let inferred = translate::products(catalog, &gathered.names, &gathered.vendor_products);
    let inferred_keys = inferred.iter().map(|product| product.key.clone()).collect();
    let (mut main, windows) = curated_affected(&gathered.index, &gathered.microsoft);
    add_inferred_cna(&mut main, &gathered.index, &inferred_keys);
    add_nvd(&mut main, catalog, &gathered.nvd, &inferred_keys);
    let listed = catalog
        .products
        .iter()
        .map(catalog::Entry::product)
        .collect();
    let mut optional = windows;
    optional.extend(inferred);
    let mut channels = BTreeMap::new();
    channels.insert(
        feed::MAIN_CHANNEL,
        channel_records(&sources, main, listed, optional, false),
    );
    if with_linux {
        let mut linux = linux_affected(catalog, &gathered.linux);
        for channel in feed::CHANNELS
            .iter()
            .filter(|channel| channel.starts_with("linux-"))
        {
            let (affected, products) = linux.remove(channel).unwrap_or_default();
            channels.insert(
                *channel,
                channel_records(&sources, affected, Vec::new(), products, true),
            );
        }
    }
    channels
}

/// Linux entries and the products they refer to, per channel.
fn linux_affected(
    catalog: &catalog::Catalog,
    linux: &BTreeMap<(String, String), Vec<feed::Span>>,
) -> BTreeMap<&'static str, (Entries, Vec<feed::Product>)> {
    let mut channels: BTreeMap<&str, (Entries, Vec<feed::Product>)> = BTreeMap::new();
    for ((cve, product), spans) in linux {
        channels
            .entry(linux_channel(product))
            .or_default()
            .0
            .insert(
                (cve.clone(), product.clone()),
                Affected {
                    cve: cve.clone(),
                    product: product.clone(),
                    fixed: cvelist::fixed_text(spans),
                    scheme: osv::scheme(product),
                    spans: spans.clone(),
                    default_affected: false,
                    fix_url: None,
                },
            );
    }
    for (affected, products) in channels.values_mut() {
        let mut keys: Vec<&String> = affected.keys().map(|(_, product)| product).collect();
        keys.sort();
        keys.dedup();
        *products = keys
            .into_iter()
            .filter_map(|key| osv::feed_product(catalog, key))
            .collect();
    }
    channels
}

/// Releases the workflow must keep: those holding the listed snapshots and
/// deltas, this one, and the previous one for servers reading its manifests.
fn keep_tags(state: &FeedState, tag: &str, prefix: &str, release: u64) -> Vec<String> {
    let mut keep: Vec<String> = state
        .channels
        .values()
        .flat_map(|channel| {
            channel
                .snapshot
                .iter()
                .map(|snapshot| snapshot.path.clone())
                .chain(channel.deltas.iter().map(|delta| delta.file.path.clone()))
                .collect::<Vec<_>>()
        })
        .filter_map(|path| release_of(&path).map(String::from))
        .chain([tag.to_string()])
        .chain((release > 1).then(|| format!("{prefix}{}", release - 1)))
        .collect();
    keep.sort_by_key(|tag| {
        (
            tag.strip_prefix(prefix)
                .and_then(|number| number.parse::<u64>().ok()),
            tag.clone(),
        )
    });
    keep.dedup();
    keep
}

async fn build(args: BuildArgs) -> Result<()> {
    let key = load_private_key(&args.key)?;
    if feed::parse_public_key(EMBEDDED_PUBLIC_KEY).ok() != Some(RsaPublicKey::from(&key)) {
        eprintln!("warning: the signing key does not match the key embedded in Remotto Server");
    }
    let catalog_bytes = std::fs::read(&args.catalog)
        .with_context(|| format!("Cannot read {}", args.catalog.display()))?;
    let catalog = catalog::Catalog::load(&args.catalog)?;
    let catalog_sha256 = feed::sha256_hex(&catalog_bytes);
    std::fs::create_dir_all(&args.state)?;
    // The workflow publishes a release only when this run writes release.env.
    for marker in ["release.env", "keep-tags.txt"] {
        let _ = std::fs::remove_file(args.out.join(marker));
    }
    let state_path = args.state.join("feed.json");
    let mut state: FeedState = match std::fs::read(&state_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("Invalid feed state")?,
        Err(_) => FeedState::default(),
    };
    let full = state.catalog_sha256.as_deref() != Some(catalog_sha256.as_str());

    let gathered = gather(&args, &catalog, full).await?;
    let channels = assemble(&catalog, &gathered, !args.no_linux);

    let release = state.release.or(state.version).unwrap_or(0) + 1;
    let run = Run {
        key: &key,
        out: &args.out,
        state: &args.state,
        release_tag: args
            .release_tag_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}{release}")),
        generated_at: Utc::now(),
        new_lineage: args.new_lineage,
        keep_deltas: args.keep_deltas,
    };
    let mut changed = false;
    let mut unchanged = Vec::new();
    for (name, records) in &channels {
        let layout = Layout {
            channel: name,
            release: run.release_tag.is_some(),
        };
        let channel = state.channels.entry(name.to_string()).or_default();
        if run.publish(&layout, channel, records)? {
            changed = true;
        } else {
            unchanged.push(layout);
        }
    }
    state.catalog_sha256 = Some(catalog_sha256);
    if !changed {
        write_atomic(&state_path, &serde_json::to_vec_pretty(&state)?)?;
        println!("No changes since release {}", release - 1);
        return Ok(());
    }
    if let (Some(tag), Some(prefix)) = (&run.release_tag, &args.release_tag_prefix) {
        // Every release carries every manifest, since servers read them from
        // the latest release; unchanged ones are copied as published.
        for layout in &unchanged {
            let saved = run.saved_manifest(layout);
            std::fs::copy(&saved, run.out.join(layout.manifest()))
                .with_context(|| format!("Cannot copy {}", saved.display()))?;
        }
        let keep = keep_tags(&state, tag, prefix, release);
        write_atomic(
            &args.out.join("keep-tags.txt"),
            format!("{}\n", keep.join("\n")).as_bytes(),
        )?;
        write_atomic(
            &args.out.join("release.env"),
            format!("TAG={tag}\nVERSION={release}\n").as_bytes(),
        )?;
    }
    state.release = Some(release);
    write_atomic(&state_path, &serde_json::to_vec_pretty(&state)?)?;
    Ok(())
}

fn keygen(private_path: &Path, public_path: &Path) -> Result<()> {
    if private_path.exists() {
        bail!("{} already exists", private_path.display());
    }
    let key = RsaPrivateKey::new(&mut rand::thread_rng(), KEY_BITS)?;
    let private = key.to_pkcs8_pem(LineEnding::LF)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(private_path)
        .with_context(|| format!("Cannot create {}", private_path.display()))?
        .write_all(private.as_bytes())?;
    std::fs::write(
        public_path,
        RsaPublicKey::from(&key).to_public_key_pem(LineEnding::LF)?,
    )?;
    println!(
        "Wrote {} and {}. Replace crates/server/vuln_feed_public_key.pem with the public key.",
        private_path.display(),
        public_path.display()
    );
    Ok(())
}

fn verify(path: &Path, public_key: Option<&Path>) -> Result<()> {
    let pem = match public_key {
        Some(path) => std::fs::read_to_string(path)?,
        None => EMBEDDED_PUBLIC_KEY.to_string(),
    };
    let key = feed::parse_public_key(&pem).map_err(|error| anyhow::anyhow!(error.0))?;
    let bytes = std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    if let Ok(manifest) = feed::open_manifest(&key, &bytes) {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
        return Ok(());
    }
    let (header, body) = feed::open_data(&key, &bytes).map_err(|error| anyhow::anyhow!(error.0))?;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for op in feed::decode_ops(body) {
        let label = match op.map_err(|error| anyhow::anyhow!(error.0))? {
            Op::Put { record } => format!("put {:?}", record.kind()),
            Op::Delete { kind, .. } => format!("delete {kind:?}"),
        };
        *counts.entry(label).or_default() += 1;
    }
    println!("{}", serde_json::to_string_pretty(&header)?);
    for (label, count) in counts {
        println!("{label}: {count}");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            private_key,
            public_key,
        } => keygen(&private_key, &public_key),
        Command::Build(args) => build(args).await,
        Command::Verify { file, public_key } => verify(&file, public_key.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use feed::{CveRecord, Product};

    fn cve(id: &str) -> Record {
        Record::Cve(CveRecord {
            id: id.into(),
            published: None,
            modified: None,
            title: None,
            description: String::new(),
            scores: vec![],
            epss: None,
            kev: None,
            ssvc: None,
            references: vec![],
        })
    }

    #[test]
    fn deltas_put_changes_and_delete_vanished_records() {
        let mut records = BTreeMap::new();
        records.insert("cve:CVE-1".to_string(), cve("CVE-1"));
        records.insert("cve:CVE-2".to_string(), cve("CVE-2"));
        records.insert(
            "product:p".to_string(),
            Record::Product(Product {
                key: "p".into(),
                name: "P".into(),
                matchers: vec![feed::Matcher::Macos],
                confidence: feed::Confidence::Curated,
            }),
        );
        let current: BTreeMap<String, String> = records
            .iter()
            .map(|(k, r)| (k.clone(), serde_json::to_string(r).unwrap()))
            .collect();
        let mut previous = current.clone();
        previous.insert("cve:CVE-2".into(), "{}".into());
        previous.insert("affected:CVE-0|p".into(), "{}".into());
        let ops = delta_ops(&previous, &current, &records);
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], Op::Put { record: Record::Cve(c) } if c.id == "CVE-2"));
        assert!(
            matches!(&ops[1], Op::Delete { kind: RecordKind::Affected, id } if id == "CVE-0|p")
        );
        assert!(delta_ops(&current, &current, &records).is_empty());

        // Snapshots list products before the records that refer to them.
        let snapshot = snapshot_ops(&records);
        assert!(matches!(
            &snapshot[0],
            Op::Put {
                record: Record::Product(_)
            }
        ));
    }

    fn chrome_record(fixed: &str) -> String {
        serde_json::json!({
            "dataVersion": "5.1",
            "cveMetadata": {"cveId": "CVE-2025-0001", "state": "PUBLISHED"},
            "containers": {"cna": {
                "providerMetadata": {"shortName": "Chrome"},
                "descriptions": [{"lang": "en", "value": "Bug."}],
                "affected": [{"vendor": "Google", "product": "Chrome", "versions": [
                    {"version": fixed, "status": "affected", "lessThan": fixed, "versionType": "custom"}]}]
            }}
        })
        .to_string()
    }

    #[tokio::test]
    async fn release_layout_points_manifests_into_tagged_releases() {
        let root = std::env::temp_dir().join(format!("vuln-feed-test-{}", uuid::Uuid::new_v4()));
        let record = root.join("cvelist/cves/2025/0xxx/CVE-2025-0001.json");
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        std::fs::create_dir_all(root.join("state/sources")).unwrap();
        std::fs::write(&record, chrome_record("140.0.1")).unwrap();
        std::fs::write(
            root.join("state/sources/kev.json"),
            br#"{"vulnerabilities":[{"cveID":"CVE-2025-0001","dateAdded":"2025-01-02"}]}"#,
        )
        .unwrap();
        let mut epss = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        epss.write_all(b"cve,epss,percentile\nCVE-2025-0001,0.5,0.9\n")
            .unwrap();
        std::fs::write(
            root.join("state/sources/epss.csv.gz"),
            epss.finish().unwrap(),
        )
        .unwrap();
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        std::fs::write(
            root.join("key.pem"),
            key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        // State of the single feed published before channels: release
        // numbers continue after its version, so tags stay unique.
        std::fs::write(
            root.join("state/feed.json"),
            br#"{"feed_id": "old", "version": 7, "catalog_sha256": null}"#,
        )
        .unwrap();
        let args = || BuildArgs {
            cvelist: root.join("cvelist"),
            pull: false,
            catalog: Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml"),
            state: root.join("state"),
            out: root.join("out"),
            key: root.join("key.pem"),
            msrc: false,
            no_nvd: true,
            no_linux: true,
            msrc_months: 24,
            offline: true,
            keep_deltas: 240,
            new_lineage: false,
            release_tag_prefix: Some("feed-".into()),
        };

        build(args()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("out/release.env")).unwrap(),
            "TAG=feed-8\nVERSION=8\n"
        );
        // Only channel files are published.
        assert!(!root.join("out/manifest.rvf").exists());
        // Nothing changed: no release.
        build(args()).await.unwrap();
        assert!(!root.join("out/release.env").exists());

        std::fs::write(&record, chrome_record("141.0.1")).unwrap();
        build(args()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("out/release.env")).unwrap(),
            "TAG=feed-9\nVERSION=9\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("out/keep-tags.txt")).unwrap(),
            "feed-8\nfeed-9\n"
        );
        let public = RsaPublicKey::from(&key);
        let manifest = feed::open_manifest(
            &public,
            &std::fs::read(root.join("out/manifest-v2-main.rvf")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.version, 2);
        assert_eq!(
            manifest.snapshot.path,
            "../../download/feed-9/snapshot-v2-main.rvf"
        );
        assert_eq!(manifest.deltas.len(), 1);
        assert_eq!(
            manifest.deltas[0].file.path,
            "../../download/feed-9/delta-v2-main-1-2.rvf"
        );
        let delta = std::fs::read(root.join("out/delta-v2-main-1-2.rvf")).unwrap();
        assert_eq!(feed::sha256_hex(&delta), manifest.deltas[0].file.sha256);
        let (header, body) = feed::open_data(&public, &delta).unwrap();
        assert_eq!((header.base_version, header.version), (Some(1), 2));
        assert_eq!(header.channel, "main");
        assert_eq!(feed::decode_ops(body).count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn nvd_feed(modified: &str, keepass_fixed: &str) -> Vec<u8> {
        let feed = serde_json::json!({"vulnerabilities": [{"cve": {
            "id": "CVE-2025-0002", "lastModified": modified, "vulnStatus": "Analyzed",
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
                {"vulnerable": true, "criteria": "cpe:2.3:a:keepass:keepass:*:*:*:*:*:*:*:*",
                 "versionEndExcluding": keepass_fixed}]}]}]
        }}]});
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(feed.to_string().as_bytes()).unwrap();
        gzip.finish().unwrap()
    }

    fn records_of(public: &RsaPublicKey, file: &[u8]) -> Vec<Record> {
        let (_, body) = feed::open_data(public, file).unwrap();
        feed::decode_ops(body)
            .filter_map(|op| match op.unwrap() {
                Op::Put { record } => Some(record),
                Op::Delete { .. } => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn unchanged_channels_are_republished_as_they_were() {
        let root = std::env::temp_dir().join(format!("vuln-feed-test-{}", uuid::Uuid::new_v4()));
        let cves = root.join("cvelist/cves/2025/0xxx");
        std::fs::create_dir_all(&cves).unwrap();
        std::fs::create_dir_all(root.join("state/sources/nvd")).unwrap();
        std::fs::write(cves.join("CVE-2025-0001.json"), chrome_record("140.0.1")).unwrap();
        // The CNA names KeePass without comparable versions; NVD has a range.
        std::fs::write(
            cves.join("CVE-2025-0002.json"),
            serde_json::json!({
                "cveMetadata": {"cveId": "CVE-2025-0002", "state": "PUBLISHED"},
                "containers": {"cna": {
                    "descriptions": [{"lang": "en", "value": "KeePass bug."}],
                    "affected": [{"vendor": "n/a", "product": "n/a", "versions": [{"version": "n/a", "status": "affected"}]}]
                }}
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            root.join("state/sources/kev.json"),
            br#"{"vulnerabilities":[{"cveID":"CVE-2025-0001","dateAdded":"2025-01-02"}]}"#,
        )
        .unwrap();
        let mut epss = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        epss.write_all(b"cve,epss\nCVE-2025-0001,0.5\n").unwrap();
        std::fs::write(
            root.join("state/sources/epss.csv.gz"),
            epss.finish().unwrap(),
        )
        .unwrap();
        // A recent update: only the modified feed is read.
        write_gzip_json(
            &root.join("state/nvd-index.json.gz"),
            &nvd::Index {
                updated_at: Some(Utc::now()),
                records: BTreeMap::new(),
            },
        )
        .unwrap();
        let modified = root.join("state/sources/nvd/modified.json.gz");
        std::fs::write(&modified, nvd_feed("2025-01-01T00:00:00.000", "2.57")).unwrap();
        // Distribution data: one Debian advisory, other archives empty.
        let osv = root.join("state/sources/osv");
        std::fs::create_dir_all(&osv).unwrap();
        for source in osv::SOURCES {
            let slug = source.directory.to_ascii_lowercase().replace(' ', "-");
            let mut zip = zip::ZipWriter::new(
                std::fs::File::create(osv.join(format!("{slug}.zip"))).unwrap(),
            );
            if source.directory == "Debian" {
                zip.start_file(
                    "DEBIAN-CVE-2025-0003.json",
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
                zip.write_all(
                    serde_json::json!({
                        "id": "DEBIAN-CVE-2025-0003", "modified": "2025-01-01T00:00:00Z",
                        "upstream": ["CVE-2025-0003"],
                        "affected": [{"package": {"name": "openssh", "ecosystem": "Debian:12"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u3"}]}]}]
                    })
                    .to_string()
                    .as_bytes(),
                )
                .unwrap();
            }
            zip.finish().unwrap();
        }
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        std::fs::write(
            root.join("key.pem"),
            key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes(),
        )
        .unwrap();
        let args = || BuildArgs {
            cvelist: root.join("cvelist"),
            pull: false,
            catalog: Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog.toml"),
            state: root.join("state"),
            out: root.join("out"),
            key: root.join("key.pem"),
            msrc: false,
            no_nvd: false,
            no_linux: false,
            msrc_months: 24,
            offline: true,
            keep_deltas: 240,
            new_lineage: false,
            release_tag_prefix: Some("feed-".into()),
        };
        let public = RsaPublicKey::from(&key);

        build(args()).await.unwrap();
        let debian_manifest = std::fs::read(root.join("out/manifest-v2-linux-debian.rvf")).unwrap();
        let debian = records_of(
            &public,
            &std::fs::read(root.join("out/snapshot-v2-linux-debian.rvf")).unwrap(),
        );
        assert!(debian.iter().any(|record| matches!(record,
            Record::Affected(entry) if entry.product == "deb:debian:12:openssh"
                && entry.affects("1:9.2p1-2+deb12u2") == Some(true))));
        let main = records_of(
            &public,
            &std::fs::read(root.join("out/snapshot-v2-main.rvf")).unwrap(),
        );
        let keepass = main
            .iter()
            .find_map(|record| match record {
                Record::Product(product) if product.key == "cpe:keepass:keepass" => {
                    Some(product.clone())
                }
                _ => None,
            })
            .expect("inferred KeePass product");
        assert_eq!(keepass.confidence, feed::Confidence::Inferred);
        assert!(main.iter().any(|record| matches!(record,
            Record::Affected(entry) if entry.product == "cpe:keepass:keepass"
                && entry.affects("2.56") == Some(true))));

        // Each run starts from an empty output directory, as in the workflow.
        std::fs::remove_dir_all(root.join("out")).unwrap();
        std::fs::write(&modified, nvd_feed("2025-02-01T00:00:00.000", "2.58")).unwrap();
        build(args()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("out/release.env")).unwrap(),
            "TAG=feed-2\nVERSION=2\n"
        );
        // Debian did not change: its manifest is republished as is and its
        // snapshot stays in release 1.
        assert_eq!(
            std::fs::read(root.join("out/manifest-v2-linux-debian.rvf")).unwrap(),
            debian_manifest
        );
        assert!(!root.join("out/snapshot-v2-linux-debian.rvf").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("out/keep-tags.txt")).unwrap(),
            "feed-1\nfeed-2\n"
        );
        let manifest = feed::open_manifest(
            &public,
            &std::fs::read(root.join("out/manifest-v2-main.rvf")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest.version, 2);
        assert_eq!(
            manifest.deltas[0].file.path,
            "../../download/feed-2/delta-v2-main-1-2.rvf"
        );
        let delta = records_of(
            &public,
            &std::fs::read(root.join("out/delta-v2-main-1-2.rvf")).unwrap(),
        );
        assert_eq!(delta.len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn record_keys_round_trip() {
        let key = record_key(RecordKind::Affected, "CVE-1|windows-client-26100");
        assert_eq!(
            parse_record_key(&key),
            Some((RecordKind::Affected, "CVE-1|windows-client-26100"))
        );
        assert_eq!(parse_record_key("bogus"), None);
    }
}
