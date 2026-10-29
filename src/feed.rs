//! Signed vulnerability feed shared by the server and the Remotto feed builder.
//!
//! Every file is `MAGIC`, a base64 RSA-PSS signature line, the signed JSON
//! header line and an optional gzip NDJSON body. A snapshot holds every record;
//! a delta holds the puts and deletes that turn `base_version` into `version`
//! of the same feed lineage (`feed_id`), so servers fetch only the changes.
//!
//! Keep identical in Remotto (crates/shared/vuln_feed.rs) and in the public
//! remotto-vuln-feed builder (src/feed.rs); bump FORMAT for breaking changes.
use chrono::{DateTime, NaiveDate, Utc};
use rsa::{
    pss::{Signature, SigningKey, VerifyingKey},
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    cmp::Ordering,
    io::{BufRead, BufReader, Read, Write},
};

pub const MAGIC: &[u8] = b"REMOTTO-VULN-FEED 1\n";
pub const FORMAT: u32 = 2;
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 1024 * 1024;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Snapshot,
    Delta,
    Manifest,
}

/// The channel of Windows, macOS and application data; Linux distributions
/// have their own (`linux_channel`).
pub const MAIN_CHANNEL: &str = "main";

/// Every channel.
pub const CHANNELS: &[&str] = &[MAIN_CHANNEL, "linux-debian", "linux-ubuntu", "linux-rhel"];

fn main_channel() -> String {
    MAIN_CHANNEL.into()
}

fn is_main_channel(channel: &str) -> bool {
    channel == MAIN_CHANNEL
}

/// Signed header of a snapshot or delta file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    pub kind: Kind,
    /// Each channel is a lineage of its own.
    #[serde(default = "main_channel", skip_serializing_if = "is_main_channel")]
    pub channel: String,
    pub feed_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_version: Option<u64>,
    pub version: u64,
    pub generated_at: DateTime<Utc>,
    pub records: u64,
    pub body_sha256: String,
    pub body_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRef {
    /// Relative to the manifest URL.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaRef {
    pub base_version: u64,
    pub version: u64,
    pub file: FileRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub kind: Kind,
    #[serde(default = "main_channel", skip_serializing_if = "is_main_channel")]
    pub channel: String,
    pub feed_id: String,
    pub version: u64,
    pub generated_at: DateTime<Utc>,
    pub snapshot: FileRef,
    #[serde(default)]
    pub deltas: Vec<DeltaRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Put { record: Record },
    Delete { kind: RecordKind, id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Cve,
    Product,
    Affected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Cve(CveRecord),
    Product(Product),
    Affected(Affected),
}

impl Record {
    pub fn kind(&self) -> RecordKind {
        match self {
            Record::Cve(_) => RecordKind::Cve,
            Record::Product(_) => RecordKind::Product,
            Record::Affected(_) => RecordKind::Affected,
        }
    }
    pub fn id(&self) -> String {
        match self {
            Record::Cve(cve) => cve.id.clone(),
            Record::Product(product) => product.key.clone(),
            Record::Affected(affected) => affected.id(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(default)]
    pub scores: Vec<Score>,
    /// Rounded to one significant digit so daily EPSS noise does not turn
    /// every record into a delta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kev: Option<Kev>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssvc: Option<Ssvc>,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreOrigin {
    /// The CNA that assigned the CVE, usually the vendor.
    Cna,
    /// An Authorized Data Publisher such as CISA Vulnrichment.
    Adp,
    /// NIST's National Vulnerability Database analysis.
    Nvd,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    pub origin: ScoreOrigin,
    pub provider: String,
    /// CVSS version: "4.0", "3.1", "3.0" or "2.0".
    pub version: String,
    pub base_score: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kev {
    pub added: NaiveDate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due: Option<NaiveDate>,
    #[serde(default)]
    pub ransomware: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ssvc {
    /// "none", "poc" or "active".
    pub exploitation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automatable: Option<bool>,
    /// "partial" or "total".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technical_impact: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
}

/// How a product's matchers were made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Reviewed against real CVE records and endpoint reports.
    #[default]
    Curated,
    /// Derived from CPE names; findings are shown as inferred.
    Inferred,
}

impl Confidence {
    pub fn is_curated(&self) -> bool {
        *self == Confidence::Curated
    }
}

/// A product the server can recognise on an endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Product {
    pub key: String,
    pub name: String,
    pub matchers: Vec<Matcher>,
    #[serde(default, skip_serializing_if = "Confidence::is_curated")]
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    /// Installed software. Names are case-insensitive `*` globs; publishers
    /// are case-insensitive substrings. A package name match is sufficient.
    Software {
        platform: Platform,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sources: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        names: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude_names: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        publishers: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        package_names: Vec<String>,
        /// How to turn the reported version into the vendor's notation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<VersionRule>,
    },
    /// Windows release by build ("26100") and edition; the version compared
    /// is the reported build.UBR.
    Windows { server: bool, build: u32 },
    /// macOS; the version compared is the marketing version ("15.5").
    Macos,
    /// Windows or macOS software whose `software_key` is one of `names`, from
    /// one of `publishers` when any are listed: on Windows the publisher must
    /// match (`publisher_matches`) or the program name start with the vendor;
    /// macOS bundles report no publisher, so the vendor must appear in the
    /// bundle identifier or the name. No platforms means Windows and macOS.
    Alias {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        platforms: Vec<Platform>,
        names: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        publishers: Vec<String>,
    },
    /// Debian or Ubuntu package built from `source` on a release (`linux_release`).
    DebPackage {
        distro: String,
        release: String,
        source: String,
    },
    /// Binary RPM package on a major release of "rhel", "almalinux" or "rocky".
    RpmPackage {
        distro: String,
        release: String,
        name: String,
    },
}

/// Vendor notations that installed versions are converted to before they
/// are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionRule {
    /// Oracle Java: "Java 8 Update 441" (DisplayVersion 8.0.4410.7) is
    /// "8u441"; Java 9 and later keep their version ("17.0.14.0").
    JavaUpdate,
}

impl VersionRule {
    pub fn apply(self, name: &str, version: &str) -> String {
        match self {
            VersionRule::JavaUpdate => {
                let words: Vec<&str> = name.split_whitespace().collect();
                let number = |word: &str| {
                    let digits: String = word.chars().take_while(|c| c.is_ascii_digit()).collect();
                    (!digits.is_empty() && digits.len() == word.len()).then_some(digits)
                };
                words
                    .windows(3)
                    .find_map(|window| {
                        let release = number(window[0])?;
                        let update = window[1]
                            .eq_ignore_ascii_case("update")
                            .then(|| number(window[2]))??;
                        Some(format!("{release}u{update}"))
                    })
                    .unwrap_or_else(|| version.to_string())
            }
        }
    }
}

/// Versions of `product` affected by `cve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Affected {
    pub cve: String,
    pub product: String,
    pub spans: Vec<Span>,
    /// Status of versions outside every span.
    #[serde(default)]
    pub default_affected: bool,
    /// Display text for the fix, such as "141.0.3537.57" or "KB5066835".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix_url: Option<String>,
    #[serde(default, skip_serializing_if = "VersionScheme::is_generic")]
    pub scheme: VersionScheme,
}

impl Affected {
    pub fn id(&self) -> String {
        affected_id(&self.cve, &self.product)
    }

    /// `None` when the version cannot be judged. Unaffected spans win.
    pub fn affects(&self, version: &str) -> Option<bool> {
        let version = version.trim();
        if version.is_empty() || !version.chars().any(|c| c.is_ascii_digit()) {
            return None;
        }
        if self
            .spans
            .iter()
            .any(|span| !span.affected && span.contains(self.scheme, version))
        {
            return Some(false);
        }
        if self
            .spans
            .iter()
            .any(|span| span.affected && span.contains(self.scheme, version))
        {
            return Some(true);
        }
        Some(self.default_affected)
    }
}

/// How the versions of an `Affected` entry are ordered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionScheme {
    /// `compare_versions`: vendor version strings.
    #[default]
    Generic,
    /// Debian package versions (`compare_dpkg`).
    Dpkg,
    /// RPM epoch:version-release (`compare_rpm`).
    Rpm,
}

impl VersionScheme {
    pub fn is_generic(&self) -> bool {
        *self == VersionScheme::Generic
    }

    pub fn compare(self, left: &str, right: &str) -> Ordering {
        match self {
            VersionScheme::Generic => compare_versions(left, right),
            VersionScheme::Dpkg => compare_dpkg(left, right),
            VersionScheme::Rpm => compare_rpm(left, right),
        }
    }
}

pub fn affected_id(cve: &str, product: &str) -> String {
    format!("{cve}|{product}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub affected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(default = "inclusive", skip_serializing_if = "is_true")]
    pub start_inclusive: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub end_inclusive: bool,
}

fn inclusive() -> bool {
    true
}
fn is_true(value: &bool) -> bool {
    *value
}
fn is_false(value: &bool) -> bool {
    !*value
}

impl Span {
    pub fn contains(&self, scheme: VersionScheme, version: &str) -> bool {
        let above =
            self.start
                .as_deref()
                .is_none_or(|start| match scheme.compare(version, start) {
                    Ordering::Greater => true,
                    Ordering::Equal => self.start_inclusive,
                    Ordering::Less => false,
                });
        let below = self
            .end
            .as_deref()
            .is_none_or(|end| match scheme.compare(version, end) {
                Ordering::Less => true,
                Ordering::Equal => self.end_inclusive,
                Ordering::Greater => false,
            });
        above && below
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Number(String),
    Text(String),
    /// `*` in "115.*": above every value.
    Any,
}

fn tokens(version: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let flush = |current: &mut String, tokens: &mut Vec<Token>| {
        if current.is_empty() {
            return;
        }
        if current.starts_with(|c: char| c.is_ascii_digit()) {
            let digits = current.trim_start_matches('0');
            tokens.push(Token::Number(if digits.is_empty() {
                "0".into()
            } else {
                digits.into()
            }));
        } else {
            tokens.push(Token::Text(current.to_ascii_lowercase()));
        }
        current.clear();
    };
    for c in version.trim().chars() {
        if c == '*' {
            flush(&mut current, &mut tokens);
            tokens.push(Token::Any);
        } else if c.is_ascii_alphanumeric() {
            let switching = current
                .chars()
                .last()
                .is_some_and(|last| last.is_ascii_digit() != c.is_ascii_digit());
            if switching {
                flush(&mut current, &mut tokens);
            }
            current.push(c);
        } else {
            flush(&mut current, &mut tokens);
        }
    }
    flush(&mut current, &mut tokens);
    tokens
}

fn compare_token(left: &Token, right: &Token) -> Ordering {
    match (left, right) {
        (Token::Any, Token::Any) => Ordering::Equal,
        (Token::Any, _) => Ordering::Greater,
        (_, Token::Any) => Ordering::Less,
        (Token::Number(a), Token::Number(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        (Token::Text(a), Token::Text(b)) => a.cmp(b),
        (Token::Number(_), Token::Text(_)) => Ordering::Greater,
        (Token::Text(_), Token::Number(_)) => Ordering::Less,
    }
}

/// Dotted, mixed-format version order: "1.10" > "1.9", "1.0" == "1.0.0",
/// a trailing label is a pre-release ("2.0-beta" < "2.0") and `*` is maximal.
pub fn compare_versions(left: &str, right: &str) -> Ordering {
    let (left, right) = (tokens(left), tokens(right));
    for index in 0..left.len().max(right.len()) {
        let ordering = match (left.get(index), right.get(index)) {
            (Some(a), Some(b)) => compare_token(a, b),
            (Some(rest), None) => trailing(rest),
            (None, Some(rest)) => trailing(rest).reverse(),
            (None, None) => Ordering::Equal,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn trailing(token: &Token) -> Ordering {
    match token {
        Token::Number(digits) if digits == "0" => Ordering::Equal,
        Token::Number(_) | Token::Any => Ordering::Greater,
        Token::Text(_) => Ordering::Less,
    }
}

/// Splits "epoch:rest" with a numeric epoch; no epoch is 0.
fn split_epoch(version: &str) -> (u64, &str) {
    match version.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            (epoch.parse().unwrap_or(u64::MAX), rest)
        }
        _ => (0, version),
    }
}

/// Numeric runs compared by value, without leading zeros.
fn compare_digits(left: &[u8], right: &[u8]) -> Ordering {
    let strip = |digits: &[u8]| {
        let start = digits
            .iter()
            .position(|b| *b != b'0')
            .unwrap_or(digits.len());
        digits[start..].to_vec()
    };
    let (left, right) = (strip(left), strip(right));
    left.len().cmp(&right.len()).then_with(|| left.cmp(&right))
}

/// dpkg's verrevcmp: `~` sorts before everything, even the end of the string;
/// letters sort before other characters; digit runs compare numerically.
fn compare_dpkg_part(left: &str, right: &str) -> Ordering {
    fn order(byte: Option<&u8>) -> i32 {
        match byte {
            None => 0,
            Some(b) if b.is_ascii_digit() => 0,
            Some(b) if b.is_ascii_alphabetic() => *b as i32,
            Some(b'~') => -1,
            Some(b) => *b as i32 + 256,
        }
    }
    let (a, b) = (left.as_bytes(), right.as_bytes());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let (left, right) = (order(a.get(i)), order(b.get(j)));
            if left != right {
                return left.cmp(&right);
            }
            i += 1;
            j += 1;
        }
        let digits = |bytes: &[u8], from: usize| {
            let end = bytes[from.min(bytes.len())..]
                .iter()
                .position(|b| !b.is_ascii_digit())
                .map_or(bytes.len(), |n| from + n);
            (from.min(bytes.len()), end)
        };
        let ((ls, le), (rs, re)) = (digits(a, i), digits(b, j));
        let ordering = compare_digits(&a[ls..le], &b[rs..re]);
        if ordering != Ordering::Equal {
            return ordering;
        }
        (i, j) = (le, re);
    }
    Ordering::Equal
}

/// Debian package versions: epoch, then upstream, then the revision after
/// the last `-` ("1:2.36-9+deb12u4"). binNMUs ("+b1") sort after their base.
pub fn compare_dpkg(left: &str, right: &str) -> Ordering {
    let split = |version: &str| -> (u64, String, String) {
        let (epoch, rest) = split_epoch(version.trim());
        match rest.rsplit_once('-') {
            Some((upstream, revision)) => (epoch, upstream.into(), revision.into()),
            None => (epoch, rest.into(), String::new()),
        }
    };
    let (left, right) = (split(left), split(right));
    left.0
        .cmp(&right.0)
        .then_with(|| compare_dpkg_part(&left.1, &right.1))
        .then_with(|| compare_dpkg_part(&left.2, &right.2))
}

/// rpm's rpmvercmp: alphanumeric segments, digits newer than letters, `~`
/// before everything and `^` after the base version but before its updates.
fn compare_rpm_part(left: &str, right: &str) -> Ordering {
    if left == right {
        return Ordering::Equal;
    }
    let (a, b) = (left.as_bytes(), right.as_bytes());
    let (mut i, mut j) = (0, 0);
    let separator = |byte: u8| !byte.is_ascii_alphanumeric() && byte != b'~' && byte != b'^';
    while i < a.len() || j < b.len() {
        while i < a.len() && separator(a[i]) {
            i += 1;
        }
        while j < b.len() && separator(b[j]) {
            j += 1;
        }
        if a.get(i) == Some(&b'~') || b.get(j) == Some(&b'~') {
            if a.get(i) != Some(&b'~') {
                return Ordering::Greater;
            }
            if b.get(j) != Some(&b'~') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if a.get(i) == Some(&b'^') || b.get(j) == Some(&b'^') {
            if i >= a.len() {
                return Ordering::Less;
            }
            if j >= b.len() {
                return Ordering::Greater;
            }
            if a[i] != b'^' {
                return Ordering::Greater;
            }
            if b[j] != b'^' {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        let numeric = a[i].is_ascii_digit();
        let same = |byte: &u8| {
            if numeric {
                byte.is_ascii_digit()
            } else {
                byte.is_ascii_alphabetic()
            }
        };
        let end = |bytes: &[u8], from: usize| {
            bytes[from..]
                .iter()
                .position(|byte| !same(byte))
                .map_or(bytes.len(), |n| from + n)
        };
        let (ie, je) = (end(a, i), end(b, j));
        if je == j {
            // A number against letters: the number is newer.
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let ordering = if numeric {
            compare_digits(&a[i..ie], &b[j..je])
        } else {
            a[i..ie].cmp(&b[j..je])
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
        (i, j) = (ie, je);
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (false, _) => Ordering::Greater,
        (true, false) => Ordering::Less,
    }
}

/// RPM "epoch:version-release"; a missing release matches any release.
pub fn compare_rpm(left: &str, right: &str) -> Ordering {
    let split = |version: &str| -> (u64, String, Option<String>) {
        let (epoch, rest) = split_epoch(version.trim());
        match rest.rsplit_once('-') {
            Some((version, release)) => (epoch, version.into(), Some(release.into())),
            None => (epoch, rest.into(), None),
        }
    };
    let (left, right) = (split(left), split(right));
    left.0
        .cmp(&right.0)
        .then_with(|| compare_rpm_part(&left.1, &right.1))
        .then_with(|| match (&left.2, &right.2) {
            (Some(a), Some(b)) => compare_rpm_part(a, b),
            _ => Ordering::Equal,
        })
}

/// Case-insensitive glob with `*` as the only wildcard.
pub fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.trim().to_lowercase().chars().collect();
    let value: Vec<char> = value.trim().to_lowercase().chars().collect();
    let (mut p, mut v) = (0, 0);
    let (mut star, mut resume) = (None, 0);
    while v < value.len() {
        if p < pattern.len() && pattern[p] != '*' && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            resume = v;
        } else if let Some(position) = star {
            p = position + 1;
            resume += 1;
            v = resume;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// One installed program as the server stores it.
#[derive(Debug, Clone, Copy)]
pub struct SoftwareRef<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub publisher: &'a str,
    pub source: &'a str,
    pub package_name: Option<&'a str>,
}

/// What a device reported, reduced to what matching needs.
#[derive(Debug, Clone)]
pub struct Endpoint<'a> {
    pub os_version: &'a str,
    /// Windows "26100.6899", macOS "24F74", Linux "<os-release ID>:<VERSION_ID>".
    pub os_build: &'a str,
    pub software: Vec<SoftwareRef<'a>>,
}

/// A recognised product and the version to compare.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Observation {
    pub product: String,
    pub name: String,
    pub version: String,
    pub confidence: Confidence,
}

pub fn endpoint_platform(os_version: &str) -> Option<Platform> {
    let os = os_version.trim().to_ascii_lowercase();
    let os = os.strip_prefix("microsoft ").unwrap_or(&os);
    if os.starts_with("windows") {
        Some(Platform::Windows)
    } else if ["macos", "mac os x", "os x"]
        .iter()
        .any(|prefix| os.starts_with(prefix))
    {
        Some(Platform::Macos)
    } else if os.is_empty() {
        None
    } else {
        Some(Platform::Linux)
    }
}

/// Marketing version of a macOS report such as "macOS 15.5 Sequoia".
fn macos_version(os_version: &str) -> Option<&str> {
    os_version
        .split_whitespace()
        .find(|part| part.starts_with(|c: char| c.is_ascii_digit()))
}

/// Channel holding the data of a `linux_release` distribution.
pub fn linux_channel(distro: &str) -> Option<&'static str> {
    match distro {
        "debian" => Some("linux-debian"),
        "ubuntu" => Some("linux-ubuntu"),
        "rhel" | "almalinux" | "rocky" => Some("linux-rhel"),
        _ => None,
    }
}

/// Distribution and release a Linux `os_build` ("ubuntu:24.04",
/// "almalinux:9.4") is matched with: Ubuntu by release, the others by major
/// release. RHEL rebuilds keep their own data: their release suffixes
/// ("1.el9_3.alma") do not compare with Red Hat's.
pub fn linux_release(os_build: &str) -> Option<(&'static str, String)> {
    let (id, version) = os_build.trim().split_once(':')?;
    let version = version.trim().trim_matches('"');
    let major = version
        .split('.')
        .next()
        .filter(|major| !major.is_empty() && major.bytes().all(|b| b.is_ascii_digit()))?;
    match id.trim().trim_matches('"').to_ascii_lowercase().as_str() {
        "debian" => Some(("debian", major.into())),
        "ubuntu" => Some(("ubuntu", version.into())),
        "rhel" => Some(("rhel", major.into())),
        "almalinux" => Some(("almalinux", major.into())),
        "rocky" => Some(("rocky", major.into())),
        _ => None,
    }
}

/// Words that describe a build rather than the product.
const BUILD_WORDS: &[&str] = &[
    "x64", "x86", "x86_64", "amd64", "arm64", "aarch64", "64-bit", "32-bit", "64bit", "32bit",
    "win64", "win32", "release", "version",
];

/// "1.2", "v24.08", "3.0.7-beta": a word that is a version number.
fn is_version_word(word: &str) -> bool {
    let word = word.strip_prefix(['v', 'V']).unwrap_or(word);
    let head = word.split('.').next().unwrap_or("");
    word.contains('.')
        && !head.is_empty()
        && head.bytes().all(|b| b.is_ascii_digit())
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
}

/// A locale tag inside parentheses: "ja", "en-us", "zh-hans".
fn is_locale_word(word: &str) -> bool {
    let mut parts = word.split('-');
    let language = parts.next().unwrap_or("");
    language.len() == 2
        && language.bytes().all(|b| b.is_ascii_lowercase())
        && parts.all(|part| {
            (2..=4).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

/// Name an installed program and a CPE title are compared by: lowercase,
/// without versions, architectures, punctuation and parenthesised notes.
/// "Mozilla Firefox (x64 ja)" and "Mozilla Firefox 120.0" are both
/// "mozilla firefox"; "7-Zip 24.08 (x64)" is "7 zip"; "Slack (Machine -
/// MSI)" is "slack".
pub fn software_key(name: &str) -> String {
    let name = name.to_lowercase().replace(['®', '™', '©'], " ");
    let mut words: Vec<String> = Vec::new();
    let mut depth = 0usize;
    for raw in name.split_whitespace() {
        let opens = raw.chars().filter(|c| matches!(c, '(' | '[')).count();
        let closes = raw.chars().filter(|c| matches!(c, ')' | ']')).count();
        // "(x64)", "(Machine - MSI)", "[ja-JP]": build notes, not the name.
        let inside = depth > 0 || raw.starts_with(['(', '[']);
        depth = (depth + opens).saturating_sub(closes);
        if inside {
            continue;
        }
        let word = raw
            .split(['(', '['])
            .next()
            .unwrap_or("")
            .trim_matches(|c: char| matches!(c, ')' | ']' | ',' | ';'));
        let noise = word.is_empty() || BUILD_WORDS.contains(&word) || is_version_word(word);
        if noise {
            continue;
        }
        let mut current = String::new();
        let mut push = |current: &mut String| {
            // "7-x64" splits into "7" and "x64": drop the build word too, so
            // that keys of keys are the same keys.
            let token = std::mem::take(current);
            if !token.is_empty() && !BUILD_WORDS.contains(&token.as_str()) {
                words.push(token);
            }
        };
        for c in word.chars() {
            if c.is_alphanumeric() || c == '+' || c == '#' {
                current.push(c);
            } else {
                push(&mut current);
            }
        }
        push(&mut current);
    }
    words.join(" ")
}

/// Company suffixes that publishers add and CPE vendors leave out.
const COMPANY_WORDS: &[&str] = &[
    "the",
    "inc",
    "incorporated",
    "corp",
    "corporation",
    "co",
    "company",
    "llc",
    "ltd",
    "limited",
    "gmbh",
    "ag",
    "sa",
    "bv",
    "oy",
    "ab",
    "kk",
    "plc",
    "srl",
    "pty",
    "sas",
    "spa",
];

/// Publisher or CPE vendor as lowercase words without company suffixes:
/// "Google LLC" and "google" are both "google"; "igor_pavlov" is "igor pavlov".
pub fn publisher_key(publisher: &str) -> String {
    publisher
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty() && !COMPANY_WORDS.contains(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A reported publisher matches a vendor key when it starts with the
/// vendor's words ("wireshark developer community" for "wireshark") or is
/// the same without spaces ("video lan" for "videolan").
pub fn publisher_matches(vendor_key: &str, publisher: &str) -> bool {
    let reported = publisher_key(publisher);
    if vendor_key.is_empty() || reported.is_empty() {
        return false;
    }
    let words: Vec<&str> = reported.split(' ').collect();
    let wanted: Vec<&str> = vendor_key.split(' ').collect();
    words.starts_with(&wanted) || reported.replace(' ', "") == vendor_key.replace(' ', "")
}

impl Matcher {
    fn observe(&self, endpoint: &Endpoint<'_>, platform: Platform) -> Vec<(String, String)> {
        match self {
            Matcher::Windows { server, build } if platform == Platform::Windows => {
                let reported_server = endpoint.os_version.to_ascii_lowercase().contains("server");
                let reported_build = endpoint.os_build.trim();
                // Without the update revision the patch level is unknown.
                let known = reported_build.split_once('.').is_some_and(|(major, ubr)| {
                    major.parse::<u32>().ok() == Some(*build)
                        && !ubr.is_empty()
                        && ubr.chars().all(|c| c.is_ascii_digit())
                });
                if reported_server == *server && known {
                    vec![(endpoint.os_version.trim().into(), reported_build.into())]
                } else {
                    Vec::new()
                }
            }
            Matcher::Macos if platform == Platform::Macos => macos_version(endpoint.os_version)
                .map(|version| vec![(endpoint.os_version.trim().into(), version.into())])
                .unwrap_or_default(),
            Matcher::Software {
                platform: wanted,
                sources,
                names,
                exclude_names,
                publishers,
                package_names,
                version: rule,
            } if *wanted == platform => endpoint
                .software
                .iter()
                .filter(|item| {
                    if !sources.is_empty() && !sources.iter().any(|s| s == item.source) {
                        return false;
                    }
                    if exclude_names
                        .iter()
                        .any(|pattern| glob_matches(pattern, item.name))
                    {
                        return false;
                    }
                    let package = item.package_name.is_some_and(|package| {
                        package_names
                            .iter()
                            .any(|wanted| wanted.eq_ignore_ascii_case(package.trim()))
                    });
                    let publisher = item.publisher.to_lowercase();
                    package
                        || (names.iter().any(|pattern| glob_matches(pattern, item.name))
                            && (publishers.is_empty()
                                || publishers
                                    .iter()
                                    .any(|wanted| publisher.contains(&wanted.to_lowercase()))))
                })
                .filter(|item| !item.version.trim().is_empty())
                .map(|item| {
                    let version = item.version.trim();
                    let version = match rule {
                        Some(rule) => rule.apply(item.name, version),
                        None => version.to_string(),
                    };
                    (item.name.trim().into(), version)
                })
                .collect(),
            // Looked up by ProductIndex instead.
            _ => Vec::new(),
        }
    }

    /// Whether an `Alias` matcher accepts software already found by name.
    fn accepts_alias(&self, item: &SoftwareRef<'_>, platform: Platform) -> bool {
        let Matcher::Alias {
            platforms,
            publishers,
            ..
        } = self
        else {
            return false;
        };
        let on_platform = if platforms.is_empty() {
            matches!(platform, Platform::Windows | Platform::Macos)
        } else {
            platforms.contains(&platform)
        };
        if !on_platform || publishers.is_empty() {
            return on_platform;
        }
        if platform == Platform::Macos {
            // Bundles report no publisher, so the vendor must appear in the
            // bundle identifier ("com.docker.docker") or the program name:
            // a "Docker" app is not synology:docker, nor Apple's Calculator
            // another vendor's calculator.
            let bundle = item.package_name.unwrap_or("").to_ascii_lowercase();
            let name = software_key(item.name).replace(' ', "");
            return publishers.iter().any(|vendor| {
                let first = vendor.split(' ').next().unwrap_or("");
                first.len() >= 3 && (bundle.contains(first) || name.contains(first))
            });
        }
        // Projects published under a person's name ("WinSCP" by Martin
        // Prikryl) carry the vendor's name in the program's.
        let first_word = software_key(item.name)
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string();
        publishers.iter().any(|vendor| {
            publisher_matches(vendor, item.publisher)
                || vendor.split(' ').next() == Some(first_word.as_str())
        })
    }
}

/// Products to match endpoints against, indexed so that matching a device
/// costs one lookup per installed program rather than one per product.
#[derive(Debug, Clone, Default)]
pub struct ProductIndex {
    products: Vec<Product>,
    /// (product, matcher) pairs checked one by one: Software, Windows, Macos.
    scanned: Vec<(usize, usize)>,
    /// `software_key` -> Alias matchers.
    aliases: std::collections::HashMap<String, Vec<(usize, usize)>>,
    /// (family, release, package) -> products.
    packages: std::collections::HashMap<(String, String, String), Vec<usize>>,
}

impl ProductIndex {
    pub fn new(products: Vec<Product>) -> Self {
        let mut index = ProductIndex::default();
        for (p, product) in products.iter().enumerate() {
            for (m, matcher) in product.matchers.iter().enumerate() {
                match matcher {
                    Matcher::Alias { names, .. } => {
                        for name in names {
                            let entry = index.aliases.entry(software_key(name)).or_default();
                            if !entry.contains(&(p, m)) {
                                entry.push((p, m));
                            }
                        }
                    }
                    Matcher::DebPackage {
                        distro,
                        release,
                        source: name,
                    }
                    | Matcher::RpmPackage {
                        distro,
                        release,
                        name,
                    } => {
                        let entry = index
                            .packages
                            .entry((distro.clone(), release.clone(), name.clone()))
                            .or_default();
                        if !entry.contains(&p) {
                            entry.push(p);
                        }
                    }
                    _ => index.scanned.push((p, m)),
                }
            }
        }
        index.products = products;
        index
    }

    pub fn products(&self) -> &[Product] {
        &self.products
    }

    /// Products recognised on the endpoint, one observation per installed
    /// copy, in catalog order.
    pub fn observe(&self, endpoint: &Endpoint<'_>) -> Vec<Observation> {
        let Some(platform) = endpoint_platform(endpoint.os_version) else {
            return Vec::new();
        };
        let mut found: Vec<(usize, String, String)> = Vec::new();
        for &(p, m) in &self.scanned {
            for (name, version) in self.products[p].matchers[m].observe(endpoint, platform) {
                found.push((p, name, version));
            }
        }
        // A program a curated product recognises is not inferred again.
        let curated: std::collections::HashSet<(String, String)> = found
            .iter()
            .filter(|(p, _, _)| self.products[*p].confidence.is_curated())
            .map(|(_, name, version)| (name.clone(), version.clone()))
            .collect();
        let linux = (platform == Platform::Linux)
            .then(|| linux_release(endpoint.os_build))
            .flatten();
        for item in &endpoint.software {
            let version = item.version.trim();
            if version.is_empty() {
                continue;
            }
            let copy = |p: usize| (p, item.name.trim().to_string(), version.to_string());
            if let Some((family, release)) = &linux {
                let package = match item.source {
                    "dpkg" => item.package_name.unwrap_or(item.name),
                    "rpm" => item.name,
                    _ => continue,
                };
                let key = (
                    family.to_string(),
                    release.clone(),
                    package.trim().to_string(),
                );
                for &p in self.packages.get(&key).into_iter().flatten() {
                    found.push(copy(p));
                }
            } else if platform != Platform::Linux
                && !curated.contains(&(item.name.trim().to_string(), version.to_string()))
            {
                for &(p, m) in self
                    .aliases
                    .get(&software_key(item.name))
                    .into_iter()
                    .flatten()
                {
                    if self.products[p].matchers[m].accepts_alias(item, platform) {
                        found.push(copy(p));
                    }
                }
            }
        }
        found.sort_by_key(|(p, _, _)| *p);
        let mut seen = std::collections::HashSet::new();
        found
            .into_iter()
            .map(|(p, name, version)| Observation {
                product: self.products[p].key.clone(),
                name,
                version,
                confidence: self.products[p].confidence,
            })
            .filter(|observation| seen.insert(observation.clone()))
            .collect()
    }
}

/// Products recognised on the endpoint, one observation per installed copy.
/// Servers keep a `ProductIndex` instead of rebuilding it per device.
pub fn observe(products: &[Product], endpoint: &Endpoint<'_>) -> Vec<Observation> {
    ProductIndex::new(products.to_vec()).observe(endpoint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> i16 {
        self as i16
    }
}

/// Qualitative CVSS rating; v2.0 has no "critical" or "none" band.
pub fn severity(score: &Score) -> Severity {
    let value = score.base_score;
    if score.version.starts_with('2') {
        return if value >= 7.0 {
            Severity::High
        } else if value >= 4.0 {
            Severity::Medium
        } else {
            Severity::Low
        };
    }
    if value >= 9.0 {
        Severity::Critical
    } else if value >= 7.0 {
        Severity::High
    } else if value >= 4.0 {
        Severity::Medium
    } else if value > 0.0 {
        Severity::Low
    } else {
        Severity::None
    }
}

fn version_rank(version: &str) -> u8 {
    match version {
        "4.0" => 4,
        "3.1" => 3,
        "3.0" => 2,
        "2.0" => 1,
        _ => 0,
    }
}

/// The CNA (usually the vendor) knows the product best; NVD's analysis is
/// the long-standing reference; ADPs such as CISA Vulnrichment fill gaps.
fn origin_rank(origin: ScoreOrigin) -> u8 {
    match origin {
        ScoreOrigin::Cna => 3,
        ScoreOrigin::Nvd => 2,
        ScoreOrigin::Adp => 1,
    }
}

/// Score shown in lists and used for priority: by origin (CNA, NVD, then
/// ADPs), then the newest CVSS version of that origin.
pub fn primary_score(scores: &[Score]) -> Option<&Score> {
    scores
        .iter()
        .filter(|score| score.base_score.is_finite() && version_rank(&score.version) > 0)
        .max_by_key(|score| (origin_rank(score.origin), version_rank(&score.version)))
}

/// 1: exploited (KEV or SSVC "active"); 2: likely exploited (EPSS >= 10% or
/// a public PoC) and high/critical or unscored; 3: high/critical; 4: others.
pub fn priority(cve: &CveRecord) -> i16 {
    let exploitation = cve.ssvc.as_ref().map(|ssvc| ssvc.exploitation.as_str());
    if cve.kev.is_some() || exploitation == Some("active") {
        return 1;
    }
    let severity = primary_score(&cve.scores).map(severity);
    let serious = severity.is_none_or(|severity| severity >= Severity::High);
    if serious && (cve.epss.is_some_and(|epss| epss >= 0.1) || exploitation == Some("poc")) {
        return 2;
    }
    if severity.is_some_and(|severity| severity >= Severity::High) {
        3
    } else {
        4
    }
}

/// One significant digit, e.g. 0.0437 -> 0.04 and 0.37 -> 0.4.
pub fn quantize_epss(value: f32) -> Option<f32> {
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    let value = value.min(1.0) as f64;
    let magnitude = 10f64.powi(value.log10().floor() as i32);
    let rounded = (value / magnitude).round() * magnitude;
    // Print-stable: "0.04", not "0.039999999".
    format!("{:.6}", rounded.min(1.0)).parse().ok()
}

#[derive(Debug)]
pub struct FeedError(pub String);

impl std::fmt::Display for FeedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FeedError {}

fn error(message: impl Into<String>) -> FeedError {
    FeedError(message.into())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// Signs the header line and prepends it to the body.
pub fn seal(key: &RsaPrivateKey, header: &[u8], body: &[u8]) -> Vec<u8> {
    assert!(!header.contains(&b'\n'), "header must be a single line");
    let signature = SigningKey::<Sha256>::new(key.clone())
        .sign_with_rng(&mut rand::thread_rng(), header)
        .to_bytes();
    use base64::Engine as _;
    let mut file = Vec::with_capacity(MAGIC.len() + header.len() + body.len() + 600);
    file.extend_from_slice(MAGIC);
    file.extend_from_slice(
        base64::engine::general_purpose::STANDARD
            .encode(signature)
            .as_bytes(),
    );
    file.push(b'\n');
    file.extend_from_slice(header);
    file.push(b'\n');
    file.extend_from_slice(body);
    file
}

/// Verifies the signature and returns the header line and the body.
pub fn open<'a>(key: &RsaPublicKey, file: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), FeedError> {
    let rest = file
        .strip_prefix(MAGIC)
        .ok_or_else(|| error("Not a Remotto vulnerability feed file"))?;
    let (signature, rest) = split_line(rest, 4096)?;
    let (header, body) = split_line(rest, MAX_HEADER_BYTES)?;
    use base64::Engine as _;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .ok()
        .and_then(|bytes| Signature::try_from(bytes.as_slice()).ok())
        .ok_or_else(|| error("Invalid feed signature"))?;
    VerifyingKey::<Sha256>::new(key.clone())
        .verify(header, &signature)
        .map_err(|_| error("Feed signature verification failed"))?;
    Ok((header, body))
}

fn split_line(bytes: &[u8], limit: usize) -> Result<(&[u8], &[u8]), FeedError> {
    let end = bytes
        .iter()
        .take(limit + 1)
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| error("Truncated feed file"))?;
    Ok((&bytes[..end], &bytes[end + 1..]))
}

/// Opens a snapshot or delta and checks its body against the signed digest.
pub fn open_data<'a>(key: &RsaPublicKey, file: &'a [u8]) -> Result<(Header, &'a [u8]), FeedError> {
    let (header, body) = open(key, file)?;
    let header: Header =
        serde_json::from_slice(header).map_err(|_| error("Invalid feed header"))?;
    if header.format != FORMAT {
        return Err(error(format!(
            "Unsupported feed format {}; update Remotto Server",
            header.format
        )));
    }
    match (header.kind, header.base_version) {
        (Kind::Snapshot, None) => {}
        (Kind::Delta, Some(base)) if base < header.version => {}
        _ => return Err(error("Invalid feed file kind")),
    }
    if body.len() as u64 != header.body_bytes || sha256_hex(body) != header.body_sha256 {
        return Err(error("Feed file is corrupted"));
    }
    Ok((header, body))
}

pub fn open_manifest(key: &RsaPublicKey, file: &[u8]) -> Result<Manifest, FeedError> {
    let (header, _) = open(key, file)?;
    let manifest: Manifest =
        serde_json::from_slice(header).map_err(|_| error("Invalid feed manifest"))?;
    if manifest.format != FORMAT {
        return Err(error(format!(
            "Unsupported feed format {}; update Remotto Server",
            manifest.format
        )));
    }
    if manifest.kind != Kind::Manifest {
        return Err(error("Invalid feed manifest"));
    }
    Ok(manifest)
}

pub fn encode_ops(ops: &[Op]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    for op in ops {
        serde_json::to_writer(&mut encoder, op).expect("feed records serialize");
        encoder.write_all(b"\n").expect("in-memory write");
    }
    encoder.finish().expect("in-memory gzip")
}

/// Streams operations without inflating the whole body into memory.
pub fn decode_ops(body: &[u8]) -> impl Iterator<Item = Result<Op, FeedError>> + '_ {
    let mut reader = BufReader::new(flate2::read::GzDecoder::new(body));
    let mut line = Vec::new();
    std::iter::from_fn(move || loop {
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_until(b'\n', &mut line);
        match read {
            Ok(0) => return None,
            Ok(_) if line.len() > MAX_RECORD_BYTES => {
                return Some(Err(error("Feed record is too large")))
            }
            Ok(_) if line.iter().all(u8::is_ascii_whitespace) => continue,
            Ok(_) => {
                return Some(
                    serde_json::from_slice(&line).map_err(|_| error("Invalid feed record")),
                )
            }
            Err(_) => return Some(Err(error("Feed file is corrupted"))),
        }
    })
}

/// Builds a signed snapshot or delta file.
#[allow(clippy::too_many_arguments)]
pub fn build_data(
    key: &RsaPrivateKey,
    kind: Kind,
    channel: &str,
    feed_id: &str,
    base_version: Option<u64>,
    version: u64,
    generated_at: DateTime<Utc>,
    ops: &[Op],
) -> Vec<u8> {
    let body = encode_ops(ops);
    let header = Header {
        format: FORMAT,
        kind,
        channel: channel.into(),
        feed_id: feed_id.into(),
        base_version,
        version,
        generated_at,
        records: ops.len() as u64,
        body_sha256: sha256_hex(&body),
        body_bytes: body.len() as u64,
    };
    seal(
        key,
        &serde_json::to_vec(&header).expect("header serializes"),
        &body,
    )
}

pub fn build_manifest(key: &RsaPrivateKey, manifest: &Manifest) -> Vec<u8> {
    seal(
        key,
        &serde_json::to_vec(manifest).expect("manifest serializes"),
        &[],
    )
}

/// Where a server stands: its feed lineage and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    pub feed_id: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    UpToDate,
    Deltas(Vec<DeltaRef>),
    Snapshot(FileRef),
}

/// The cheapest way to reach the manifest's version: a chain of deltas from
/// the current version when it is complete and smaller, else the snapshot.
pub fn plan(manifest: &Manifest, current: Option<&Position>) -> Plan {
    let Some(current) = current.filter(|current| current.feed_id == manifest.feed_id) else {
        return Plan::Snapshot(manifest.snapshot.clone());
    };
    if current.version >= manifest.version {
        return Plan::UpToDate;
    }
    let mut chain = Vec::new();
    let mut version = current.version;
    while version < manifest.version {
        let Some(next) = manifest
            .deltas
            .iter()
            .filter(|delta| delta.base_version == version && delta.version > version)
            .max_by_key(|delta| delta.version)
        else {
            return Plan::Snapshot(manifest.snapshot.clone());
        };
        version = next.version;
        chain.push(next.clone());
    }
    let delta_bytes: u64 = chain.iter().map(|delta| delta.file.bytes).sum();
    if delta_bytes >= manifest.snapshot.bytes {
        Plan::Snapshot(manifest.snapshot.clone())
    } else {
        Plan::Deltas(chain)
    }
}

pub fn parse_public_key(pem: &str) -> Result<RsaPublicKey, FeedError> {
    use rsa::pkcs8::DecodePublicKey;
    RsaPublicKey::from_public_key_pem(pem).map_err(|_| error("Invalid feed public key"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> RsaPrivateKey {
        // A small key keeps tests fast; production keys are 3072-bit.
        RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap()
    }

    fn span(affected: bool, start: Option<&str>, end: Option<&str>, end_inclusive: bool) -> Span {
        Span {
            affected,
            start: start.map(Into::into),
            start_inclusive: true,
            end: end.map(Into::into),
            end_inclusive,
        }
    }

    #[test]
    fn versions_compare_numerically_and_by_shape() {
        use Ordering::*;
        for (left, right, expected) in [
            ("1.10", "1.9", Greater),
            ("1.0", "1.0.0", Equal),
            ("140.0.7339.185", "140.0.7339.80", Greater),
            ("26100.6899", "26100.10000", Less),
            ("26100", "26100.1", Less),
            ("2.0-beta", "2.0", Less),
            ("115.23.1", "115.*", Less),
            ("116.0", "115.*", Greater),
            ("007", "7", Equal),
            ("24.08", "24.8", Equal),
            ("99999999999999999999999", "9", Greater),
        ] {
            assert_eq!(compare_versions(left, right), expected, "{left} vs {right}");
        }
    }

    #[test]
    fn spans_follow_cve_version_semantics() {
        // Google: "affected, version X, lessThan X" means below X.
        let chrome = Affected {
            cve: "CVE-1".into(),
            product: "google-chrome".into(),
            spans: vec![span(true, None, Some("140.0.7339.185"), false)],
            default_affected: false,
            fixed: None,
            fix_url: None,
            scheme: VersionScheme::Generic,
        };
        assert_eq!(chrome.affects("140.0.7339.80"), Some(true));
        assert_eq!(chrome.affects("140.0.7339.185"), Some(false));
        assert_eq!(chrome.affects(""), None);
        assert_eq!(chrome.affects("unknown"), None);

        // Mozilla: fixed branches listed as unaffected, everything else affected.
        let firefox = Affected {
            cve: "CVE-2".into(),
            product: "mozilla-firefox".into(),
            spans: vec![
                span(false, Some("115.23.1"), Some("115.*"), true),
                span(false, Some("128.10.1"), Some("128.*"), true),
                span(false, Some("138.0.4"), None, false),
            ],
            default_affected: true,
            fixed: None,
            fix_url: None,
            scheme: VersionScheme::Generic,
        };
        assert_eq!(firefox.affects("137.0"), Some(true));
        assert_eq!(firefox.affects("138.0.4"), Some(false));
        assert_eq!(firefox.affects("128.9.0"), Some(true));
        assert_eq!(firefox.affects("128.10.1"), Some(false));
        assert_eq!(firefox.affects("116.0"), Some(true));
    }

    #[test]
    fn java_versions_are_read_in_oracle_notation() {
        let rule = VersionRule::JavaUpdate;
        assert_eq!(
            rule.apply("Java 8 Update 441 (64-bit)", "8.0.4410.7"),
            "8u441"
        );
        assert_eq!(
            rule.apply(
                "Java SE Development Kit 8 Update 451 (64-bit)",
                "8.0.4510.9"
            ),
            "8u451"
        );
        assert_eq!(
            rule.apply("Java(TM) SE Development Kit 21.0.6 (64-bit)", "21.0.6.0"),
            "21.0.6.0"
        );
    }

    #[test]
    fn dpkg_versions_follow_debian_policy() {
        use Ordering::*;
        for (left, right, expected) in [
            ("1.0", "1.0", Equal),
            ("1.0-1", "1.0-2", Less),
            ("1:1.0", "2.0", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0~~", "1.0~", Less),
            ("1.0+b1", "1.0", Greater),
            ("3.0.15-1~deb12u1", "3.0.15-1", Less),
            ("2.36-9+deb12u4", "2.36-9+deb12u10", Less),
            ("1.2a", "1.2+", Less),
            ("1.10", "1.9", Greater),
            ("0:1.0", "1.0", Equal),
            ("1.0-1ubuntu0.24.04.1", "1.0-1", Greater),
            ("7.88.1-10+deb12u8", "7.88.1-10+deb12u12", Less),
        ] {
            assert_eq!(compare_dpkg(left, right), expected, "{left} vs {right}");
            assert_eq!(
                compare_dpkg(right, left),
                expected.reverse(),
                "{right} vs {left}"
            );
        }
    }

    #[test]
    fn rpm_versions_follow_rpmvercmp() {
        use Ordering::*;
        // Cases from rpm's own test suite (rpmvercmp.at).
        for (left, right, expected) in [
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0.1", "2.0", Greater),
            ("5.5p1", "5.5p2", Less),
            ("5.5p10", "5.5p1", Greater),
            ("10xyz", "10.1xyz", Less),
            ("xyz10", "xyz10.1", Less),
            ("1.0aa", "1.0a", Greater),
            ("2a", "2.0", Less),
            ("1.0", "1.fc4", Greater),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0^", "1.0", Greater),
            ("1.0^git1", "1.0^git2", Less),
            ("1.0^git1", "1.01", Less),
            ("1.0^git1~pre", "1.0^git1", Less),
            ("1:3.0.7-27.el9", "3.0.7-27.el9", Greater),
            ("0:3.0.7-27.el9", "3.0.7-28.el9_4", Less),
            ("0:3.0.7-27.el9", "3.0.7-27.el9", Equal),
            ("3.0.7", "3.0.7-27.el9", Equal),
        ] {
            assert_eq!(compare_rpm(left, right), expected, "{left} vs {right}");
            assert_eq!(
                compare_rpm(right, left),
                expected.reverse(),
                "{right} vs {left}"
            );
        }
    }

    #[test]
    fn linux_entries_compare_with_their_scheme() {
        let openssl = Affected {
            cve: "CVE-2024-1".into(),
            product: "deb:debian:12:openssl".into(),
            spans: vec![span(true, Some("0"), Some("3.0.15-1~deb12u1"), false)],
            default_affected: false,
            fixed: Some("3.0.15-1~deb12u1".into()),
            fix_url: None,
            scheme: VersionScheme::Dpkg,
        };
        assert_eq!(openssl.affects("3.0.14-1~deb12u2"), Some(true));
        assert_eq!(openssl.affects("3.0.15-1~deb12u1"), Some(false));
        // Generic ordering would call "~deb12u1" a pre-release of 3.0.15-1.
        assert_eq!(openssl.affects("3.0.15-1"), Some(false));
    }

    #[test]
    fn software_keys_ignore_versions_architectures_and_locales() {
        for (name, key) in [
            ("Mozilla Firefox (x64 ja)", "mozilla firefox"),
            ("Mozilla Firefox 120.0", "mozilla firefox"),
            ("Mozilla Firefox ESR (x64 en-US)", "mozilla firefox esr"),
            ("7-Zip 24.08 (x64)", "7 zip"),
            ("7-Zip", "7 zip"),
            ("PuTTY release 0.74 (64-bit)", "putty"),
            ("Notepad++ (64-bit x64)", "notepad++"),
            (
                "Adobe Acrobat Reader DC 2015.006.30033",
                "adobe acrobat reader dc",
            ),
            ("Wireshark 4.2.5 x64", "wireshark"),
            (
                "Microsoft® Office Professional Plus 2019",
                "microsoft office professional plus 2019",
            ),
            ("VLC media player", "vlc media player"),
            ("Python 3.12.4 (64-bit)", "python"),
            ("Git", "git"),
            ("Slack (Machine - MSI)", "slack"),
            (
                "Microsoft 365 Apps for enterprise - ja-jp",
                "microsoft 365 apps for enterprise ja jp",
            ),
            ("Tool [Beta (x64)] Plus", "tool plus"),
            ("PowerShell 7-x64", "powershell 7"),
        ] {
            assert_eq!(software_key(name), key, "{name}");
            // Keys are stable: the index normalizes stored keys again.
            assert_eq!(software_key(key), key, "{key}");
        }
    }

    #[test]
    fn publishers_match_cpe_vendors() {
        assert_eq!(publisher_key("Google LLC"), "google");
        assert_eq!(publisher_key("Mozilla Corporation"), "mozilla");
        assert!(publisher_matches("google", "Google LLC"));
        assert!(publisher_matches("igor pavlov", "Igor Pavlov"));
        assert!(publisher_matches(
            "wireshark",
            "The Wireshark developer community"
        ));
        assert!(publisher_matches("videolan", "Video LAN"));
        assert!(publisher_matches(
            "apache",
            "The Apache Software Foundation"
        ));
        assert!(!publisher_matches("google", "Mozilla"));
        assert!(!publisher_matches("google", ""));
        assert!(!publisher_matches("micro", "Microsoft Corporation"));
    }

    #[test]
    fn linux_releases_are_matched_by_major_release() {
        assert_eq!(
            linux_release("ubuntu:24.04"),
            Some(("ubuntu", "24.04".into()))
        );
        assert_eq!(linux_release("debian:12"), Some(("debian", "12".into())));
        assert_eq!(
            linux_release("almalinux:9.4"),
            Some(("almalinux", "9".into()))
        );
        assert_eq!(linux_release("rocky:\"8.10\""), Some(("rocky", "8".into())));
        assert_eq!(linux_release("rhel:10.0"), Some(("rhel", "10".into())));
        assert_eq!(linux_release("fedora:40"), None);
        assert_eq!(linux_release("26100.6899"), None);
    }

    fn inferred(key: &str, names: &[&str], publishers: &[&str]) -> Product {
        Product {
            key: key.into(),
            name: key.into(),
            matchers: vec![Matcher::Alias {
                platforms: vec![],
                names: names.iter().map(|name| software_key(name)).collect(),
                publishers: publishers.iter().map(|p| publisher_key(p)).collect(),
            }],
            confidence: Confidence::Inferred,
        }
    }

    #[test]
    fn aliases_are_looked_up_by_software_key() {
        let mut catalog = products();
        catalog.push(inferred(
            "cpe:wireshark:wireshark",
            &["Wireshark"],
            &["wireshark"],
        ));
        catalog.push(inferred(
            "cpe:videolan:vlc",
            &["VLC media player"],
            &["videolan"],
        ));
        let index = ProductIndex::new(catalog);
        let windows = Endpoint {
            os_version: "Windows 11 Pro 24H2",
            os_build: "26100.6899",
            software: vec![
                software(
                    "Wireshark 4.2.5 x64",
                    "4.2.5",
                    "The Wireshark developer community",
                    "registry",
                    None,
                ),
                // Same name, unrelated publisher: not this product on Windows.
                software("VLC media player", "3.0.20", "Somebody", "registry", None),
            ],
        };
        let found = index.observe(&windows);
        let keys: Vec<(&str, Confidence)> = found
            .iter()
            .map(|o| (o.product.as_str(), o.confidence))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("windows-client-26100", Confidence::Curated),
                ("cpe:wireshark:wireshark", Confidence::Inferred),
            ]
        );
        assert_eq!(found[1].version, "4.2.5");

        // A project published under a person's name carries the vendor's name.
        let mut named = products();
        named.push(inferred("cpe:winscp:winscp", &["WinSCP"], &["winscp"]));
        named.push(inferred("cpe:acme:calculator", &["Calculator"], &["acme"]));
        named.push(inferred(
            "cpe:google:chrome",
            &["Google Chrome"],
            &["google"],
        ));
        let named = ProductIndex::new(named);
        let found = named.observe(&Endpoint {
            os_version: "Windows 11 Pro",
            os_build: "",
            software: vec![
                software("WinSCP 6.3.5", "6.3.5", "Martin Prikryl", "registry", None),
                software("Google Chrome", "141.0", "Google LLC", "registry", None),
            ],
        });
        let keys: Vec<&str> = found.iter().map(|o| o.product.as_str()).collect();
        // Chrome is the curated product only, not inferred again.
        assert_eq!(keys, vec!["google-chrome", "cpe:winscp:winscp"]);
        let mac = |bundle: &'static str| Endpoint {
            os_version: "macOS 15.5",
            os_build: "",
            software: vec![software(
                "Calculator",
                "11.0",
                "",
                "app_bundle",
                Some(bundle),
            )],
        };
        assert!(named
            .observe(&mac("com.apple.calculator"))
            .iter()
            .all(|o| o.product != "cpe:acme:calculator"));
        assert!(named
            .observe(&mac("com.acme.calculator"))
            .iter()
            .any(|o| o.product == "cpe:acme:calculator"));

        // macOS bundles have no publisher: the vendor must be in the bundle
        // identifier or the name.
        let mac = Endpoint {
            os_version: "macOS 15.5 Sequoia",
            os_build: "24F74",
            software: vec![software(
                "VLC media player",
                "3.0.20",
                "",
                "app_bundle",
                Some("org.videolan.vlc"),
            )],
        };
        assert!(index
            .observe(&mac)
            .iter()
            .any(|o| o.product == "cpe:videolan:vlc"));
    }

    #[test]
    fn linux_packages_are_matched_per_release() {
        let package = |key: &str, matcher: Matcher| Product {
            key: key.into(),
            name: key.into(),
            matchers: vec![matcher],
            confidence: Confidence::Curated,
        };
        let index = ProductIndex::new(vec![
            package(
                "deb:debian:12:openssl",
                Matcher::DebPackage {
                    distro: "debian".into(),
                    release: "12".into(),
                    source: "openssl".into(),
                },
            ),
            package(
                "rpm:almalinux:9:openssl",
                Matcher::RpmPackage {
                    distro: "almalinux".into(),
                    release: "9".into(),
                    name: "openssl".into(),
                },
            ),
            inferred("cpe:openssl:openssl", &["openssl"], &[]),
        ]);
        let debian = Endpoint {
            os_version: "Debian GNU/Linux 12 (bookworm)",
            os_build: "debian:12",
            software: vec![
                software("libssl3", "3.0.14-1~deb12u2", "", "dpkg", Some("openssl")),
                software("openssl", "3.0.14-1~deb12u2", "", "dpkg", Some("openssl")),
            ],
        };
        let found = index.observe(&debian);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().all(|o| o.product == "deb:debian:12:openssl"));

        let alma = Endpoint {
            os_version: "AlmaLinux 9.4 (Seafoam Ocelot)",
            os_build: "almalinux:9.4",
            software: vec![software(
                "openssl",
                "1:3.0.7-27.el9",
                "AlmaLinux",
                "rpm",
                None,
            )],
        };
        let found = index.observe(&alma);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].product, "rpm:almalinux:9:openssl");

        // Another release, or a distribution without data: nothing.
        let other = Endpoint {
            os_version: "Debian GNU/Linux 11",
            os_build: "debian:11",
            software: debian.software.clone(),
        };
        assert!(index.observe(&other).is_empty());
    }

    #[test]
    fn optional_fields_are_omitted_at_their_defaults() {
        // Defaults are left out, keeping the many curated products and
        // generic entries small.
        let product = &products()[0];
        let json = serde_json::to_string(product).unwrap();
        assert!(!json.contains("confidence"));
        let entry = Affected {
            cve: "CVE-1".into(),
            product: "p".into(),
            spans: vec![],
            default_affected: false,
            fixed: None,
            fix_url: None,
            scheme: VersionScheme::Generic,
        };
        assert!(!serde_json::to_string(&entry).unwrap().contains("scheme"));
        let inferred = serde_json::to_string(&inferred("cpe:a:b", &["B"], &["a"])).unwrap();
        assert!(inferred.contains(r#""confidence":"inferred""#));
        assert!(inferred.contains(r#""type":"alias""#));
    }

    #[test]
    fn globs_match_case_insensitively() {
        assert!(glob_matches("Mozilla Firefox*", "Mozilla Firefox (x64 ja)"));
        assert!(glob_matches("7-zip*", "7-Zip 24.08 (x64)"));
        assert!(glob_matches("*reader*", "Adobe Acrobat Reader DC"));
        assert!(!glob_matches("Mozilla Firefox*", "Mozilla Thunderbird"));
        assert!(glob_matches("Google Chrome", " google chrome "));
        assert!(!glob_matches("Google Chrome", "Google Chrome Beta"));
    }

    fn products() -> Vec<Product> {
        vec![
            Product {
                key: "google-chrome".into(),
                name: "Google Chrome".into(),
                matchers: vec![
                    Matcher::Software {
                        platform: Platform::Windows,
                        sources: vec!["registry".into()],
                        names: vec!["Google Chrome".into()],
                        exclude_names: vec![],
                        publishers: vec!["Google".into()],
                        package_names: vec![],
                        version: None,
                    },
                    Matcher::Software {
                        platform: Platform::Macos,
                        sources: vec![],
                        names: vec![],
                        exclude_names: vec![],
                        publishers: vec![],
                        package_names: vec!["com.google.Chrome".into()],
                        version: None,
                    },
                ],
                confidence: Confidence::Curated,
            },
            Product {
                key: "windows-client-26100".into(),
                name: "Windows 11 Version 24H2".into(),
                matchers: vec![Matcher::Windows {
                    server: false,
                    build: 26100,
                }],
                confidence: Confidence::Curated,
            },
            Product {
                key: "windows-server-26100".into(),
                name: "Windows Server 2025".into(),
                matchers: vec![Matcher::Windows {
                    server: true,
                    build: 26100,
                }],
                confidence: Confidence::Curated,
            },
            Product {
                key: "macos".into(),
                name: "macOS".into(),
                matchers: vec![Matcher::Macos],
                confidence: Confidence::Curated,
            },
        ]
    }

    fn software<'a>(
        name: &'a str,
        version: &'a str,
        publisher: &'a str,
        source: &'a str,
        package_name: Option<&'a str>,
    ) -> SoftwareRef<'a> {
        SoftwareRef {
            name,
            version,
            publisher,
            source,
            package_name,
        }
    }

    #[test]
    fn endpoints_are_observed_per_platform() {
        let windows = Endpoint {
            os_version: "Windows 11 Pro 24H2",
            os_build: "26100.6899",
            software: vec![
                software(
                    "Google Chrome",
                    "141.0.7390.108",
                    "Google LLC",
                    "registry",
                    None,
                ),
                software("Google Chrome", "", "Google LLC", "registry", None),
                software(
                    "Chrome Remote Desktop Host",
                    "1.0",
                    "Google LLC",
                    "registry",
                    None,
                ),
            ],
        };
        let found = observe(&products(), &windows);
        assert_eq!(
            found,
            vec![
                Observation {
                    product: "google-chrome".into(),
                    name: "Google Chrome".into(),
                    version: "141.0.7390.108".into(),
                    confidence: Confidence::Curated,
                },
                Observation {
                    product: "windows-client-26100".into(),
                    name: "Windows 11 Pro 24H2".into(),
                    version: "26100.6899".into(),
                    confidence: Confidence::Curated,
                },
            ]
        );

        let server = Endpoint {
            os_version: "Windows Server 2025 Standard 24H2",
            os_build: "26100.6899",
            software: vec![],
        };
        assert_eq!(
            observe(&products(), &server)[0].product,
            "windows-server-26100"
        );

        // A build without the update revision cannot be judged.
        let unknown = Endpoint {
            os_version: "Windows 11 Pro",
            os_build: "26100",
            software: vec![],
        };
        assert!(observe(&products(), &unknown).is_empty());

        let mac = Endpoint {
            os_version: "macOS 15.5 Sequoia",
            os_build: "24F74",
            software: vec![software(
                "Google Chrome",
                "141.0",
                "",
                "app_bundle",
                Some("com.google.Chrome"),
            )],
        };
        let found = observe(&products(), &mac);
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].version, "15.5");
    }

    fn cve(scores: Vec<Score>) -> CveRecord {
        CveRecord {
            id: "CVE-2025-0001".into(),
            published: None,
            modified: None,
            title: None,
            description: String::new(),
            scores,
            epss: None,
            kev: None,
            ssvc: None,
            references: vec![],
        }
    }

    fn score(origin: ScoreOrigin, version: &str, base_score: f32) -> Score {
        Score {
            origin,
            provider: "x".into(),
            version: version.into(),
            base_score,
            vector: None,
        }
    }

    #[test]
    fn primary_score_prefers_the_cna_then_nvd_then_adps() {
        let scores = vec![
            score(ScoreOrigin::Adp, "4.0", 9.0),
            score(ScoreOrigin::Cna, "3.1", 7.5),
            score(ScoreOrigin::Cna, "2.0", 5.0),
        ];
        assert_eq!(primary_score(&scores).unwrap().base_score, 7.5);
        // Without the CNA: NVD before ADPs, whatever their versions.
        let scores = vec![
            score(ScoreOrigin::Adp, "4.0", 9.0),
            score(ScoreOrigin::Nvd, "3.1", 8.1),
            score(ScoreOrigin::Nvd, "2.0", 6.8),
        ];
        assert_eq!(primary_score(&scores).unwrap().base_score, 8.1);
        assert_eq!(
            primary_score(&[score(ScoreOrigin::Adp, "3.1", 5.3)])
                .unwrap()
                .base_score,
            5.3
        );
        assert_eq!(
            severity(&score(ScoreOrigin::Cna, "3.1", 9.8)),
            Severity::Critical
        );
        assert_eq!(
            severity(&score(ScoreOrigin::Cna, "2.0", 9.8)),
            Severity::High
        );
        assert_eq!(
            severity(&score(ScoreOrigin::Cna, "4.0", 0.0)),
            Severity::None
        );
    }

    #[test]
    fn priority_puts_exploited_vulnerabilities_first() {
        let mut record = cve(vec![score(ScoreOrigin::Cna, "3.1", 5.0)]);
        assert_eq!(priority(&record), 4);
        record.scores = vec![score(ScoreOrigin::Cna, "3.1", 8.8)];
        assert_eq!(priority(&record), 3);
        record.epss = Some(0.2);
        assert_eq!(priority(&record), 2);
        record.kev = Some(Kev {
            added: NaiveDate::from_ymd_opt(2025, 1, 1).unwrap(),
            due: None,
            ransomware: false,
        });
        assert_eq!(priority(&record), 1);

        let mut unscored = cve(vec![]);
        unscored.ssvc = Some(Ssvc {
            exploitation: "poc".into(),
            automatable: None,
            technical_impact: None,
        });
        assert_eq!(priority(&unscored), 2);
        unscored.ssvc.as_mut().unwrap().exploitation = "active".into();
        assert_eq!(priority(&unscored), 1);
    }

    #[test]
    fn epss_is_quantized_to_one_significant_digit() {
        assert_eq!(quantize_epss(0.0437), Some(0.04));
        assert_eq!(quantize_epss(0.37), Some(0.4));
        assert_eq!(quantize_epss(0.96), Some(1.0));
        assert_eq!(quantize_epss(0.000123), Some(0.0001));
        assert_eq!(quantize_epss(0.0), None);
    }

    fn put_cve(id: &str) -> Op {
        let mut record = cve(vec![]);
        record.id = id.into();
        Op::Put {
            record: Record::Cve(record),
        }
    }

    #[test]
    fn signed_files_round_trip_and_reject_tampering() {
        let private = key();
        let public = RsaPublicKey::from(&private);
        let ops = vec![
            put_cve("CVE-2025-0001"),
            Op::Delete {
                kind: RecordKind::Affected,
                id: "CVE-2024-1|macos".into(),
            },
        ];
        let file = build_data(
            &private,
            Kind::Delta,
            "linux-debian",
            "feed",
            Some(1),
            2,
            Utc::now(),
            &ops,
        );
        let (header, body) = open_data(&public, &file).unwrap();
        assert_eq!((header.base_version, header.version), (Some(1), 2));
        assert_eq!(header.channel, "linux-debian");
        let decoded: Vec<Op> = decode_ops(body).collect::<Result<_, _>>().unwrap();
        assert_eq!(decoded, ops);

        let mut tampered = file.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_data(&public, &tampered).is_err());

        let other = RsaPublicKey::from(&key());
        assert!(open_data(&other, &file).is_err());
        assert!(open_data(&public, b"garbage").is_err());
    }

    fn file(bytes: u64) -> FileRef {
        FileRef {
            path: "x".into(),
            sha256: String::new(),
            bytes,
        }
    }

    fn manifest(deltas: &[(u64, u64, u64)], snapshot_bytes: u64) -> Manifest {
        Manifest {
            format: FORMAT,
            kind: Kind::Manifest,
            channel: MAIN_CHANNEL.into(),
            feed_id: "feed".into(),
            version: 5,
            generated_at: Utc::now(),
            snapshot: file(snapshot_bytes),
            deltas: deltas
                .iter()
                .map(|(base, version, bytes)| DeltaRef {
                    base_version: *base,
                    version: *version,
                    file: file(*bytes),
                })
                .collect(),
        }
    }

    #[test]
    fn update_plan_takes_the_cheapest_complete_path() {
        let position = |version| Position {
            feed_id: "feed".into(),
            version,
        };
        let manifest = manifest(&[(3, 4, 10), (4, 5, 10), (2, 3, 10)], 1000);
        assert_eq!(plan(&manifest, Some(&position(5))), Plan::UpToDate);
        match plan(&manifest, Some(&position(2))) {
            Plan::Deltas(chain) => assert_eq!(
                chain.iter().map(|d| d.version).collect::<Vec<_>>(),
                vec![3, 4, 5]
            ),
            other => panic!("{other:?}"),
        }
        // Too old for the retained deltas, or another lineage: full snapshot.
        assert!(matches!(
            plan(&manifest, Some(&position(1))),
            Plan::Snapshot(_)
        ));
        assert!(matches!(plan(&manifest, None), Plan::Snapshot(_)));
        let other = Position {
            feed_id: "other".into(),
            version: 4,
        };
        assert!(matches!(plan(&manifest, Some(&other)), Plan::Snapshot(_)));
        // Deltas larger than the snapshot are not worth downloading.
        let heavy = self::manifest(&[(4, 5, 2000)], 1000);
        assert!(matches!(
            plan(&heavy, Some(&position(4))),
            Plan::Snapshot(_)
        ));
    }
}
