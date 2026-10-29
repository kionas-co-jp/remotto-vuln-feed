# remotto-vuln-feed

Builds and publishes the signed vulnerability data used by [Remotto](https://kionas.co.jp/en/remotto/). A GitHub Actions workflow builds it regularly and, when anything changed, publishes a new version as a GitHub Release.

Remotto で利用する、署名付きの脆弱性データを作成・公開するツールです。GitHub Actions で定期的に作成し、変更があれば GitHub Releases に新しいバージョンを公開します。

## What is published

The data is split into channels, each a lineage of its own, so that servers download only the data for the systems they manage.

| Channel | Contents |
| --- | --- |
| `main` | Windows, macOS and applications |
| `linux-debian` | Debian 11, 12 and 13 packages |
| `linux-ubuntu` | Ubuntu 20.04, 22.04 and 24.04 LTS packages |
| `linux-rhel` | RHEL, AlmaLinux and Rocky Linux 8, 9 and 10 packages |

Every release holds the manifest of every channel; snapshots and deltas are attached to the release in which they were built.

| File | Contents |
| --- | --- |
| `manifest-v2-<channel>.rvf` | The channel's latest version and the files that reach it, with their SHA-256 |
| `snapshot-v2-<channel>.rvf` | All records of the channel, for first and offline imports |
| `delta-v2-<channel>-<from>-<to>.rvf` | Changes from one version to the next |
| `state.tar.gz` | What the next build continues from (latest release only) |

Remotto Server checks `https://github.com/kionas-co-jp/remotto-vuln-feed/releases/latest/download/manifest-v2-main.rvf`, plus the Linux manifests next to it for the distributions it manages, and downloads only the deltas it lacks. For an offline server, download the `snapshot-v2-*.rvf` files of the latest release and import them in the Remotto console.

## How the data is built

Affected versions come from machine-readable sources and are matched to installed programs through the product catalog and the NVD CPE dictionary.

- **Sources:** CVE records of the CVE Program ([cvelistV5](https://github.com/CVEProject/cvelistV5)), CISA KEV and Vulnrichment, FIRST EPSS, NVD CVE feeds and the CPE dictionary, MSRC and the Microsoft 365 Apps security release notes, and Debian, Ubuntu, Red Hat, AlmaLinux and Rocky Linux advisories through [OSV.dev](https://osv.dev).
- **Curated products** ([catalog.toml](catalog.toml)) are reviewed against real CVE records and device reports: Windows, macOS, Microsoft 365 Apps and Office, Oracle Java SE, browsers and common applications.
- **Inferred products** cover every other CPE product with known affected versions. They are matched by program name and publisher from CPE data, and Remotto Server shows their findings as inferred.
- **Linux packages** are compared with each distribution's fixed versions under dpkg or rpm ordering.

## Verifying files

Every file carries an RSA-PSS signature over its header, and the header carries the SHA-256 of the body. Remotto Server accepts only files signed by the key in [`vuln_feed_public_key.pem`](vuln_feed_public_key.pem). The signature protects the files from tampering; it does not hide them: the body is gzip-compressed JSON that anyone can read. To inspect a file:

```bash
cargo run --release -- verify manifest-v2-main.rvf --public-key vuln_feed_public_key.pem
```

## Data sources and disclaimer

Data sourced from the CVE Program, NVD, CISA KEV and Vulnrichment, FIRST EPSS, the Microsoft Security Response Center, Microsoft Learn and OSV.dev (Debian, Ubuntu, Red Hat, AlmaLinux and Rocky Linux). The terms and credits of each source are in [NOTICE.md](NOTICE.md).

The data is provided as is, without warranty of accuracy or completeness. Vulnerability databases contain gaps and errors, and scores such as EPSS are estimates that cannot predict future attacks. The authors are not liable for any damages arising from the use of the data or of its results.

## License

The source code is under the [MIT License](LICENSE). The published data is subject to the terms of its sources, listed in [NOTICE.md](NOTICE.md).
