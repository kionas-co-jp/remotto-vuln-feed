Signed vulnerability data used by Remotto. Each release holds the manifest of every channel: `manifest-v2-main.rvf` (Windows, macOS and applications), `manifest-v2-linux-debian.rvf`, `manifest-v2-linux-ubuntu.rvf` and `manifest-v2-linux-rhel.rvf` (RHEL, AlmaLinux and Rocky Linux). Servers download a manifest from the latest release and only the delta files it lists; the snapshot files hold the complete data for first or offline imports. Every file is verified against the Remotto feed key before it is applied.

## Data sources and notices

Data sourced from the CVE Program, NVD, CISA KEV and Vulnrichment, FIRST EPSS, the Microsoft Security Response Center, Microsoft Learn and OSV.dev (Debian, Ubuntu, Red Hat, AlmaLinux and Rocky Linux).

- **CVE records** — CVE Program ([cvelistV5](https://github.com/CVEProject/cvelistV5)). Copyright © 1999–2026, The MITRE Corporation. CVE and the CVE logo are registered trademarks of The MITRE Corporation. Used under the CVE Terms of Use reproduced below.
- **Known Exploited Vulnerabilities** and **Vulnrichment** — Cybersecurity and Infrastructure Security Agency (CISA), CC0 1.0. Use does not imply endorsement by CISA or DHS.
- **EPSS** — Forum of Incident Response and Security Teams (FIRST). See EPSS at https://www.first.org/epss.
- **NVD** — National Vulnerability Database, National Institute of Standards and Technology (NIST): CVE configurations, CVSS scores and the CPE dictionary. This product uses data from the NVD API but is not endorsed or certified by the NVD.
- **Microsoft Security Response Center** — security update data from the MSRC CVRF API, and fixed builds from the [Microsoft 365 Apps security release notes](https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates), © Microsoft Corporation.
- **Linux distributions**, through [OSV.dev](https://osv.dev):
  - Debian Security Tracker data (Debian channel).
  - Ubuntu Security Notices and CVE tracker, © Canonical Ltd., licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). The Ubuntu channel data is a derivative and is distributed under the same license.
  - Red Hat Security Data, © Red Hat, Inc., licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
  - AlmaLinux OSV database (MIT License) and Rocky Linux errata (BSD License).

Use of this data does not imply endorsement by MITRE, CISA, FIRST, NIST, Microsoft, Debian, Canonical, Red Hat, AlmaLinux OS Foundation or the Rocky Enterprise Software Foundation.

## Disclaimer

The data is provided "as is", without warranty of any kind, express or implied, including warranties of accuracy, completeness, timeliness, merchantability and fitness for a particular purpose. Vulnerability databases are incomplete and contain errors; scores such as CVSS and EPSS are estimates, and EPSS is a probability that cannot predict whether or when a vulnerability will be exploited. Products marked as inferred are matched by name from CPE data and may be wrong. Findings can therefore be missing or mistaken, and do not replace the security advisories of each vendor.

Kionas Inc. and the contributors to this repository are not liable for any damages arising from the use of this data or from decisions made on its results.

### CVE Terms of Use

CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive,
no-charge, royalty-free, irrevocable copyright license to reproduce, prepare
derivative works of, publicly display, publicly perform, sublicense, and
distribute Common Vulnerabilities and Exposures (CVE®). Any copy you make for
such purposes is authorized provided that you reproduce MITRE's copyright
designation and this license in any such copy.

DISCLAIMERS

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN PROVIDED BY MITRE ARE
PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE
REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF
TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE
INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF
MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
