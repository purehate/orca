# ORCA — Odoo Recon & Configuration Analyzer

**ORCA** is an unauthenticated, frontend-focused dynamic security scanner and network discovery tool for Odoo ERP instances. Designed for bug bounty hunters, penetration testers, and security teams who need to find shadow/dev deployments, exposed attack surface, and known vulnerabilities — all without credentials.

> ⚠️ **Only test on systems you own or have explicit written permission to test.**

---

## Features

| Feature | Description |
|---------|-------------|
| **Unauthenticated-first** | Every check works without login credentials |
| **Mass Network Discovery** | Scan `/16` networks, CIDR ranges, or host lists for Odoo instances |
| **Shadow/Dev Hunt** | Flag unauthorized development boxes and staging deployments |
| **Version Fingerprinting** | Detects Odoo version via HTML signatures, XML-RPC, JSON-RPC |
| **Module Enumeration** | Discovers installed frontend modules via path probing + asset parsing |
| **CVE Correlation** | Maps detected version + modules to known CVEs via NVD API |
| **Attack Surface Discovery** | QWeb assets, custom controllers, GraphQL, RPC endpoints |
| **Vulnerability Detection** | XSS, IDOR, open redirects, sensitive file exposure, debug mode, LFI, SSRF |
| **Fuzzing Engine** | Parameter discovery and payload mutation for reflected injection |
| **Multiple Outputs** | Rich console tables, JSON, CSV, and self-contained HTML reports |
| **Stealth Controls** | Rate limiting, jitter, proxy support, SSL bypass |

---

## Installation

```bash
git clone https://github.com/purehate/orca.git
cd orca
pip install -e .
```

Requires **Python ≥3.9**.

---

## Quick Start

### Full Security Scan

```bash
orca -u https://target.odoo.com
```

### Network Discovery — Find Odoo Instances

```bash
# Scan a /24 network
orca --discover -t 10.0.0.0/24

# Scan a list of IPs from file
orca --discover --target-file hosts.txt

# Scan custom ports
orca --discover -t 192.168.1.0/24 --ports 80,443,8069,8080
```

### Shadow/Dev Hunt — Find Unauthorized Instances

```bash
# Discover + flag shadow dev boxes
orca --discover -t 10.0.0.0/16 --shadow-hunt --threads 200 --timeout 3

# Save results to JSON for SIEM
orca --discover -t 10.0.0.0/16 --shadow-hunt -o findings.json --format json
```

### Targeted Security Checks

```bash
# Run specific checks only
orca -u https://target.odoo.com --checks xss,idor,misconfig

# Minimum severity filter
orca -u https://target.odoo.com --min-severity medium

# Output formats
orca -u https://target.odoo.com --format json -o report.json
orca -u https://target.odoo.com --format html -o report.html
orca -u https://target.odoo.com --format csv -o report.csv

# Stealth mode
orca -u https://target.odoo.com --rate 2 --jitter 30 --proxy http://127.0.0.1:8080
```

---

## Checks

| Check | Description |
|-------|-------------|
| `recon` | Version, database listing, WAF detection, module enumeration, signup exposure |
| `endpoints` | QWeb assets, manifests, GraphQL, custom routes, CORS preflight |
| `misconfig` | Debug mode, database manager, missing security headers, CORS misconfig |
| `sensitive_files` | `.git`, `.env`, backups, configs, swagger, sitemaps |
| `xss` | Reflected XSS on URL parameters, search fields, error pages |
| `idor` | Unauthenticated `/web/content`, `/web/image`, `/web/pdf`, RPC read |
| `auth_issues` | Session cookie flags, open redirects, password reset behavior |
| `disclosure` | Error page analysis, `/website/info`, `base_import_module` leak |
| `rpc_surface` | XML-RPC/JSON-RPC exposure, unauthenticated `call_kw` access |
| `cve` | Correlate detected version + modules with NVD CVE database |
| `fuzzer` | Parameter discovery and payload mutation on HTML forms |
| `reports` | PDF report disclosure, CSV export, FEC export, invoice XSS |
| `lfi` | Local File Inclusion via static file path abuse |
| `ssrf` | SSRF via website URL fetch features and webhooks |
| `exposure` | Dangerous modules: dbfilter, oauth, anonymization, payment tokens |
| `source_leak` | Source code leak via asset path abuse |

---

## Discovery Engine

ORCA's discovery mode uses **10+ unique Odoo markers** to fingerprint instances across large networks:

- `var odoo = { ... }` JavaScript object
- `csrf_token` in login forms
- `data-website-id` HTML attributes
- `/web/static/` and `/web/assets/` paths
- `Login | <DatabaseName>` title pattern
- `Werkzeug` Server header (dev instances)
- `openerp.` legacy references
- Odoo-specific CSS classes (`o_*`)

XML-RPC version probes confirm ambiguous hosts.

### Shadow Hunt Indicators

| Indicator | Dev Box Signal |
|-----------|---------------|
| `werkzeug` | Running dev server (no reverse proxy) |
| `debug_mode` | Debug UI enabled via `?debug=1` |
| `db_manager` | Database manager exposed |
| `db_listing` | Databases listable with dev/test/demo names |
| `self_signed_ssl` | Invalid/self-signed certificate |
| `dev_port` | Running on port 8069 or 8080 |
| `open_registration` | Public signup enabled |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings |
| 1 | Medium findings |
| 2 | High findings |
| 3 | Critical findings |

---

## Example Output

```
╭────────────── Scan Summary ───────────────╮
│ Target: https://synergy.trustedsec.com    │
│ Version: 18                               │
│ Databases: trustedsec-production-12404823 │
│ Modules: 6 detected                       │
│ WAF: Cloudflare                           │
╰───────────────────────────────────────────╯

HIGH (2)
  idor: Unauthenticated attachment access (IDOR)
  cve: Known CVE: CVE-2021-23178

MEDIUM (6)
  recon: Database listing enabled
  disclosure: Detailed error pages exposed
  idor: Unauthenticated image access (IDOR)
  fuzzer: Error disclosure via form fuzzing on /event
  cve: Known CVE: CVE-2021-44775
  cve: Known CVE: CVE-2018-15641

LOW (3)
  misconfig: Missing security headers
  disclosure: /website/info page exposed
  rpc_surface: JSON-RPC /jsonrpc exposed
```

---

## Architecture

```
orca/
├── cli.py              # Entry point (scan / discover / shadow-hunt)
├── core.py             # Threaded scanner engine
├── discover.py         # Mass network discovery
├── shadow_hunt.py      # Dev/shadow instance detection
├── target.py           # HTTP session + Odoo helpers
├── findings.py         # Severity / Finding / ScanResult dataclasses
├── checks/             # 16 security check modules
│   ├── recon.py
│   ├── endpoints.py
│   ├── misconfig.py
│   ├── sensitive_files.py
│   ├── xss.py
│   ├── idor.py
│   ├── auth_issues.py
│   ├── disclosure.py
│   ├── rpc_surface.py
│   ├── cve.py
│   ├── fuzzer.py
│   ├── reports.py
│   ├── lfi.py
│   ├── ssrf.py
│   ├── exposure.py
│   └── source_leak.py
├── reporters/          # Console, JSON, HTML, CSV
├── data/               # Wordlists & payloads
│   ├── odoo_paths.txt
│   ├── controller_routes.txt
│   ├── sensitive_paths.txt
│   └── payloads/
└── utils/              # Colors, HTTP helpers, WAF detection
```

---

## License

Apache-2.0
