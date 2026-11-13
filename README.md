# InfoSec Audit & Reconnaissance Tools

[![CI](https://github.com/rafaelsoje/infosec-audit-tools/actions/workflows/ci.yml/badge.svg)](https://github.com/rafaelsoje/infosec-audit-tools/actions)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Security: InfoSec](https://img.shields.io/badge/Domain-Information%20Security-red)](https://rafaelsoje.com)
[![AsyncIO](https://img.shields.io/badge/Networking-AsyncIO%20%2F%20RDAP-green)](https://docs.python.org/3/library/asyncio.html)
[![OWASP: Secure Headers](https://img.shields.io/badge/OWASP-Secure%20Headers-orange)](https://owasp.org/www-project-secure-headers/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[ English ] • [ [Versão em Português](README.pt-br.md) ]

---

A modular suite of Python utilities designed for attack surface reconnaissance, defensive HTTP security header auditing, and controlled vulnerability validation.

Developed by **[Rafael Soje](https://rafaelsoje.com)** — Postgraduate in Information Security & Full Stack Software Engineer.

---

> [!CAUTION]
> **Ethical and Legal Disclaimer:**
> The tools in this repository are intended strictly for educational purposes, authorized penetration testing, and Blue Team / Red Team exercises conducted within controlled lab environments or on systems where explicit authorization has been granted by the asset owner. The author accepts no liability for misuse, unauthorized access, or damages resulting from the use of these tools.

---

## Repository Structure

```text
infosec-audit-tools/
├── recon/
│   ├── domain_availability_checker.py     # Asynchronous RDAP and DNS lookup reconnaissance
│   ├── email_security_auditor.py          # Defensive email security auditing (SPF, DMARC, DKIM, anti-spoofing)
│   ├── http_security_headers_auditor.py   # Defensive HTTP security header auditing with OWASP scoring
│   ├── ssl_tls_security_auditor.py        # Passive SSL/TLS cipher and X.509 certificate auditing
│   └── subdomain_recon_crtsh.py           # Passive subdomain discovery via CT Logs (crt.sh)
├── wordpress/
│   ├── really_simple_security_detector.py # Passive security header audit and plugin version detection
│   └── cve_2024_10924_poc.py              # Proof of Concept and remediation guide for CVE-2024-10924
├── requirements.txt                       # Project dependencies (aiohttp, requests)
├── LICENSE                                # MIT License
├── README.md                              # English documentation and usage guides
└── README.pt-br.md                        # Portuguese documentation
```

---

## Installation & Prerequisites

Using a Python virtual environment is recommended:

```bash
# Clone the repository
git clone https://github.com/rafaelsoje/infosec-audit-tools.git
cd infosec-audit-tools

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Modules & Usage Guides

### 1. Attack Surface Reconnaissance (`recon/`)

#### `domain_availability_checker.py`
High-performance asynchronous scanner built with `asyncio` and `aiohttp` for large-scale domain availability checking and infrastructure reconnaissance:
* Queries official **RDAP (Registration Data Access Protocol)** endpoints: Verisign (`.com`), Registro.br (`.com.br`), and `rdap.org`.
* Validates primary DNS resolution (`A`/`AAAA`) with semaphore-based concurrency control (`asyncio.Semaphore`).
* Direct CSV export for brand intelligence, defensive domain registration tracking, and domain discovery.

```bash
# Check availability from an input wordlist:
python3 recon/domain_availability_checker.py wordlist.txt --tlds com,com.br --concurrency 30 -o available_domains.csv

# Output to stdout only:
python3 recon/domain_availability_checker.py wordlist.txt --only-print
```

#### `email_security_auditor.py`
Passive DNS-based email security posture and domain spoofing auditor:
* Audits **SPF (Sender Policy Framework, RFC 7208)**: validates `all` qualifiers (`-all`, `~all`, `?all`, `+all`), identifies multiple SPF records, and warns if DNS lookups exceed the RFC 10-lookup threshold.
* Audits **DMARC (RFC 7489)**: inspects enforcement policy (`p=reject`, `p=quarantine`, `p=none`), subdomain policy (`sp=`), enforcement percentage (`pct=`), and aggregate/forensic telemetry tags (`rua`/`ruf`).
* Discovers and verifies **DKIM (RFC 6376)** public keys using automated selector discovery or custom selector input (`-s` / `--selector`).
* Calculates overall **Domain Spoofing Risk** (Critical, High, Medium, Low/Secure), numerical score (0-100), and letter grade (A+ through F).
* Supports structured JSON output (`--json`) and file export (`-o`).

```bash
# Run email security audit against a target domain:
python3 recon/email_security_auditor.py example.com

# Audit with a custom DKIM selector and export to JSON:
python3 recon/email_security_auditor.py example.com -s google --json -o email_audit.json
```

#### `http_security_headers_auditor.py`
Defensive web posture and HTTP security header auditor aligned with the OWASP Secure Headers Project:
* Evaluates critical defensive headers: HSTS (`Strict-Transport-Security`), CSP (`Content-Security-Policy`), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy (COOP), and Cross-Origin-Resource-Policy (CORP).
* Flags overly permissive or dangerous directives in CSP (`'unsafe-inline'`, `'unsafe-eval'`) and sensitive server banner leakage (`Server`, `X-Powered-By`).
* Computes numerical technical score and letter grade rating (A+, A, B, C, D, or F).
* Supports structured JSON output (`--json`) and file export (`-o`).

```bash
# Run direct audit:
python3 recon/http_security_headers_auditor.py https://example.com

# Export structured audit results to JSON:
python3 recon/http_security_headers_auditor.py https://example.com -o headers_report.json
```

#### `ssl_tls_security_auditor.py`
Passive cryptographic and SSL/TLS certificate auditor:
* Native TLS socket implementation without external dependencies.
* Assesses negotiated TLS protocol version (TLS 1.2 / TLS 1.3) and warns about legacy/insecure ciphers.
* Inspects Certificate Authority (CA) chain, active cipher suites, and exact expiration timestamp with countdown alerts.
* Enumerates all **Subject Alternative Names (SANs)**, discovering sibling domains and hidden hostnames associated with the target.

```bash
python3 recon/ssl_tls_security_auditor.py example.com
```

#### `subdomain_recon_crtsh.py`
Passive subdomain enumeration leveraging Certificate Transparency (CT Logs):
* Queries public `crt.sh` logs to uncover exposed assets without sending traffic to the target.
* Deduplicates entries, strips wildcard prefixes (`*.`), and optionally verifies active DNS resolution (`--resolve`).
* Supports direct CSV report export.

```bash
# Enumerate subdomains and test active DNS resolution:
python3 recon/subdomain_recon_crtsh.py example.com --resolve -o subdomains.csv
```

---

### 2. Web Security & Application Auditing (`wordpress/`)

#### `really_simple_security_detector.py`
Passive web security and defensive configuration detector:
* Inspects defensive headers:
  * `Strict-Transport-Security` (HSTS)
  * `Content-Security-Policy` (CSP)
  * `X-Content-Type-Options`
  * `X-Frame-Options`
  * `Permissions-Policy`
* Detects active plugin signatures within the DOM/HTML.
* Audits public changelog metadata (`readme.txt`) and issues automated alerts if the discovered version is vulnerable to known CVEs.

```bash
python3 wordpress/really_simple_security_detector.py https://example.com
```

#### `cve_2024_10924_poc.py`
Laboratory validation and Proof of Concept for critical vulnerability **CVE-2024-10924** (CVSS 9.8 - *Authentication Bypass* in *Really Simple Security* prior to version 9.1.2):
* Demonstrates the impact of missing REST API nonce verification on `/reallysimplessl/v1/two_fa/skip_onboarding`.
* Includes remediation recommendations at both code and WAF layers (Cloudflare / Nginx).

```bash
# Run in an authorized lab environment (e.g., TryHackMe / HackTheBox / local container):
python3 wordpress/cve_2024_10924_poc.py http://lab-target.local:8080 --user-id 1
```

---

## Defensive Remediation Best Practices

1. **Defense in Depth**: Defensive HTTP headers should always be enforced at the edge/reverse proxy layer (Cloudflare / Nginx / Apache), independent of application-level plugins or CMS extensions.
2. **Proactive Patch Management**: High-severity vulnerabilities in web frameworks require automated patch monitoring and rapid deployment pipelines.
3. **Endpoint Hardening**: Restrict onboarding, authentication, and debugging endpoints via WAF rate limiting, GeoIP blocking, and IP allowlisting.

---

## Author

**Rafael Soje**
* **Official Website**: [rafaelsoje.com](https://rafaelsoje.com)
* **GitHub**: [@rafaelsoje](https://github.com/rafaelsoje)
* **Education**: Postgraduate in Information Security | B.S. in Computer Science
