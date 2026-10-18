# 🛡️ SurfaceSentry

> **Automated External Attack Surface Management (EASM) & Continuous Exposure Monitoring**

[![CI](https://github.com/your-username/surfacesentry/actions/workflows/ci.yml/badge.svg)](https://github.com/your-username/surfacesentry/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**SurfaceSentry** is an automated attack surface monitoring platform designed for security engineers, red teams, and DevSecOps practitioners. It continuously maps your internet-facing perimeter, benchmarks baselines, and flags exposure drift—alerting you the moment a new subdomain goes live, an administrative port is left open, or an SSL/TLS certificate approaches expiration.

---

## 📑 Architecture Overview

```text
                               +-----------------------------+
                               |     Target Domain Input     |
                               +--------------+--------------+
                                              |
                     +------------------------v------------------------+
                     |             Subdomain Discovery                 |
                     |  - Certificate Transparency (crt.sh)           |
                     |  - Active Wordlist Brute-force                  |
                     |  - Concurrent Async DNS Resolvers               |
                     +------------------------+------------------------+
                                              |
                     +------------------------v------------------------+
                     |           Multi-Vector Probing                  |
                     |  - Non-blocking TCP Port Scanner (asyncio)      |
                     |  - Banner & Protocol Fingerprinter              |
                     |  - TLS / SSL Certificate Inspector              |
                     |  - HTTP Title & Technology Heuristics           |
                     +------------------------+------------------------+
                                              |
                     +------------------------v------------------------+
                     |              Plugin Engine                      |
                     |  - Security Header Validator (HSTS, CSP, etc.)  |
                     |  - Sensitive File Leak Probe (.git, .env)       |
                     |  - Extensible Custom Checks                     |
                     +------------------------+------------------------+
                                              |
                     +------------------------v------------------------+
                     |          Differential Engine (Diff)             |
                     |  - Compares against historical SQLite baseline  |
                     |  - Flags new assets, closed ports, & drifts     |
                     +------------------------+------------------------+
                                              |
             +--------------------------------+--------------------------------+
             |                                                                 |
             v                                                                 v
+--------------------------+                                      +--------------------------+
|    Interactive CLI       |                                      |   Alerts & Notifications |
|    (Rich Dashboard)      |                                      |   (Slack/Discord/JSON)   |
+--------------------------+                                      +--------------------------+
```

---

## ✨ Key Features

- **Concurrent Subdomain Discovery**: Blends passive Certificate Transparency (crt.sh) streaming with high-throughput asynchronous DNS resolution.
- **Asynchronous Port & Service Mapping**: Native non-blocking TCP socket scanner powered by Python `asyncio` with banner extraction.
- **Automated Attack Surface Diffing**: Pinpoints exact deltas over time—discovering rogue hosts, shadow IT, newly opened ports, or closed services.
- **TLS/SSL Expiration Warnings**: Automatically detects certificates nearing expiration (default: < 14 days) to prevent service degradation or hijacking.
- **Technology & Header Fingerprinting**: Detects server runtimes, reverse proxies, and missing modern defensive HTTP headers (CSP, HSTS, frame-ancestors).
- **Pluggable Architecture**: Easily write custom vulnerability and reconnaissance modules by implementing a single `BasePlugin` class.
- **Alert Dispatching**: Ships with immediate console output, formatted JSON exports, and webhook notifications for Slack or Discord.

---

## 🚀 Quick Start

### 1. Installation

Clone the repository and install the package in editable mode:

```bash
git clone https://github.com/<your-username>/surfacesentry.git
cd surfacesentry
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 2. Run a Surface Scan

Scan an authorized target domain:

```bash
# Run full reconnaissance and vulnerability inspection
surfacesentry scan example.com

# Run in passive mode (CT logs + DNS, no port scanning)
surfacesentry scan example.com --passive

# Send alerts to Slack/Discord on newly discovered assets
surfacesentry scan example.com --webhook https://hooks.slack.com/services/XXX/YYY/ZZZ

# Export results to JSON
surfacesentry scan example.com --export scan_output.json
```

### 3. Review Attack Surface Deltas

Compare the latest scan against a previous baseline:

```bash
# Automatically diff latest scan with previous baseline
surfacesentry diff example.com

# Explicitly compare two historical scan IDs
surfacesentry diff example.com --base scan_a1b2c3d4 --target scan_e5f6g7h8
```

### 4. Inspect Scan History

```bash
surfacesentry history example.com
```

---

## 🧩 Extending SurfaceSentry (Plugin System)

Writing a custom detector takes under 20 lines of Python:

```python
from surfacesentry.plugins.base import BasePlugin
from surfacesentry.core.models import Asset, Finding

class GrafanaDetector(BasePlugin):
    name = "grafana_detector"
    description = "Checks for exposed Grafana login dashboards"

    def run(self, asset: Asset) -> list[Finding]:
        findings = []
        for port in asset.ports:
            if port.port in (3000, 80, 443) and "grafana" in (port.banner or "").lower():
                findings.append(Finding(
                    plugin_name=self.name,
                    severity="MEDIUM",
                    title="Exposed Grafana Dashboard",
                    description=f"Grafana detected on {asset.subdomain}:{port.port}",
                    target=asset.subdomain
                ))
        return findings
```

Register the module in `surfacesentry/plugins/manager.py` to include it in subsequent runs.

---

## 🧪 Testing

SurfaceSentry includes a complete unit test suite validating models, SQLite persistence, diff calculations, and plugin lifecycle:

```bash
pytest -v
```

---

## 🐳 Docker Deployment

Run SurfaceSentry using Docker without installing local Python dependencies:

```bash
docker build -t surfacesentry .
docker run --rm surfacesentry scan example.com --passive
```

---

## ⚖️ Legal & Ethical Usage

> **DISCLAIMER**: SurfaceSentry is developed strictly for authorized security assessments, defensive asset management, and research on systems you own or have explicit, documented permission to test. Unauthorized port scanning or reconnaissance against third-party networks may violate applicable laws and computer crime statutes. The author assumes no liability for misuse.
