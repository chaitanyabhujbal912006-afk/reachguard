
<p align="center">
  <img src="logo.png" alt="ReachGuard Logo" width="600" />
</p>

<p align="center">
  <strong>Refined. Secure. Connected.</strong><br>
  <em>Reachability-Aware Dependency Vulnerability Scanner for Python</em>
</p>

<p align="center">
  <a href="https://pypi.org/project/reachguard/"><img src="https://img.shields.io/pypi/v/reachguard.svg" alt="PyPI Version"></a>
  <a href="https://github.com/chaitanyabhujbal912006-afk/reachguard/releases"><img src="https://img.shields.io/github/v/release/chaitanyabhujbal912006-afk/reachguard.svg" alt="GitHub Release"></a>
  <a href="https://github.com/chaitanyabhujbal912006-afk/reachguard/actions/workflows/ci.yml"><img src="https://github.com/chaitanyabhujbal912006-afk/reachguard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://osv.dev/"><img src="https://img.shields.io/badge/Vulnerability%20Data-OSV.dev-green.svg" alt="OSV.dev"></a>
  <a href="https://github.com/vitsalis/pycg"><img src="https://img.shields.io/badge/Call%20Graph-PyCG-purple.svg" alt="PyCG Powered"></a>
</p>

---

## 🎯 The Problem

Traditional dependency security tools (**Dependabot**, **Snyk**, **Safety**) flag hundreds of vulnerabilities simply because a package version is listed in `requirements.txt`. However, in real-world applications:

* **>80% of flagged CVEs are completely unreachable** because your application never imports or calls the vulnerable functions.
* Developers suffer from **severe alert fatigue**, leading to critical vulnerabilities being ignored amidst the noise.
* Enterprise reachability tools are expensive, proprietary, and require sending private code to external cloud SaaS platforms.

---

## ✨ The Solution

**ReachGuard** is an open-source, local-first, zero-cost vulnerability scanner that performs **static call-graph reachability analysis**. It traces your application's execution path from entry points down to external dependency calls to verify whether a vulnerable function can actually be reached at runtime.

```
[ Entry Points ] --> [ Import Scanner ] --> [ PyCG Call Graph ]
                                                   │
                                                   ▼
[ OSV Advisory ] --> [ Target Mine ]  --> [ BFS Reachability Check ]
                                                   │
                                                   ▼
                                      ┌──────────────────────────┐
                                      │   REACHABLE   (Action!)  │
                                      │   UNKNOWN     (Review)   │
                                      │   UNREACHABLE (Ignore)   │
                                      └──────────────────────────┘
```

---

## 💡 How It Works

1. **Auto-Discovers Dependencies**: Reads your `requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, or `pdm.lock` — or scans the active environment if no file is given.
2. **Queries OSV.dev**: Checks every dependency against the open **OSV.dev** security database (no API key needed) with parallel requests, caching, and retry logic.
3. **Import-Based Pre-Filter**: AST-walks your source files to check which packages are actually imported. Packages that are **never imported** are immediately marked `UNREACHABLE` — without needing a call graph.
4. **Call Graph Reachability**: Builds a PyCG call graph and runs a BFS from detected entry points (Flask routes, `asyncio.run()`, `__main__.py`, etc.) to confirm if vulnerable functions are reachable.

### 📊 The 3 Statuses:

| Status | Meaning | Action |
|---|---|---|
| 🔴 **`REACHABLE`** | Your code **actually calls** the vulnerable function | **Patch immediately!** |
| 🟡 **`UNKNOWN`** | Package is imported but advisory function details are sparse | Manual review |
| 🟢 **`UNREACHABLE`** | CVE exists but vulnerable code path is never called | **Safe to deprioritize** |

### 🔍 Real-World Example:

```text
requirements.txt contains werkzeug==2.3.3 (CVE in parse_multipart):

- Dependabot:  🔴 "CRITICAL! Update Werkzeug!"  (even if your app never uploads files)
- ReachGuard:  🟢 "UNREACHABLE — werkzeug is never imported in your source"
- ReachGuard:  🔴 "REACHABLE   — app.py::upload() -> Flask.dispatch() -> werkzeug.parse_multipart()"
```

---

## 🚀 Key Features

| Feature | Details |
|---|---|
| 🎯 **Smart Reachability** | BFS from entry points to vulnerable functions |
| 🔍 **Import Pre-Filter** | Instant UNREACHABLE for packages never imported (~40% noise reduction) |
| 💾 **OSV Cache** | Disk cache with 24h TTL (`~/.cache/reachguard/`) — fast repeat scans |
| ⚡ **Retry Resilience** | 3x exponential backoff on OSV rate limits & server errors |
| 📦 **Multi-Format** | `requirements.txt`, `pyproject.toml`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `pdm.lock` |
| 🔄 **Zero-Config** | Auto-discovers dependency files — just run `reachguard` in your project |
| 🌐 **Framework Support** | Flask, FastAPI, Django, Celery, Click, Typer, Tornado, Aiohttp |
| 📊 **Rich Outputs** | Table, JSON, SARIF v2.1.0, HTML dashboard, CycloneDX v1.5 SBOM |
| 🪝 **Pre-Commit Hook** | Block commits if REACHABLE CVEs are found |
| 🤖 **GitHub Action** | Built-in action + CI workflow with auto-PyPI publish |
| 📈 **EPSS Scoring** | `--epss` fetches exploit probability scores from `first.org` API |
| ⚡ **PR Diff Scanning** | `--diff main` scans only code modified in a Pull Request |
| 📋 **Policy Engine** | `.reachguardignore` / `reachguard.toml` to suppress false positives |
| 🔧 **Auto-Remediation** | `--suggest-fixes` shows exact `pip install pkg>=fixed_version` commands |

---

## ⚙️ Installation

### Via PyPI (Recommended)
```bash
pip install reachguard
```

### Run as Python Module
```bash
python -m reachguard_core --help
```

### From Source
```bash
git clone https://github.com/chaitanyabhujbal912006-afk/reachguard.git
cd reachguard
pip install -e .
```

---

## 💻 Usage

### Zero-Config (just run in your project directory)
```bash
reachguard
```
*(Displays the interactive terminal ASCII banner, color-coded findings table, and reachability overview)*


### Scan a specific file or directory
```bash
reachguard requirements.txt --src ./src
```

### With all output formats
```bash
reachguard . --src . \
  --output-json report.json \
  --output-sarif report.sarif \
  --output-html report.html \
  --output-sbom sbom.json \
  --suggest-fixes
```

### CI/CD quality gate — fail on REACHABLE CVEs
```bash
reachguard . --src . --fail-on-reachable
```

### Filter noise — only show HIGH+ severity findings that are reachable
```bash
reachguard . --src . --min-severity HIGH --only-reachable
```

### PR Incremental Scanning (scan only modified code in a Pull Request)
```bash
reachguard . --src . --diff main
```

### EPSS Exploit Probability Scoring (fetch scores from first.org)
```bash
reachguard . --src . --epss
```

### Speed up with caching and more workers
```bash
reachguard . --src . --max-workers 20 --cache-dir ./.cache
```

---

## 📋 Full CLI Reference

```
Usage: reachguard [OPTIONS] [REQUIREMENTS_PATH]

Arguments:
  REQUIREMENTS_PATH  Path to requirements file, pyproject.toml, lockfile,
                     or project directory. Defaults to current directory.

Options:
  -s, --src TEXT           Source directory for call graph & entry point detection.
  -g, --call-graph TEXT    Pre-built PyCG call graph JSON (skips auto-build).
  -o, --output-json TEXT   Write findings as JSON to this file.
  --output-sarif TEXT      Write findings in SARIF v2.1.0 format.
  --output-html TEXT       Write an interactive HTML dashboard report.
  --output-sbom TEXT       Write CycloneDX v1.5 SBOM JSON.
  --fail-on-reachable      Exit code 1 if any REACHABLE CVEs found.
  --exit-code TEXT         Exit strategy: 'none' | 'any' | 'reachable' (default).
  --suggest-fixes          Show recommended pip upgrade commands.
  --epss                   Fetch EPSS exploit probability scores from first.org API.
  --diff TEXT              Git base branch (e.g. 'main') for PR incremental scanning.
  --min-severity TEXT      Minimum severity: LOW | MEDIUM | HIGH | CRITICAL.
  --only-reachable         Show only REACHABLE findings.
  --timeout INT            OSV HTTP timeout in seconds (default: 10).
  --max-workers INT        Concurrent OSV HTTP threads (default: 10).
  --no-cache               Disable disk-based OSV response cache.
  --cache-dir TEXT         Custom cache directory (default: ~/.cache/reachguard/).
  -v, --verbose            Debug output: raw API responses, cache stats.
  -q, --quiet              Suppress all output except errors.
  --log-file TEXT          Write structured log to this file.
  --log-format TEXT        Log format: 'plain' (default) or 'json'.
  -c, --config TEXT        Policy file (.reachguardignore / reachguard.toml).
  -V, --version            Print version and exit.
  --help                   Show this message and exit.
```

---

## 📊 Sample Terminal Output

```text
ReachGuard v1.0.0 scanning requirements.txt — 21 dependencies

Building call graph via PyCG … (./src)
Call graph built: 137 nodes

Entry points detected: 4
Import scanner: 14 packages imported in source

                            ReachGuard Scan Results
┌──────────────────┬─────────────────────┬──────────┬──────────────┬──────────────────────────────────────────┐
│ Package          │ CVE / ID            │ Severity │ Status       │ Summary                                  │
├──────────────────┼─────────────────────┼──────────┼──────────────┼──────────────────────────────────────────┤
│ werkzeug==2.3.3  │ GHSA-29vq-49wr-vm6x │ HIGH     │ REACHABLE    │ Werkzeug multipart parsing DoS ...       │
│                  │                     │          │              │ --> Path: upload -> dispatch -> parse_... │
│ celery==5.2.7    │ GHSA-1234-abcd-5678 │ HIGH     │ unknown      │ Celery deserialization advisory           │
│ flask==2.3.2     │ GHSA-68rp-wp8r-4726 │ LOW      │ unreachable  │ Flask session Vary: Cookie header         │
│ jinja2==3.1.2    │ GHSA-q2x7-8rv6-6q7h │ MEDIUM   │ unreachable  │ Jinja sandbox breakout (not imported)    │
└──────────────────┴─────────────────────┴──────────┴──────────────┴──────────────────────────────────────────┘

Summary:  1 reachable  |  1 unknown  |  2 unreachable  |  0 critical severity (total CVEs: 4)

! Action required: 1 CVE(s) are reachable from your code -- patch or mitigate these first.
```

---

## 🤖 GitHub Actions Integration

```yaml
name: ReachGuard Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  reachguard-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ReachGuard Scan
        uses: chaitanyabhujbal912006-afk/reachguard@main
        with:
          requirements: '.'
          src: '.'
          output_sarif: 'reachguard.sarif'
          fail_on_reachable: 'true'

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reachguard.sarif
```

---

## 🪝 Pre-Commit Integration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/chaitanyabhujbal912006-afk/reachguard
    rev: v1.0.0
    hooks:
      - id: reachguard
        args: [".", "--src", ".", "--fail-on-reachable"]
```

---

## 🛡️ Policy Suppression

Suppress known false positives or accepted risks:

**`.reachguardignore`** (line-based):
```
# Accepted risk — only triggered via admin panel
GHSA-29vq-49wr-vm6x  # Werkzeug multipart — admin-only endpoint, rate-limited
CVE-2023-12345       # No viable patch yet, mitigated by WAF
```

**`reachguard.toml`** (with expiry dates):
```toml
[ignore]
"GHSA-29vq-49wr-vm6x" = { reason = "Admin-only endpoint", expires = "2026-12-31" }

[ignore_packages]
ignore_packages = ["dev-only-tool"]
```

---

## 🛠️ Architecture

```
                     ┌───────────────────────────────┐
                     │   Dependency File Parser      │
                     │ (requirements / toml / lock)  │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │  OSV.dev API (Parallel+Cache) │
                     │  Retry on 429/5xx, 24h TTL    │
                     └───────────────┬───────────────┘
                                     │
                     ┌───────────────▼───────────────┐
                     │   Import Scanner (AST-fast)   │  ← NEW in v1.0
                     │  Not imported → UNREACHABLE   │
                     └───────────────┬───────────────┘
                                     │
┌──────────────────────────┐        ┌▼─────────────────────────┐
│  AST Entry Point Detector│        │  PyCG Static Call Graph  │
│  (__main__, @app.route,  │        │  (Caller → Callee Graph) │
│   asyncio.run, uvicorn)  │        └──────────────┬───────────┘
└──────────────┬───────────┘                       │
               └─────────────────┬─────────────────┘
                                 │
                                 ▼
                     ┌───────────────────────────────┐
                     │   Three-Tier BFS Engine       │
                     │  1. Basename Match            │
                     │  2. Path-Prefix Match         │
                     │  3. Top-Level Entry Seed      │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │  Rich Table / JSON / SARIF /  │
                     │  HTML / CycloneDX SBOM        │
                     └───────────────────────────────┘
```

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all 61 tests
python -m pytest tests/ -v

# With coverage report
python -m pytest tests/ --cov=reachguard_core --cov-report=term-missing
```

**Test coverage includes:**
- EPSS API fetching & composite risk score calculation (`test_epss.py`)
- GitDiffScanner PR modified function extraction (`test_diff.py`)
- Cache TTL, hit/miss, corruption handling (`test_cache.py`)
- Import scanner: aliases, .venv skipping, syntax errors (`test_import_scanner.py`)
- OSV: mocked HTTP, retry logic, batch queries (`test_osv.py`)
- Reachability: BFS traversal, noise filtering, suffix matching
- CLI: HTML output, SBOM, SARIF, policy suppression, severity parsing (`test_cli.py`)
- Dependency parsers: `uv.lock`, `pdm.lock`, recursive `-r` includes (`test_suite.py`)

---

## 📜 Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## 🤝 Contributing

Contributions welcome! Open an issue or submit a pull request:

1. Fork the project
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
