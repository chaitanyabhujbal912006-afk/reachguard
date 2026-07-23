# ReachGuard 🛡️

> **Reachability-Aware Dependency Vulnerability Scanner for Python**

[![PyPI Version](https://img.shields.io/pypi/v/reachguard.svg)](https://pypi.org/project/reachguard/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OSV.dev](https://img.shields.io/badge/Vulnerability%20Data-OSV.dev-green.svg)](https://osv.dev/)
[![PyCG Powered](https://img.shields.io/badge/Call%20Graph-PyCG-purple.svg)](https://github.com/vitsalis/pycg)

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
[ Entry Points ] ---> [ AST Walk ] ---> [ PyCG Call Graph ]
                                               │
                                               ▼
[ OSV Advisory ] ---> [ Target Mine ] ---> [ BFS Reachability Check ]
                                               │
                                               ▼
                                  ┌──────────────────────────┐
                                  │   REACHABLE   (Action!)  │
                                  │   UNKNOWN     (Review)   │
                                  │   UNREACHABLE (Ignore)   │
                                  └──────────────────────────┘
```

---

## 💡 How It Works (In 2 Simple Steps)

1. **Finds CVEs in Dependencies**: ReachGuard reads your `requirements.txt` (or `pyproject.toml` / `Pipfile.lock`) and queries the open **OSV.dev** security database for known vulnerabilities.
2. **Traces Your Source Code**: It walks your Python source code (`--src ./src`), constructs a call graph via PyCG, and verifies: *"Does your code actually call the broken function inside that package?"*

### 📊 The 3 Statuses ReachGuard Gives You:

| Status | Meaning | Action |
|---|---|---|
| 🔴 **`REACHABLE`** | Your code **actually calls** the vulnerable function! | **Fix / Patch Immediately!** |
| 🟡 **`UNKNOWN`** | Package has a CVE, but advisory function details are sparse. | Manual Review. |
| 🟢 **`UNREACHABLE`** | Package has a CVE, but your code **never calls** that function. | **Safe to Ignore!** |

### 🔍 Real-World Example:

```text
Suppose your requirements.txt contains `werkzeug==2.3.3` (which has CVE-2023-221 in `parse_multipart`):

- Dependabot:  🔴 "CRITICAL VULNERABILITY! Update Werkzeug!" (Even if your app never uploads files!)
- ReachGuard:  🟢 "UNREACHABLE — Werkzeug has a CVE, but your code never calls parse_multipart()."
- ReachGuard:  🔴 "REACHABLE   — app.py::download() -> Flask.dispatch_request() -> werkzeug.safe_join()"
```

---

## 🚀 Key Features

* 🎯 **Smart Reachability Ranking**: Classifies findings into:
  * `REACHABLE` 🔴: Vulnerable function is reachable from application entry points (High Priority).
  * `UNKNOWN` 🟡: Package is imported but function-level advisory details are sparse (Manual Review).
  * `UNREACHABLE` 🟢: Package contains a CVE, but the vulnerable code path is never called (Safe to Deprioritize).
* ⚡ **Zero-Cost & Local-First**: Built entirely on free, open tools — **OSV.dev API** (no API key needed) and **PyCG** (static analysis).
* 📦 **Multi-Format & Dynamic Dependency Support**: Auto-detects `requirements.txt`, `pyproject.toml` (PEP 621 & Poetry), and `Pipfile.lock`. Automatically resolves exact pins (`flask==2.3.2`) as well as unpinned or version-ranged dependencies (`flask>=2.0`) via `importlib.metadata`.
* 🔍 **AST Entry Point Detector**: Automatically identifies `if __name__ == '__main__'` blocks and web route handlers (`@app.route`, `@app.get`, `@router.post` for Flask, FastAPI, Starlette).
* 🧹 **Noise & Stdlib Filter**: Eliminates false positives by filtering standard library method references (`str.format`) and template filter names (`xmlattr`).
* 📊 **CI/CD Integrated**: Rich terminal formatting with severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), `--output-json` exports, and `--fail-on-reachable` exit gates for build pipelines.

---

## ⚙️ Installation

### Option 1: Via PyPI (Recommended)
Install ReachGuard globally from PyPI:

```bash
pip install reachguard
```

### Option 2: From Source
```bash
git clone https://github.com/chaitanyabhujbal912006-afk/reachguard.git
cd reachguard
pip install -e .
```

*(Requirements include `typer`, `rich`, `requests`, and `pycg`)*

---

## 💻 Quick Start & Usage

### 1. Basic Scan (Auto-build Call Graph)
Provide your dependency file and source code directory. ReachGuard will automatically detect entry points and generate the call graph:

```bash
python main.py requirements.txt --src ./src
```

### 2. Scan using Pre-Built Call Graph
If you already generated a PyCG call graph JSON file:

```bash
python main.py requirements.txt --src ./src --call-graph callgraph.json
```

### 3. CI/CD Quality Gate Pipeline
Export findings to JSON and break the build if any `REACHABLE` vulnerabilities exist:

```bash
python main.py requirements.txt --src ./src --output-json report.json --fail-on-reachable
```

---

## 📋 CLI Reference

```text
Usage: main.py [OPTIONS] REQUIREMENTS_PATH

Arguments:
  REQUIREMENTS_PATH  Path to requirements.txt, pyproject.toml, or Pipfile.lock  [required]

Options:
  -s, --src TEXT          Path to Python source directory for auto call-graph & entry points.
  -g, --call-graph TEXT   Path to pre-built PyCG call graph JSON file.
  -o, --output-json TEXT  File path to export scan findings as structured JSON.
  --fail-on-reachable     Exit with non-zero status (1) if reachable CVEs are detected.
  --help                  Show this message and exit.
```

---

## 📊 Sample Terminal Output

```text
ReachGuard scanning requirements.txt — 21 pinned dependencies

Loaded call graph: callgraph.json (137 nodes)
Entry points detected: 2

                            ReachGuard Scan Results                            
┌──────────────────┬─────────────────────┬──────────┬──────────────┬─────────────────────────────────────────┐
│ Package          │ CVE / ID            │ Severity │ Status       │ Summary                                 │
├──────────────────┼─────────────────────┼──────────┼──────────────┼─────────────────────────────────────────┤
│ werkzeug==2.3.3  │ GHSA-29vq-49wr-vm6x │ MODERATE │ REACHABLE    │ Werkzeug high resource usage parsing... │
│ werkzeug==2.3.3  │ GHSA-87hc-h4r5-73f7 │ MODERATE │ REACHABLE    │ Werkzeug parsing multipart form data... │
│ celery==5.2.7    │ GHSA-1234-abcd-5678 │ HIGH     │ UNKNOWN      │ Celery deserialization advisory         │
│ flask==2.3.2     │ GHSA-68rp-wp8r-4726 │ LOW      │ UNREACHABLE  │ Flask session Vary: Cookie header       │
│ jinja2==3.1.2    │ GHSA-q2x7-8rv6-6q7h │ MODERATE │ UNREACHABLE  │ Jinja sandbox breakout via format       │
└──────────────────┴─────────────────────┴──────────┴──────────────┴─────────────────────────────────────────┘

Summary:  2 reachable  |  1 unknown  |  2 unreachable  |  0 critical severity (total CVEs: 5)

! Action required: 2 CVE(s) are reachable from your code -- patch or mitigate these first.
```

---

## 🛠️ Architecture & How It Works

```
                     ┌───────────────────────────────┐
                     │   Dependency File Parser      │
                     │ (requirements / toml / lock)  │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │       OSV.dev API Query       │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
┌──────────────────────────────┐    ┌──────────────────────────────┐
│  AST Entry Point Detector    │    │  PyCG Static Call Graph      │
│  (__main__, @app.route)      │    │  (Caller -> Callee Graph)    │
└──────────────┬───────────────┘    └──────────────┬───────────────┘
               │                                   │
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
                     │     Rich Terminal & JSON      │
                     └───────────────────────────────┘
```

1. **Dependency Ingestion**: Auto-detects dependency files and normalizes package names and exact pinned versions according to PEP 503.
2. **Advisory Resolution**: Batch queries OSV.dev REST endpoints to retrieve known vulnerability data and extracts function targets using heuristic regex mining.
3. **Call Graph Generation**: Invokes PyCG to construct a complete control-flow call graph of Python callables.
4. **AST Entry Point Mining**: Walks repository ASTs to locate execution roots (`if __name__ == '__main__'`, Flask/FastAPI route decorators).
5. **Graph Traversal (BFS)**: Executes a multi-tier Breadth-First Search from discovered entry points to target vulnerability functions, returning a deterministic `ReachabilityStatus`.

---

## 🧪 Running Tests

ReachGuard includes a 35-test suite covering AST parsing, OSV target extraction, noise filtering, call-graph normalisation, and reachability traversal:

```bash
python tests/test_suite.py
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request:

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.
