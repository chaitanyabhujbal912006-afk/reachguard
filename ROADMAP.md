# ReachGuard 🛡️ Roadmap & Feature Backlog

> **Refined. Secure. Connected.** — A comprehensive task list and implementation guide for future ReachGuard enhancements.

---

## 📌 Phase 1: High-Value Quick Wins (Prioritized)

### 1. 💡 Auto-Remediation & Patch Advice (`--suggest-fixes`) [COMPLETED]
* **Goal**: For every `REACHABLE` vulnerability, extract the fixed version from OSV advisories and display the exact upgrade command.
* **CLI Flag**: `reachguard requirements.txt --src ./src --suggest-fixes`
* **Implementation Outline**:
  - In `reachguard_core/osv.py`: Extract `affected[].ranges[].events[].fixed` version string from OSV JSON response.
  - In `reachguard_core/cli.py`: If `--suggest-fixes` is active, append `pip install <package>>=<fixed_version>` beneath reachable findings in terminal table and JSON output.

### 2. 🛡️ SARIF Output Format (`--output-sarif report.sarif`) [COMPLETED]
* **Goal**: Support standard SARIF v2.1.0 output for native GitHub Code Scanning & VS Code integration.
* **CLI Flag**: `reachguard requirements.txt --src ./src --output-sarif report.sarif`
* **Implementation Outline**:
  - Create `reachguard_core/sarif.py` to construct valid SARIF v2.1.0 JSON payloads.
  - Map `REACHABLE` findings to SARIF `error` level with location URI and message trace.
  - Update `action.yml` to support uploading SARIF files to GitHub Security tab via `github/codeql-action/upload-sarif`.

### 3. ⚡ Async Parallel OSV Batch Queries [COMPLETED]
* **Goal**: Speed up dependency scanning for large projects with 100+ dependencies by making concurrent HTTP requests to OSV.dev.
* **Implementation Outline**:
  - Update `reachguard_core/osv.py` to use `concurrent.futures.ThreadPoolExecutor` or `asyncio` / `httpx`.
  - Fetch OSV.dev advisory JSONs in parallel batches of 10 requests.

---

## 🚀 Phase 2: User Experience & Workflow Tools

### 4. 📊 Interactive HTML Dashboard (`--output-html report.html`)
* **Goal**: Generate a single-file, self-contained HTML security report with interactive charts, collapsible call graph trees, search filters, and severity meters.
* **CLI Flag**: `reachguard requirements.txt --src ./src --output-html report.html`
* **Implementation Outline**:
  - Create `reachguard_core/html_report.py` using Jinja2 or lightweight HTML/CSS templates.
  - Embed JSON data directly into script tags for zero-dependency browser rendering.

### 5. 🪝 Pre-Commit Git Hook Integration
* **Goal**: Allow developers to run ReachGuard automatically prior to every `git commit`.
* **Implementation Outline**:
  - Create `.pre-commit-hooks.yaml` in repository root:
    ```yaml
    - id: reachguard
      name: ReachGuard Reachability Scan
      entry: reachguard
      language: python
      types: [python]
    ```
  - Document pre-commit usage in `README.md`.

---

## 🏢 Phase 3: Framework & Enterprise Expansion

### 6. 🔍 Extended AST Detectors (Django, Celery, Click)
* **Goal**: Expand AST entry-point mining in `reachguard_core/entrypoints.py` beyond Flask/FastAPI to auto-detect:
  - **Django**: Class-based views (`APIView`, `View`) and `urls.py` patterns.
  - **Celery**: Asynchronous background tasks (`@app.task`, `@shared_task`).
  - **Click / Typer**: CLI command functions (`@click.command()`, `@app.command()`).

### 7. 📄 SBOM Export with Reachability Annotations (CycloneDX / SPDX)
* **Goal**: Generate Software Bill of Materials (SBOM) annotated with reachability statuses for enterprise compliance (SOC2, ISO 27001).
* **CLI Flag**: `reachguard requirements.txt --output-sbom cyclonedx.json`
* **Implementation Outline**:
  - Create `reachguard_core/sbom.py` to emit CycloneDX v1.4 JSON specs with `properties` fields indicating reachability status (`REACHABLE` / `UNREACHABLE`).

---

## 🛠️ Summary Task Checklist

- [x] Implement `--suggest-fixes` patch recommendations.
- [x] Implement `--output-sarif` for GitHub Code Scanning tab integration.
- [x] Add parallel thread executor to `osv.py` for sub-second queries.
- [x] Implement standalone HTML report generator (`--output-html`).
- [x] Add `.pre-commit-hooks.yaml` config.
- [ ] Extend `entrypoints.py` AST walker for Django and Celery.
- [ ] Add CycloneDX SBOM exporter (`--output-sbom`).
