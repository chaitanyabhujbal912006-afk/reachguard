# ReachGuard 🛡️ Roadmap & Feature Backlog

> **Refined. Secure. Connected.** — A comprehensive task list and implementation guide for future ReachGuard enhancements.

---

## 📌 Phase 1: High-Value Quick Wins (Prioritized)

### 1. 💡 Auto-Remediation & Patch Advice (`--suggest-fixes`) [COMPLETED]
* **Goal**: For every `REACHABLE` vulnerability, extract the fixed version from OSV advisories and display the exact upgrade command.
* **CLI Flag**: `reachguard requirements.txt --src ./src --suggest-fixes`

### 2. 🛡️ SARIF Output Format (`--output-sarif report.sarif`) [COMPLETED]
* **Goal**: Support standard SARIF v2.1.0 output for native GitHub Code Scanning & VS Code integration.
* **CLI Flag**: `reachguard requirements.txt --src ./src --output-sarif report.sarif`

### 3. ⚡ Async Parallel OSV Batch Queries [COMPLETED]
* **Goal**: Speed up dependency scanning for large projects with 100+ dependencies by making concurrent HTTP requests to OSV.dev.

---

## 🚀 Phase 2: User Experience & Workflow Tools

### 4. 📊 Interactive HTML Dashboard (`--output-html report.html`) [COMPLETED]
* **Goal**: Generate a single-file, self-contained HTML security report with interactive charts, collapsible call graph trees, search filters, and severity meters.

### 5. 🪝 Pre-Commit Git Hook Integration [COMPLETED]
* **Goal**: Allow developers to run ReachGuard automatically prior to every `git commit`.

---

## 🏢 Phase 3: Framework & Enterprise Expansion

### 6. 🔍 Extended AST Detectors (Django, Celery, Click, Typer) [COMPLETED]
* **Goal**: Expand AST entry-point mining in `reachguard_core/entrypoints.py` beyond Flask/FastAPI to auto-detect:
  - **Django**: Class-based views (`APIView`, `View`, `ModelViewSet`).
  - **Celery**: Asynchronous background tasks (`@app.task`, `@shared_task`).
  - **Click / Typer**: CLI command functions (`@click.command()`, `@app.command()`).

### 7. 📄 SBOM Export with Reachability Annotations (CycloneDX v1.5) [COMPLETED]
* **Goal**: Generate Software Bill of Materials (SBOM) annotated with reachability statuses for enterprise compliance (SOC2, ISO 27001).
* **CLI Flag**: `reachguard requirements.txt --output-sbom cyclonedx.json`

### 8. 🛡️ Policy & Ignored Vulnerabilities (`.reachguardignore` / `reachguard.toml`) [COMPLETED]
* **Goal**: Dismiss accepted risks or false positives with expiration dates and audit rationale.

---

## 🚀 Phase 4: Future Horizons

### 9. ⚡ PR / Git Diff Incremental Scanning (`--diff main`)
* **Goal**: Scan only functions modified in a Pull Request to check if new reachability paths were introduced.

### 10. 📊 EPSS Probability Score Integration
* **Goal**: Fetch Exploit Prediction Scoring System (EPSS) scores to produce composite risk scores (`Reachability x Severity x EPSS`).

---

## 🛠️ Summary Task Checklist

- [x] Implement `--suggest-fixes` patch recommendations.
- [x] Implement `--output-sarif` for GitHub Code Scanning tab integration.
- [x] Add parallel thread executor to `osv.py` for sub-second queries.
- [x] Implement standalone HTML report generator (`--output-html`).
- [x] Add `.pre-commit-hooks.yaml` config.
- [x] Extend `entrypoints.py` AST walker for Django, Celery, Click, and Typer.
- [x] Add CycloneDX v1.5 SBOM exporter (`--output-sbom`).
- [x] Add Policy Suppression engine (`.reachguardignore` / `reachguard.toml`).
- [ ] Add PR Git Diff scanning (`--diff main`).
- [ ] Add EPSS score risk rating.
