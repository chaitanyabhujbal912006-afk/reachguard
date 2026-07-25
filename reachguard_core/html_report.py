"""Interactive HTML dashboard generator for ReachGuard scan results.

Produces a single-file, self-contained HTML report with:
  - Donut chart: REACHABLE / UNKNOWN / UNREACHABLE breakdown.
  - Bar chart: severity distribution (CRITICAL / HIGH / MEDIUM / LOW).
  - Searchable, filterable findings table with call-path traces.
  - Zero external runtime dependencies (Chart.js loaded via CDN with inline fallback).
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from reachguard_core.reachability import ReachabilityStatus

# Type alias matching cli.py
# (name, version, cve_id, summary, status, severity, call_path, fixed_version)
Finding = tuple[str, str, str, str, ReachabilityStatus, str, list[str] | None, str | None]


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>ReachGuard Report — {scan_target}</title>
<meta name="description" content="ReachGuard reachability-aware vulnerability scan report for {scan_target}" />
<style>
  /* ── Design tokens (Official Brand Palette) ─────────────────────── */
  :root {{
    --bg:           #0f172a; /* Deep Slate */
    --surface:      #1e293b;
    --surface2:     #334155;
    --border:       #475569;
    --text:         #f8fafc;
    --text-muted:   #94a3b8;
    --accent:       #34a8c4; /* Slate Cyan */
    --sapphire:     #1a3b8c; /* Deep Sapphire Blue */
    --silver:       #e1e5e9; /* Polished Silver */
    --reachable:    #ef4444;
    --unknown:      #f59e0b;
    --unreachable:  #10b981;
    --critical:     #f87171;
    --high:         #ef4444;
    --medium:       #f59e0b;
    --low:          #10b981;
    --radius:       10px;
    --shadow:       0 4px 24px rgba(0,0,0,.5);
  }}

  /* ── Reset & base ──────────────────────────────────────────────── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    line-height: 1.6;
  }}

  /* ── Header ────────────────────────────────────────────────────── */
  header {{
    background: linear-gradient(135deg, #0f172a 0%, #1a3b8c 50%, #0f172a 100%);
    border-bottom: 1px solid var(--border);
    padding: 24px 40px;
    display: flex;
    align-items: center;
    gap: 18px;
    position: sticky;
    top: 0;
    z-index: 100;
    backdrop-filter: blur(8px);
  }}
  .logo {{
    font-size: 1.9rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    background: linear-gradient(90deg, #34a8c4, #e1e5e9);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    user-select: none;
  }}
  .logo span {{ font-weight: 400; opacity: .6; }}
  .header-meta {{
    margin-left: auto;
    text-align: right;
    font-size: .8rem;
    color: var(--text-muted);
    line-height: 1.4;
  }}

  /* ── Layout ────────────────────────────────────────────────────── */
  main {{ max-width: 1300px; margin: 0 auto; padding: 36px 40px 60px; }}

  /* ── Stat cards ────────────────────────────────────────────────── */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 36px;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 22px;
    display: flex;
    flex-direction: column;
    gap: 4px;
    transition: transform .18s, box-shadow .18s;
    position: relative;
    overflow: hidden;
  }}
  .stat-card::before {{
    content: "";
    position: absolute;
    inset: 0 0 auto 0;
    height: 3px;
    border-radius: var(--radius) var(--radius) 0 0;
  }}
  .stat-card.reachable::before  {{ background: var(--reachable); }}
  .stat-card.unknown::before    {{ background: var(--unknown); }}
  .stat-card.unreachable::before{{ background: var(--unreachable); }}
  .stat-card.total::before      {{ background: linear-gradient(90deg, #58a6ff, #bc8cff); }}
  .stat-card.critical::before   {{ background: var(--critical); }}
  .stat-card:hover {{ transform: translateY(-3px); box-shadow: var(--shadow); }}
  .stat-label {{ font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; color: var(--text-muted); }}
  .stat-value {{ font-size: 2.1rem; font-weight: 700; line-height: 1; }}
  .stat-card.reachable  .stat-value {{ color: var(--reachable); }}
  .stat-card.unknown    .stat-value {{ color: var(--unknown); }}
  .stat-card.unreachable.stat-value {{ color: var(--unreachable); }}
  .stat-card.critical   .stat-value {{ color: var(--critical); }}
  .stat-card.total      .stat-value {{ color: var(--accent); }}

  /* ── Chart row ─────────────────────────────────────────────────── */
  .charts-row {{
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: 20px;
    margin-bottom: 36px;
  }}
  @media (max-width: 768px) {{ .charts-row {{ grid-template-columns: 1fr; }} }}
  .chart-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
  }}
  .chart-title {{
    font-size: .8rem;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--text-muted);
    margin-bottom: 16px;
  }}
  .chart-wrap {{ position: relative; height: 220px; }}

  /* ── Toolbar ────────────────────────────────────────────────────── */
  .toolbar {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 18px;
  }}
  .search-box {{
    flex: 1;
    min-width: 220px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    padding: 9px 14px;
    font-size: .9rem;
    outline: none;
    transition: border-color .15s;
  }}
  .search-box:focus {{ border-color: var(--accent); }}
  .search-box::placeholder {{ color: var(--text-muted); }}
  .filter-btn {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text-muted);
    padding: 9px 16px;
    font-size: .85rem;
    cursor: pointer;
    transition: background .15s, border-color .15s, color .15s;
    white-space: nowrap;
  }}
  .filter-btn:hover  {{ background: var(--surface); color: var(--text); }}
  .filter-btn.active {{
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(88,166,255,.08);
  }}
  .filter-btn.active-red {{ border-color: var(--reachable); color: var(--reachable); background: rgba(248,81,73,.08); }}

  /* ── Findings table ─────────────────────────────────────────────── */
  .table-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }}
  .findings-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: .88rem;
  }}
  .findings-table thead tr {{
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
  }}
  .findings-table th {{
    padding: 12px 16px;
    text-align: left;
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--text-muted);
    font-weight: 600;
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
  }}
  .findings-table th:hover {{ color: var(--text); }}
  .findings-table th .sort-arrow {{ opacity: .4; margin-left: 4px; font-size: .65rem; }}
  .findings-table th.sorted .sort-arrow {{ opacity: 1; color: var(--accent); }}
  .findings-table tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background .12s;
  }}
  .findings-table tbody tr:last-child {{ border-bottom: none; }}
  .findings-table tbody tr:hover {{ background: var(--surface2); }}
  .findings-table td {{ padding: 13px 16px; vertical-align: top; }}
  .pkg-cell {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: .82rem; color: var(--accent); }}
  .cve-link {{
    color: var(--text);
    text-decoration: none;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: .82rem;
    transition: color .12s;
  }}
  .cve-link:hover {{ color: var(--accent); text-decoration: underline; }}
  .summary-cell {{ max-width: 380px; color: var(--text-muted); font-size: .85rem; }}

  /* ── Badges ─────────────────────────────────────────────────────── */
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: .72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .05em;
    white-space: nowrap;
  }}
  .badge-reachable   {{ background: rgba(248,81,73,.15);  color: var(--reachable);   border: 1px solid rgba(248,81,73,.3);  }}
  .badge-unknown     {{ background: rgba(210,153,34,.15); color: var(--unknown);     border: 1px solid rgba(210,153,34,.3); }}
  .badge-unreachable {{ background: rgba(63,185,80,.12);  color: var(--unreachable); border: 1px solid rgba(63,185,80,.25); }}
  .badge-critical    {{ background: rgba(255,68,68,.15);  color: var(--critical);    border: 1px solid rgba(255,68,68,.3);  }}
  .badge-high        {{ background: rgba(248,81,73,.12);  color: #ff7b72;            border: 1px solid rgba(248,81,73,.25); }}
  .badge-medium      {{ background: rgba(210,153,34,.12); color: var(--medium);      border: 1px solid rgba(210,153,34,.25);}}
  .badge-low         {{ background: rgba(63,185,80,.1);   color: var(--low);         border: 1px solid rgba(63,185,80,.2);  }}
  .badge-none        {{ background: var(--surface2); color: var(--text-muted); border: 1px solid var(--border); }}

  /* ── Call path & fix rows ───────────────────────────────────────── */
  .detail-toggle {{
    background: none;
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text-muted);
    font-size: .72rem;
    padding: 2px 8px;
    cursor: pointer;
    margin-top: 6px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    transition: border-color .12s, color .12s;
  }}
  .detail-toggle:hover {{ border-color: var(--accent); color: var(--accent); }}
  .detail-content {{
    display: none;
    margin-top: 8px;
    padding: 10px 12px;
    background: var(--bg);
    border-radius: 6px;
    border-left: 3px solid var(--reachable);
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: .78rem;
    color: #ff7b72;
    line-height: 1.8;
    word-break: break-all;
  }}
  .fix-pill {{
    display: inline-block;
    margin-top: 8px;
    padding: 4px 12px;
    background: rgba(63,185,80,.1);
    border: 1px solid rgba(63,185,80,.3);
    border-radius: 6px;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: .78rem;
    color: var(--unreachable);
  }}
  .fix-label {{ font-size: .72rem; color: var(--text-muted); margin-top: 6px; display: block; }}

  /* ── Empty state ────────────────────────────────────────────────── */
  .empty-state {{
    padding: 48px;
    text-align: center;
    color: var(--text-muted);
    font-size: .95rem;
  }}
  .empty-state-icon {{ font-size: 2.5rem; margin-bottom: 12px; }}

  /* ── Footer ─────────────────────────────────────────────────────── */
  footer {{
    text-align: center;
    padding: 28px;
    font-size: .78rem;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
    margin-top: 48px;
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}
  footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>

<header>
  <div style="display:flex;align-items:center;gap:14px;">
    {logo_img_tag}
    <div>
      <div class="logo">Reach<span>Guard</span></div>
      <div style="font-size:.78rem;color:var(--text-muted);margin-top:3px;">
        Refined. Secure. Connected. &nbsp;·&nbsp; Reachability-aware vulnerability scanner
      </div>
    </div>
  </div>
  <div class="header-meta">
    <div><strong>Target:</strong> {scan_target}</div>
    <div><strong>Scanned:</strong> {scan_time}</div>
    <div><strong>Total CVEs:</strong> {total}</div>
  </div>
</header>

<main>

  <!-- ── Stat cards ───────────────────────────────────────────────── -->
  <div class="stats-grid">
    <div class="stat-card total">
      <div class="stat-label">Total CVEs</div>
      <div class="stat-value">{total}</div>
    </div>
    <div class="stat-card reachable">
      <div class="stat-label">Reachable</div>
      <div class="stat-value">{reachable}</div>
    </div>
    <div class="stat-card unknown">
      <div class="stat-label">Unknown</div>
      <div class="stat-value">{unknown}</div>
    </div>
    <div class="stat-card unreachable">
      <div class="stat-label">Unreachable</div>
      <div class="stat-value">{unreachable}</div>
    </div>
    <div class="stat-card critical">
      <div class="stat-label">Critical Sev.</div>
      <div class="stat-value">{critical}</div>
    </div>
  </div>

  <!-- ── Charts ───────────────────────────────────────────────────── -->
  <div class="charts-row">
    <div class="chart-card">
      <div class="chart-title">Reachability Breakdown</div>
      <div class="chart-wrap">
        <canvas id="donutChart"></canvas>
      </div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Severity Distribution</div>
      <div class="chart-wrap">
        <canvas id="barChart"></canvas>
      </div>
    </div>
  </div>

  <!-- ── Toolbar ──────────────────────────────────────────────────── -->
  <div class="toolbar">
    <input
      id="searchInput"
      class="search-box"
      type="search"
      placeholder="🔍  Search by package, CVE ID, or summary…"
      oninput="applyFilters()"
    />
    <button class="filter-btn active" id="btn-all"         onclick="setFilter('all')">All</button>
    <button class="filter-btn"        id="btn-REACHABLE"   onclick="setFilter('REACHABLE')">⚠ Reachable</button>
    <button class="filter-btn"        id="btn-UNKNOWN"     onclick="setFilter('UNKNOWN')">? Unknown</button>
    <button class="filter-btn"        id="btn-UNREACHABLE" onclick="setFilter('UNREACHABLE')">✓ Unreachable</button>
    <button class="filter-btn"        id="btn-CRITICAL"    onclick="setSeverityFilter('CRITICAL')">🔴 Critical</button>
  </div>

  <!-- ── Findings table ───────────────────────────────────────────── -->
  <div class="table-wrap">
    <table class="findings-table" id="findingsTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Package <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(1)">CVE / ID <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(2)">Severity <span class="sort-arrow">↕</span></th>
          <th onclick="sortTable(3)">Status <span class="sort-arrow">↕</span></th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody id="findingsBody">
        <!-- Populated by JavaScript -->
      </tbody>
    </table>
    <div class="empty-state" id="emptyState" style="display:none">
      <div class="empty-state-icon">🔎</div>
      <div>No findings match your current filter.</div>
    </div>
  </div>

</main>

<footer>
  Generated by <a href="https://github.com/chaitanyabhujbal912006-afk/reachguard" target="_blank">ReachGuard</a>
  &nbsp;·&nbsp; {scan_time}
</footer>

<!-- ── Embedded scan data ────────────────────────────────────────── -->
<script>
const SCAN_DATA = {scan_data_json};
</script>

<!-- ── Chart.js via CDN ──────────────────────────────────────────── -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
        crossorigin="anonymous"></script>

<!-- ── App logic ─────────────────────────────────────────────────── -->
<script>
"use strict";

// ── State ──────────────────────────────────────────────────────────
let activeFilter   = "all";
let activeSevFilter = null;
let sortCol        = -1;
let sortAsc        = true;

// ── Badge helpers ──────────────────────────────────────────────────
function statusBadge(s) {{
  const cls = {{REACHABLE:"reachable", UNKNOWN:"unknown", UNREACHABLE:"unreachable"}}[s] || "none";
  return `<span class="badge badge-${{cls}}">${{s}}</span>`;
}}
function severityBadge(s) {{
  if (!s || s === "-") return `<span class="badge badge-none">—</span>`;
  const cls = s.toLowerCase();
  return `<span class="badge badge-${{cls}}">${{s}}</span>`;
}}

// ── Render ─────────────────────────────────────────────────────────
function renderFindings(data) {{
  const tbody = document.getElementById("findingsBody");
  const empty = document.getElementById("emptyState");

  if (!data.length) {{
    tbody.innerHTML = "";
    empty.style.display = "block";
    return;
  }}
  empty.style.display = "none";

  tbody.innerHTML = data.map((f, idx) => {{
    let details = `<div class="summary-cell">${{escHtml(f.summary)}}</div>`;

    if (f.call_path && f.call_path.length) {{
      const chain = f.call_path.map(n => n.includes(".") ? n.split(".").pop() : n).join(" → ");
      details += `
        <button class="detail-toggle" onclick="toggleDetail(${{idx}})">
          <span>▶</span> Call path
        </button>
        <div class="detail-content" id="detail-${{idx}}">${{escHtml(chain)}}</div>`;
    }}

    if (f.suggested_fix) {{
      details += `
        <span class="fix-label">Suggested fix:</span>
        <span class="fix-pill">${{escHtml(f.suggested_fix)}}</span>`;
    }}

    return `<tr
      data-status="${{f.status}}"
      data-severity="${{f.severity}}"
      data-search="${{[f.package, f.version, f.cve_id, f.summary].join(" ").toLowerCase()}}"
    >
      <td class="pkg-cell">${{escHtml(f.package)}}<br/><span style="color:var(--text-muted);font-size:.75rem">${{escHtml(f.version)}}</span></td>
      <td><a class="cve-link" href="https://osv.dev/vulnerability/${{encodeURIComponent(f.cve_id)}}" target="_blank" rel="noopener">${{escHtml(f.cve_id)}}</a></td>
      <td>${{severityBadge(f.severity)}}</td>
      <td>${{statusBadge(f.status)}}</td>
      <td>${{details}}</td>
    </tr>`;
  }}).join("");
}}

function escHtml(str) {{
  if (!str) return "";
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}}

function toggleDetail(idx) {{
  const el  = document.getElementById(`detail-${{idx}}`);
  const btn = el.previousElementSibling.querySelector("span");
  if (el.style.display === "block") {{
    el.style.display = "none";
    btn.textContent  = "▶";
  }} else {{
    el.style.display = "block";
    btn.textContent  = "▼";
  }}
}}

// ── Filtering ──────────────────────────────────────────────────────
function applyFilters() {{
  const q = document.getElementById("searchInput").value.toLowerCase();
  let data = SCAN_DATA.findings;

  if (activeFilter !== "all") data = data.filter(f => f.status === activeFilter);
  if (activeSevFilter)        data = data.filter(f => f.severity === activeSevFilter);
  if (q)                      data = data.filter(f =>
    [f.package, f.version, f.cve_id, f.summary].join(" ").toLowerCase().includes(q)
  );
  renderFindings(data);
}}

function setFilter(f) {{
  activeFilter = f;
  activeSevFilter = null;
  document.querySelectorAll(".filter-btn").forEach(b => {{
    b.classList.remove("active", "active-red");
  }});
  const btn = document.getElementById(`btn-${{f}}`);
  if (btn) {{
    btn.classList.add(f === "REACHABLE" ? "active-red" : "active");
  }}
  applyFilters();
}}

function setSeverityFilter(s) {{
  activeSevFilter = activeSevFilter === s ? null : s;
  activeFilter    = "all";
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active","active-red"));
  if (activeSevFilter) {{
    // Only highlight severity button; leave "All" unhighlighted to avoid confusion
    const btn = document.getElementById(`btn-${{s}}`);
    if (btn) btn.classList.add("active-red");
  }} else {{
    // Cleared — restore "All" as active
    document.getElementById("btn-all").classList.add("active");
  }}
  applyFilters();
}}

// ── Sorting ────────────────────────────────────────────────────────
function sortTable(col) {{
  if (sortCol === col) {{ sortAsc = !sortAsc; }}
  else {{ sortCol = col; sortAsc = true; }}

  document.querySelectorAll(".findings-table th").forEach((th, i) => {{
    th.classList.toggle("sorted", i === col);
    const arrow = th.querySelector(".sort-arrow");
    if (arrow) arrow.textContent = i === col ? (sortAsc ? "↑" : "↓") : "↕";
  }});

  const keys = ["package", "cve_id", "severity", "status"];
  const key  = keys[col];
  const data = [...SCAN_DATA.findings].sort((a, b) => {{
    const av = (a[key] || "").toLowerCase();
    const bv = (b[key] || "").toLowerCase();
    return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  renderFindings(data);
}}

// ── Charts ─────────────────────────────────────────────────────────
function initCharts() {{
  const chartDefaults = {{
    plugins: {{ legend: {{ labels: {{ color: "#8b949e", font: {{ size: 12 }} }} }} }},
  }};

  // Donut
  new Chart(document.getElementById("donutChart"), {{
    type: "doughnut",
    data: {{
      labels: ["Reachable", "Unknown", "Unreachable"],
      datasets: [{{
        data: [SCAN_DATA.reachable, SCAN_DATA.unknown, SCAN_DATA.unreachable],
        backgroundColor: ["rgba(248,81,73,.8)", "rgba(210,153,34,.8)", "rgba(63,185,80,.7)"],
        borderColor:     ["#f85149", "#d29922", "#3fb950"],
        borderWidth: 2,
        hoverOffset: 8,
      }}],
    }},
    options: {{
      ...chartDefaults,
      cutout: "68%",
      plugins: {{
        ...chartDefaults.plugins,
        legend: {{ position: "bottom", labels: {{ color: "#8b949e", padding: 16, font: {{ size: 11 }} }} }},
      }},
      animation: {{ animateRotate: true, duration: 700 }},
    }},
  }});

  // Bar
  const sevLabels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const sevCounts = sevLabels.map(s => SCAN_DATA.findings.filter(f => f.severity === s).length);
  new Chart(document.getElementById("barChart"), {{
    type: "bar",
    data: {{
      labels: sevLabels,
      datasets: [{{
        label: "CVEs",
        data: sevCounts,
        backgroundColor: [
          "rgba(255,68,68,.75)",
          "rgba(248,81,73,.65)",
          "rgba(210,153,34,.65)",
          "rgba(63,185,80,.6)",
        ],
        borderColor: ["#ff4444","#f85149","#d29922","#3fb950"],
        borderWidth: 2,
        borderRadius: 6,
      }}],
    }},
    options: {{
      ...chartDefaults,
      indexAxis: "x",
      scales: {{
        x: {{ ticks: {{ color: "#8b949e" }}, grid: {{ color: "rgba(48,54,61,.6)" }} }},
        y: {{ ticks: {{ color: "#8b949e", precision: 0 }}, grid: {{ color: "rgba(48,54,61,.6)" }} }},
      }},
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{ callbacks: {{ label: ctx => ` ${{ctx.parsed.y}} CVE(s)` }} }},
      }},
      animation: {{ duration: 700 }},
    }},
  }});
}}

// ── Boot ───────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {{
  renderFindings(SCAN_DATA.findings);
  if (typeof Chart !== "undefined") {{
    initCharts();
  }} else {{
    // CDN unavailable — hide chart area gracefully
    document.querySelector(".charts-row").style.display = "none";
  }}
}});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

import base64

def _get_logo_img_tag() -> str:
    """Return an HTML <img> tag embedding base64 logo.png if present."""
    candidates = [
        Path("logo.png"),
        Path(__file__).parent.parent / "logo.png",
        Path(__file__).parent / "logo.png",
    ]
    for p in candidates:
        if p.exists():
            try:
                b64 = base64.b64encode(p.read_bytes()).decode("utf-8")
                return (
                    f'<img src="data:image/png;base64,{b64}" alt="ReachGuard Logo" '
                    'style="height:44px;width:auto;border-radius:6px;'
                    'filter:drop-shadow(0 2px 8px rgba(0,0,0,0.5));" />'
                )
            except Exception:
                pass
    return ""


def generate_html_report(
    findings: list[Finding],
    requirements_path: str = "requirements.txt",
) -> str:
    """Return a complete, self-contained HTML string for the given findings."""
    # Build JSON payload (mirrors write_json_output in cli.py)
    records = []
    for name, version, cve_id, summary, status, severity, call_path, fixed_version in findings:
        records.append({
            "package":       name,
            "version":       version,
            "cve_id":        cve_id,
            "summary":       summary,
            "status":        status.value,
            "severity":      severity if severity else "-",
            "call_path":     call_path,
            "fixed_version": fixed_version,
            "suggested_fix": f"pip install {name}>={fixed_version}" if fixed_version else None,
        })

    reachable_n   = sum(1 for r in records if r["status"] == "REACHABLE")
    unknown_n     = sum(1 for r in records if r["status"] == "UNKNOWN")
    unreachable_n = sum(1 for r in records if r["status"] == "UNREACHABLE")
    critical_n    = sum(1 for r in records if r["severity"] == "CRITICAL")

    scan_data = {
        "total":       len(records),
        "reachable":   reachable_n,
        "unknown":     unknown_n,
        "unreachable": unreachable_n,
        "findings":    records,
    }

    scan_target = Path(requirements_path).name
    scan_time   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return _HTML_TEMPLATE.format(
        scan_target    = scan_target,
        scan_time      = scan_time,
        total          = len(records),
        reachable      = reachable_n,
        unknown        = unknown_n,
        unreachable    = unreachable_n,
        critical       = critical_n,
        scan_data_json = json.dumps(scan_data, indent=2),
        logo_img_tag   = _get_logo_img_tag(),
    )


def write_html_report(
    findings: list[Finding],
    path: str,
    requirements_path: str = "requirements.txt",
) -> None:
    """Write a self-contained HTML report to *path*."""
    html = generate_html_report(findings, requirements_path=requirements_path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
