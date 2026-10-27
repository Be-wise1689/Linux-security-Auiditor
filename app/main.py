"""FastAPI backend and modern web dashboard for the Linux Security Auditor."""

from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.scanner.checks import run_security_checks, SCANNER_VERSION

app = FastAPI(
    title="Linux Security Configuration Auditor",
    description=(
        "A read-only Linux security configuration scanner "
        "that reports evidence and recommendations."
    ),
    version=SCANNER_VERSION,
)


@app.get("/", response_class=HTMLResponse)
def homepage():
    """Serve the interactive security dashboard."""
    return r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#080d19">
<meta name="description" content="Linux Security Configuration Auditor dashboard">
<title>Sentinel | Linux Security Auditor</title>
<style>
:root {
  color-scheme: dark;
  --bg: #080d19;
  --panel: #101827;
  --panel2: #151f31;
  --border: #26344b;
  --text: #e8eef9;
  --muted: #94a3b8;
  --blue: #60a5fa;
  --cyan: #67e8f9;
  --green: #34d399;
  --red: #fb7185;
  --yellow: #fbbf24;
  --gray: #cbd5e1;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background:
    radial-gradient(ellipse at 15% 0%, #142647 0, transparent 35%),
    radial-gradient(ellipse at 95% 15%, #102b37 0, transparent 28%),
    var(--bg);
  color: var(--text);
  font: 14px/1.6 Inter, ui-sans-serif, system-ui, -apple-system,
        BlinkMacSystemFont, "Segoe UI", sans-serif;
}
button, input, select { font: inherit; }
button, select { cursor: pointer; }
button:focus-visible, input:focus-visible, select:focus-visible,
summary:focus-visible, a:focus-visible {
  outline: 2px solid var(--cyan);
  outline-offset: 3px;
}
.container { width: min(1240px, 94%); margin: auto; padding: 30px 0 45px; }
.topbar {
  display: flex; justify-content: space-between; align-items: center;
  gap: 18px; flex-wrap: wrap; margin-bottom: 28px;
}
.brand { display: flex; gap: 13px; align-items: center; }
.logo {
  width: 49px; height: 49px; display: grid; place-items: center;
  border-radius: 15px; font-size: 24px;
  background: linear-gradient(145deg, #1d4775, #122a46);
  border: 1px solid #32608d;
  box-shadow: 0 0 28px #2563eb25;
}
h1, h2, h3, p { margin-top: 0; }
h1 { font-size: clamp(21px, 3vw, 27px); letter-spacing: -.7px; margin-bottom: 0; }
h2 { font-size: 19px; letter-spacing: -.3px; margin-bottom: 4px; }
h3 { font-size: 15px; margin-bottom: 3px; }
.subtitle, .muted { color: var(--muted); }
.subtitle { margin: 2px 0 0; font-size: 12px; }
.top-right { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.pill {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 7px 11px; border: 1px solid var(--border);
  background: #101827cc; border-radius: 999px; color: var(--muted);
  font-size: 11px; font-weight: 700; letter-spacing: .3px;
}
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); }
.version { color: var(--blue); }
.hero {
  display: grid; grid-template-columns: minmax(0, 1fr) auto;
  align-items: center; gap: 24px; padding: 27px;
  border: 1px solid #2a4263; border-radius: 20px;
  background: linear-gradient(115deg, #14243bdf, #101827e8);
  box-shadow: 0 18px 55px #00000018; margin-bottom: 22px;
}
.eyebrow {
  color: var(--cyan); font-size: 10px; font-weight: 800;
  text-transform: uppercase; letter-spacing: 1.8px; margin-bottom: 8px;
}
.hero h2 { font-size: clamp(23px, 3.5vw, 31px); margin-bottom: 7px; }
.hero p { color: var(--muted); max-width: 650px; margin-bottom: 0; }
.hero-actions { display: flex; align-items: center; flex-direction: column; gap: 8px; }
.primary {
  display: inline-flex; justify-content: center; align-items: center; gap: 10px;
  padding: 12px 19px; color: #06111f; background: linear-gradient(110deg, #67e8f9, #60a5fa);
  border: 0; border-radius: 10px; font-weight: 800;
  box-shadow: 0 5px 22px #3b82f633; transition: transform .18s, filter .18s;
}
.primary:hover { transform: translateY(-2px); filter: brightness(1.08); }
.primary:disabled { opacity: .65; cursor: wait; transform: none; }
.scan-note { font-size: 10px; color: var(--muted); }
.spinner {
  display: none; width: 15px; height: 15px; border-radius: 50%;
  border: 2px solid #102c43; border-top-color: #e0f2fe;
  animation: spin .7s linear infinite;
}
.scanning .spinner { display: inline-block; }
@keyframes spin { to { transform: rotate(360deg); } }
.section-title {
  display: flex; justify-content: space-between; align-items: end;
  gap: 15px; flex-wrap: wrap; margin: 28px 0 13px;
}
.section-title h2 { margin-bottom: 2px; }
.section-title p { margin-bottom: 0; color: var(--muted); font-size: 12px; }
.summary {
  display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
}
.metric {
  position: relative; overflow: hidden; padding: 17px;
  background: linear-gradient(145deg, #131e30, #0e1625);
  border: 1px solid var(--border); border-radius: 14px;
  transition: transform .2s, border-color .2s;
}
.metric:hover { transform: translateY(-3px); border-color: #405777; }
.metric::before {
  content: ""; position: absolute; top: 0; left: 0; right: 0;
  height: 2px; background: var(--accent, var(--blue)); opacity: .8;
}
.metric-label { color: var(--muted); font-size: 11px; font-weight: 700; }
.metric-number { font-size: 31px; font-weight: 800; line-height: 1.35; margin-top: 5px; }
.metric-foot { color: #718096; font-size: 10px; margin-top: 3px; }
.blue { --accent: var(--blue); color: var(--blue); }
.green { --accent: var(--green); color: var(--green); }
.red { --accent: var(--red); color: var(--red); }
.yellow { --accent: var(--yellow); color: var(--yellow); }
.gray { --accent: #94a3b8; color: var(--gray); }
.panel {
  background: #101827d9; border: 1px solid var(--border);
  border-radius: 16px; padding: 19px;
}
.overview-grid {
  display: grid; grid-template-columns: minmax(0, 1.3fr) minmax(240px, .7fr);
  gap: 14px; margin-top: 14px;
}
.panel-heading {
  display: flex; justify-content: space-between; align-items: center;
  gap: 12px; margin-bottom: 17px;
}
.panel-heading h3 { margin: 0; }
.small-label { color: var(--muted); font-size: 11px; }
.bar-track {
  height: 9px; display: flex; overflow: hidden; border-radius: 99px;
  background: #263247; margin: 16px 0 13px;
}
.bar-segment { height: 100%; width: 0; transition: width .55s ease; }
.bar-pass { background: var(--green); }
.bar-fail { background: var(--red); }
.bar-review { background: var(--yellow); }
.bar-unknown { background: #94a3b8; }
.legend { display: flex; flex-wrap: wrap; gap: 13px; }
.legend-item { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 11px; }
.legend-dot { width: 7px; height: 7px; border-radius: 2px; }
.run-state {
  display: flex; gap: 12px; align-items: center; padding: 12px;
  border-radius: 11px; background: #0b1321; border: 1px solid #202e43;
}
.state-icon {
  flex: 0 0 38px; height: 38px; border-radius: 11px;
  display: grid; place-items: center; background: #19334c; color: var(--cyan);
  font-size: 18px;
}
.run-state strong { display: block; font-size: 12px; }
.run-state span { display: block; color: var(--muted); font-size: 11px; overflow-wrap: anywhere; }
.toolbar {
  display: grid; grid-template-columns: minmax(180px, 1.5fr) repeat(2, minmax(140px, .7fr));
  gap: 10px; margin-bottom: 14px;
}
.control {
  width: 100%; color: var(--text); background: #0b1321;
  border: 1px solid var(--border); border-radius: 9px; padding: 10px 12px;
}
.control::placeholder { color: #74839a; }
.control:focus { border-color: var(--blue); outline: none; }
.results-line {
  display: flex; justify-content: space-between; gap: 12px;
  flex-wrap: wrap; color: var(--muted); font-size: 11px; margin-bottom: 12px;
}
.findings { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 13px; }
.finding {
  min-width: 0; background: linear-gradient(145deg, #131e30, #0f1726);
  border: 1px solid var(--border); border-radius: 14px; overflow: hidden;
  transition: border-color .2s, transform .2s;
  animation: appear .25s ease both;
}
.finding:hover { border-color: #405777; transform: translateY(-2px); }
@keyframes appear { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
.finding-main { padding: 17px; }
.finding-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
.finding h3 { overflow-wrap: anywhere; }
.check-id { color: #72829a; font-size: 10px; font-weight: 700; letter-spacing: .4px; }
.badge {
  flex-shrink: 0; border-radius: 6px; padding: 4px 8px;
  font-size: 9px; font-weight: 900; letter-spacing: .6px;
}
.status-pass { color: var(--green); background: #12372e; border: 1px solid #1b5b49; }
.status-fail { color: var(--red); background: #3e1e2a; border: 1px solid #6c2b3c; }
.status-review { color: var(--yellow); background: #3b3017; border: 1px solid #665022; }
.status-unknown { color: var(--gray); background: #263244; border: 1px solid #3b4a60; }
.finding-meta { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 13px; }
.tag {
  color: var(--muted); border: 1px solid #2a394f; background: #0b1320;
  border-radius: 6px; padding: 3px 7px; font-size: 10px;
}
.tag strong { color: #d8e3f3; font-weight: 700; }
.finding details { border-top: 1px solid #26344b; }
.finding summary {
  list-style: none; display: flex; justify-content: space-between; gap: 10px;
  cursor: pointer; padding: 11px 17px; color: var(--blue); font-size: 11px; font-weight: 700;
}
.finding summary::-webkit-details-marker { display: none; }
.finding summary::after { content: "+"; font-size: 15px; line-height: 1; }
.finding details[open] summary::after { content: "−"; }
.detail-body { padding: 0 17px 16px; }
.detail-label {
  font-size: 9px; font-weight: 900; letter-spacing: 1px;
  color: var(--cyan); text-transform: uppercase; margin: 12px 0 4px;
}
.detail { color: #c1ccdc; font-size: 12px; margin: 0; overflow-wrap: anywhere; white-space: pre-wrap; }
.empty {
  grid-column: 1 / -1; text-align: center; padding: 34px 20px;
  color: var(--muted); background: #101827a8;
  border: 1px dashed #34445d; border-radius: 14px;
}
.empty strong { display: block; color: var(--text); font-size: 14px; margin-bottom: 5px; }
.notice {
  margin-top: 22px; display: flex; align-items: flex-start; gap: 12px;
  padding: 15px 17px; border: 1px solid #5d4b27;
  border-radius: 12px; background: #211d14; color: #e8d6a6;
  font-size: 11px;
}
.notice-icon { font-size: 17px; }
.notice strong { display: block; margin-bottom: 3px; }
footer {
  display: flex; justify-content: space-between; flex-wrap: wrap; gap: 12px;
  border-top: 1px solid var(--border); margin-top: 27px; padding-top: 17px;
  color: var(--muted); font-size: 11px;
}
footer a { color: var(--blue); text-decoration: none; }
footer a:hover { text-decoration: underline; }
[hidden] { display: none !important; }
@media (max-width: 900px) {
  .summary { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .overview-grid { grid-template-columns: 1fr; }
}
@media (max-width: 650px) {
  .container { width: 92%; padding-top: 20px; }
  .hero { grid-template-columns: 1fr; padding: 20px; }
  .hero-actions { align-items: stretch; }
  .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .findings { grid-template-columns: 1fr; }
  .toolbar { grid-template-columns: 1fr; }
  .topbar { align-items: flex-start; }
  .metric { padding: 14px; }
  .metric-number { font-size: 27px; }
  footer { flex-direction: column; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; scroll-behavior: auto !important; }
}
</style>
</head>
<body>
<main class="container">
  <header class="topbar">
    <div class="brand">
      <div class="logo" aria-hidden="true">🛡</div>
      <div>
        <h1>Linux Security Auditor</h1>
        <p class="subtitle">Configuration assessment · Evidence-based results</p>
      </div>
    </div>
    <div class="top-right">
      <span class="pill"><span class="dot"></span> SCANNER INTERFACE</span>
      <span class="pill version" id="version">VERSION loading</span>
    </div>
  </header>

  <section class="hero">
    <div>
      <div class="eyebrow">● Defensive security tool</div>
      <h2>Security overview</h2>
      <p>Review Linux security configuration, examine supporting evidence, and identify settings that need attention. Checks are read-only; results reflect only what the scanner can verify.</p>
    </div>
    <div class="hero-actions">
      <button class="primary" id="scanButton" type="button" onclick="runScan()">
        <span class="spinner" aria-hidden="true"></span>
        <span id="scanButtonText">↻ &nbsp; Run security scan</span>
      </button>
      <span class="scan-note">READ-ONLY · NO SETTINGS CHANGED</span>
    </div>
  </section>

  <div class="section-title">
    <div><h2>Assessment summary</h2><p>Results from the most recent scan</p></div>
    <span class="small-label" id="scanInfo">Waiting for first scan</span>
  </div>

  <section class="summary" aria-label="Scan summary">
    <article class="metric blue"><div class="metric-label">TOTAL CHECKS</div><div class="metric-number" id="total">—</div><div class="metric-foot">Checks executed</div></article>
    <article class="metric green"><div class="metric-label">PASSED</div><div class="metric-number" id="pass">—</div><div class="metric-foot">Criteria met</div></article>
    <article class="metric red"><div class="metric-label">FAILED</div><div class="metric-number" id="fail">—</div><div class="metric-foot">Criteria not met</div></article>
    <article class="metric yellow"><div class="metric-label">NEEDS REVIEW</div><div class="metric-number" id="review">—</div><div class="metric-foot">Investigate further</div></article>
    <article class="metric gray"><div class="metric-label">UNKNOWN</div><div class="metric-number" id="unknown">—</div><div class="metric-foot">Could not verify</div></article>
  </section>

  <section class="overview-grid" aria-label="Assessment visualization">
    <article class="panel">
      <div class="panel-heading"><h3>Finding distribution</h3><span class="small-label" id="distributionTotal">No data yet</span></div>
      <div class="bar-track" aria-label="Distribution of scan statuses">
        <div class="bar-segment bar-pass" id="barPass"></div>
        <div class="bar-segment bar-fail" id="barFail"></div>
        <div class="bar-segment bar-review" id="barReview"></div>
        <div class="bar-segment bar-unknown" id="barUnknown"></div>
      </div>
      <div class="legend">
        <span class="legend-item"><i class="legend-dot bar-pass"></i> Pass</span>
        <span class="legend-item"><i class="legend-dot bar-fail"></i> Fail</span>
        <span class="legend-item"><i class="legend-dot bar-review"></i> Review</span>
        <span class="legend-item"><i class="legend-dot bar-unknown"></i> Unknown</span>
      </div>
    </article>
    <article class="panel">
      <div class="panel-heading"><h3>Scanner status</h3><span class="small-label">SERVICE</span></div>
      <div class="run-state">
        <div class="state-icon" aria-hidden="true">⌁</div>
        <div><strong id="serviceState">Ready to scan</strong><span id="serviceDescription">Run a scan to retrieve current findings.</span></div>
      </div>
      <p class="small-label" style="margin:12px 0 0">API: <a href="/api/health" style="color:var(--cyan)">health endpoint</a> · <a href="/docs" style="color:var(--cyan)">API documentation</a></p>
    </article>
  </section>

  <section id="findingsSection">
    <div class="section-title">
      <div><h2>Security findings</h2><p>Search, filter, and inspect evidence and recommendations</p></div>
      <span class="small-label" id="resultCount">0 findings</span>
    </div>
    <div class="toolbar">
      <input class="control" id="searchInput" type="search" placeholder="⌕  Search title, ID, evidence..." aria-label="Search findings" disabled>
      <select class="control" id="statusFilter" aria-label="Filter by status" disabled>
        <option value="ALL">All statuses</option><option value="PASS">Pass</option>
        <option value="FAIL">Fail</option><option value="REVIEW">Review</option><option value="UNKNOWN">Unknown</option>
      </select>
      <select class="control" id="severityFilter" aria-label="Filter by severity" disabled>
        <option value="ALL">All severities</option><option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option><option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option><option value="INFO">Info</option>
      </select>
    </div>
    <div class="results-line"><span id="filterDescription">Run a scan to populate findings.</span><span>Expand any finding for details ↓</span></div>
    <div class="findings" id="findings" aria-live="polite">
      <div class="empty"><strong>Ready for assessment</strong>Select “Run security scan” to inspect available Linux security checks.</div>
    </div>
  </section>

  <aside class="notice">
    <span class="notice-icon" aria-hidden="true">ⓘ</span>
    <div><strong>Interpret results carefully</strong>
      PASS means a specific check met its implemented criteria. FAIL means the check detected a condition that did not meet its criteria. REVIEW indicates that further investigation is needed. UNKNOWN means the scanner could not verify the setting. These results do not guarantee that a system is secure.
    </div>
  </aside>

  <footer>
    <span>Linux Security Configuration Auditor · Defensive assessment tool</span>
    <span>Read-only checks · <a href="/docs">API docs</a> · <a href="/api/health">Service health</a></span>
  </footer>
</main>

<script>
"use strict";

let allFindings = [];
let scanCompleted = false;

function el(id) { return document.getElementById(id); }

function makeElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function addDetail(parent, label, value) {
  parent.appendChild(makeElement("div", "detail-label", label));
  parent.appendChild(makeElement("p", "detail", value || "No details provided."));
}

function renderFinding(item, index) {
  const card = makeElement("article", "finding");
  card.style.animationDelay = Math.min(index * 25, 250) + "ms";

  const main = makeElement("div", "finding-main");
  const top = makeElement("div", "finding-top");
  const heading = document.createElement("div");
  heading.appendChild(makeElement("div", "check-id", item.check_id || "CHECK"));
  heading.appendChild(makeElement("h3", "", item.title || "Untitled finding"));

  const status = String(item.status || "UNKNOWN").toUpperCase();
  const allowedStatuses = ["PASS", "FAIL", "REVIEW", "UNKNOWN"];
  const safeStatus = allowedStatuses.includes(status) ? status : "UNKNOWN";
  const badge = makeElement("span", "badge status-" + safeStatus.toLowerCase(), safeStatus);
  top.append(heading, badge);
  main.appendChild(top);

  const meta = makeElement("div", "finding-meta");
  meta.appendChild(makeTag("Severity", String(item.severity || "Unspecified").toUpperCase()));
  if (item.category) meta.appendChild(makeTag("Category", item.category));
  main.appendChild(meta);
  card.appendChild(main);

  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "View evidence & recommendation";
  details.appendChild(summary);
  const body = makeElement("div", "detail-body");
  addDetail(body, "Evidence", item.evidence);
  addDetail(body, "Recommendation", item.recommendation);
  details.appendChild(body);
  card.appendChild(details);

  return card;
}

function makeTag(label, value) {
  const tag = makeElement("span", "tag");
  tag.appendChild(makeElement("strong", "", label + ": "));
  tag.appendChild(document.createTextNode(String(value)));
  return tag;
}

function updateDistribution(summary, total) {
  const statuses = [
    ["Pass", summary.pass || 0],
    ["Fail", summary.fail || 0],
    ["Review", summary.review || 0],
    ["Unknown", summary.unknown || 0]
  ];
  const denominator = total > 0 ? total : 1;

  for (const [name, value] of statuses) {
    el("bar" + name).style.width = Math.max(0, Number(value) || 0) / denominator * 100 + "%";
  }
  el("distributionTotal").textContent = total + " checks assessed";
}

function populateSummary(data) {
  const summary = data.summary || {};
  const total = Number(data.checks_run ?? (data.findings || []).length) || 0;
  const normalized = {
    pass: Number(summary.pass) || 0,
    fail: Number(summary.fail) || 0,
    review: Number(summary.review) || 0,
    unknown: Number(summary.unknown) || 0
  };

  el("total").textContent = total;
  el("pass").textContent = normalized.pass;
  el("fail").textContent = normalized.fail;
  el("review").textContent = normalized.review;
  el("unknown").textContent = normalized.unknown;
  el("version").textContent = "VERSION " + (data.version || "unknown");
  updateDistribution(normalized, total);
}

function filterFindings() {
  const query = el("searchInput").value.trim().toLowerCase();
  const status = el("statusFilter").value;
  const severity = el("severityFilter").value.toUpperCase();

  const filtered = allFindings.filter(item => {
    const searchable = [
      item.title, item.check_id, item.evidence, item.recommendation,
      item.status, item.severity, item.category
    ].join(" ").toLowerCase();
    return (!query || searchable.includes(query))
      && (status === "ALL" || String(item.status || "UNKNOWN").toUpperCase() === status)
      && (severity === "ALL" || String(item.severity || "").toUpperCase() === severity);
  });

  const container = el("findings");
  container.replaceChildren();
  el("resultCount").textContent = filtered.length + " of " + allFindings.length + " findings";
  el("filterDescription").textContent = query || status !== "ALL" || severity !== "ALL"
    ? "Filtered results — adjust filters to broaden the list."
    : "Showing all findings from the latest scan.";

  if (!filtered.length) {
    const empty = makeElement("div", "empty");
    empty.appendChild(makeElement("strong", "", allFindings.length ? "No matching findings" : "No findings returned"));
    empty.appendChild(document.createTextNode(allFindings.length
      ? "Try another search term or change the filters."
      : "The scan returned no findings."));
    container.appendChild(empty);
    return;
  }

  filtered.forEach((item, index) => container.appendChild(renderFinding(item, index)));
}

function enableFilters() {
  ["searchInput", "statusFilter", "severityFilter"].forEach(id => el(id).disabled = false);
}

function setScanning(isScanning) {
  const button = el("scanButton");
  button.disabled = isScanning;
  button.classList.toggle("scanning", isScanning);
  el("scanButtonText").textContent = isScanning ? "Scanning system..." : "↻  Run security scan";
}

async function runScan() {
  setScanning(true);
  el("serviceState").textContent = "Assessment in progress";
  el("serviceDescription").textContent = "Running read-only checks against available configuration.";
  el("scanInfo").textContent = "Scan in progress…";
  el("findings").replaceChildren(makeElement("div", "empty", "Running security checks. Please wait…"));
  el("filterDescription").textContent = "Collecting scanner results…";

  try {
    const response = await fetch("/api/scan", {
      method: "GET",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });
    if (!response.ok) throw new Error("The scan endpoint returned HTTP " + response.status + ".");

    const data = await response.json();
    if (!Array.isArray(data.findings)) throw new Error("The scan response did not contain a findings list.");

    allFindings = data.findings;
    scanCompleted = true;
    populateSummary(data);
    enableFilters();
    filterFindings();

    const timestamp = data.scanned_at ? new Date(data.scanned_at) : null;
    const timeText = timestamp && !Number.isNaN(timestamp.getTime())
      ? timestamp.toLocaleString()
      : "time unavailable";
    el("scanInfo").textContent = "Last scan: " + timeText;
    el("serviceState").textContent = "Scan completed";
    el("serviceDescription").textContent = allFindings.length + " findings received from the scanner.";
  } catch (error) {
    el("serviceState").textContent = "Scan could not complete";
    el("serviceDescription").textContent = error.message || "An unexpected error occurred.";
    el("scanInfo").textContent = "Scan failed";
    const empty = makeElement("div", "empty");
    empty.appendChild(makeElement("strong", "", "Unable to retrieve scan results"));
    empty.appendChild(document.createTextNode(error.message || "Please check the application and try again."));
    el("findings").replaceChildren(empty);
  } finally {
    setScanning(false);
  }
}

el("searchInput").addEventListener("input", filterFindings);
el("statusFilter").addEventListener("change", filterFindings);
el("severityFilter").addEventListener("change", filterFindings);

// Check the API when the page loads; this does not run a security scan.
(async function checkService() {
  try {
    const response = await fetch("/api/health", { cache: "no-store" });
    if (!response.ok) throw new Error("Health endpoint returned HTTP " + response.status);
    const data = await response.json();
    if (data.status === "ok") {
      el("serviceState").textContent = "Service online · Ready";
      el("serviceDescription").textContent = "API is responding. Run a scan when ready.";
    } else {
      el("serviceState").textContent = "Service response received";
      el("serviceDescription").textContent = "Review the API health response.";
    }
  } catch (_) {
    el("serviceState").textContent = "Service status unavailable";
    el("serviceDescription").textContent = "The health endpoint could not be reached.";
  }
})();
</script>
</body>
</html>
    """


@app.get("/api/health")
def health():
    """Return basic service status."""
    return {
        "status": "ok",
        "service": "linux-security-auditor",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/scan")
def scan():
    """Run security checks and return structured findings."""
    result = run_security_checks()
    result["scanned_at"] = datetime.now(timezone.utc).isoformat()
    return result
