"""FastAPI backend and web dashboard for the Linux Security Auditor."""

from datetime import datetime, timezone
from html import escape

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
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#101827">
  <title>Linux Security Auditor</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b1120;
      --panel: #141e30;
      --panel2: #1b2940;
      --border: #2a3a53;
      --text: #e8eef8;
      --muted: #a4b2c8;
      --blue: #60a5fa;
      --green: #34d399;
      --red: #f87171;
      --yellow: #fbbf24;
      --gray: #cbd5e1;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, BlinkMacSystemFont,
                   "Segoe UI", sans-serif;
      line-height: 1.6;
    }

    .container {
      width: min(1120px, 94%);
      margin: 0 auto;
      padding: 32px 0 48px;
    }

    header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      margin-bottom: 28px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .logo {
      display: grid;
      place-items: center;
      width: 52px;
      height: 52px;
      background: #203c62;
      border: 1px solid #365984;
      border-radius: 14px;
      font-size: 25px;
    }

    h1, h2, h3, p { margin-top: 0; }
    h1 { font-size: clamp(22px, 4vw, 32px); margin-bottom: 3px; }
    h2 { font-size: 21px; }
    h3 { font-size: 16px; }

    .muted { color: var(--muted); }
    .subtitle { margin: 0; color: var(--muted); }

    .version {
      border: 1px solid var(--border);
      background: var(--panel);
      border-radius: 20px;
      padding: 6px 12px;
      color: var(--blue);
      font-size: 13px;
      font-weight: 700;
    }

    .hero {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      padding: 26px;
      margin-bottom: 22px;
      border: 1px solid var(--border);
      border-radius: 18px;
      background: linear-gradient(120deg, #172942, #141e30);
    }

    .hero p { margin-bottom: 0; max-width: 660px; }

    button {
      padding: 12px 20px;
      border: 0;
      border-radius: 9px;
      background: #3b82f6;
      color: white;
      font-weight: 700;
      font-size: 14px;
      cursor: pointer;
    }

    button:hover { background: #2563eb; }
    button:disabled { opacity: .6; cursor: wait; }

    .grid {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }

    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 19px;
      min-width: 0;
    }

    .card-label {
      color: var(--muted);
      font-size: 13px;
      margin-bottom: 8px;
    }

    .card-value { font-size: 32px; font-weight: 800; line-height: 1.2; }
    .c-blue { color: var(--blue); }
    .c-green { color: var(--green); }
    .c-red { color: var(--red); }
    .c-yellow { color: var(--yellow); }
    .c-gray { color: var(--gray); }

    .section-heading {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: baseline;
      gap: 10px;
      margin-bottom: 14px;
    }

    .section-heading h2 { margin-bottom: 0; }

    #scanInfo { font-size: 13px; color: var(--muted); }

    .findings {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 15px;
    }

    .finding {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      overflow-wrap: anywhere;
    }

    .finding-top {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      margin-bottom: 12px;
    }

    .finding h3 { margin-bottom: 4px; }
    .check-id { font-size: 12px; color: var(--muted); }

    .badge {
      flex-shrink: 0;
      border-radius: 20px;
      padding: 4px 9px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .3px;
    }

    .status-pass { color: var(--green); background: #123b34; }
    .status-fail { color: var(--red); background: #49252e; }
    .status-review { color: var(--yellow); background: #49391b; }
    .status-unknown { color: var(--gray); background: #303b4d; }

    .severity {
      display: inline-block;
      margin-bottom: 12px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .5px;
      color: var(--muted);
    }

    .detail-label {
      font-size: 12px;
      font-weight: 800;
      color: var(--blue);
      text-transform: uppercase;
      letter-spacing: .5px;
      margin-bottom: 4px;
    }

    .detail {
      font-size: 14px;
      color: #d3deed;
      margin-bottom: 15px;
    }

    .empty {
      grid-column: 1 / -1;
      padding: 28px;
      border: 1px dashed var(--border);
      border-radius: 14px;
      text-align: center;
      color: var(--muted);
    }

    .notice {
      margin-top: 26px;
      padding: 17px 20px;
      border: 1px solid #66532a;
      background: #292416;
      border-radius: 12px;
      color: #f5dfaa;
      font-size: 13px;
    }

    footer {
      margin-top: 26px;
      padding-top: 18px;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      text-align: center;
    }

    a { color: var(--blue); }

    @media (max-width: 850px) {
      .grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }

    @media (max-width: 600px) {
      .container { padding-top: 20px; }
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .findings { grid-template-columns: 1fr; }
      .hero { padding: 20px; }
      .hero button { width: 100%; }
    }
  </style>
</head>
<body>
  <main class="container">
    <header>
      <div class="brand">
        <div class="logo" aria-hidden="true">🛡</div>
        <div>
          <h1>Linux Security Auditor</h1>
          <p class="subtitle">Linux Security Configuration Auditor</p>
        </div>
      </div>
      <span class="version" id="version">VERSION 0.3.0</span>
    </header>

    <section class="hero">
      <div>
        <h2>Security overview</h2>
        <p class="muted">
          Inspect selected Linux security settings, review evidence,
          and follow recommendations. Scans are read-only.
        </p>
      </div>
      <button id="scanButton" onclick="runScan()">Run security scan</button>
    </section>

    <section aria-label="Scan summary">
      <div class="grid">
        <div class="card">
          <div class="card-label">Total checks</div>
          <div class="card-value c-blue" id="total">—</div>
        </div>
        <div class="card">
          <div class="card-label">Passed</div>
          <div class="card-value c-green" id="pass">—</div>
        </div>
        <div class="card">
          <div class="card-label">Failed</div>
          <div class="card-value c-red" id="fail">—</div>
        </div>
        <div class="card">
          <div class="card-label">Review</div>
          <div class="card-value c-yellow" id="review">—</div>
        </div>
        <div class="card">
          <div class="card-label">Unknown</div>
          <div class="card-value c-gray" id="unknown">—</div>
        </div>
      </div>
    </section>

    <section>
      <div class="section-heading">
        <h2>Security findings</h2>
        <span id="scanInfo">No scan has been run yet.</span>
      </div>
      <div class="findings" id="findings" aria-live="polite">
        <div class="empty">
          Select “Run security scan” to inspect the available checks.
        </div>
      </div>
    </section>

    <div class="notice">
      <strong>Interpret results carefully.</strong>
      PASS means a specific check met its implemented criteria.
      REVIEW means further investigation is needed.
      UNKNOWN means the scanner could not verify the setting.
      These results do not guarantee that a system is secure.
    </div>

    <footer>
      Read-only checks ·
      <a href="/docs">API documentation</a> ·
      <a href="/api/health">Service health</a>
    </footer>
  </main>

  <script>
    function makeElement(tag, className, text) {
      const element = document.createElement(tag);
      if (className) element.className = className;
      if (text !== undefined) element.textContent = text;
      return element;
    }

    function addDetail(parent, label, value) {
      parent.appendChild(makeElement("div", "detail-label", label));
      parent.appendChild(makeElement("p", "detail", value || "No details provided."));
    }

    function renderFinding(item) {
      const card = makeElement("article", "finding");
      const top = makeElement("div", "finding-top");
      const heading = document.createElement("div");

      heading.appendChild(makeElement("h3", "", item.title));
      heading.appendChild(makeElement("div", "check-id", item.check_id));

      const status = String(item.status || "UNKNOWN").toUpperCase();
      const badge = makeElement(
        "span",
        "badge status-" + status.toLowerCase(),
        status
      );

      top.appendChild(heading);
      top.appendChild(badge);
      card.appendChild(top);

      card.appendChild(makeElement(
        "div",
        "severity",
        "SEVERITY: " + String(item.severity || "UNSPECIFIED").toUpperCase()
      ));

      addDetail(card, "Evidence", item.evidence);
      addDetail(card, "Recommendation", item.recommendation);

      return card;
    }

    async function runScan() {
      const button = document.getElementById("scanButton");
      const findings = document.getElementById("findings");
      const info = document.getElementById("scanInfo");

      button.disabled = true;
      button.textContent = "Scanning...";
      findings.replaceChildren(makeElement("div", "empty", "Running read-only security checks..."));
      info.textContent = "Scan in progress";

      try {
        const response = await fetch("/api/scan", { cache: "no-store" });
        if (!response.ok) {
          throw new Error("Scan request failed with HTTP " + response.status);
        }

        const data = await response.json();
        const summary = data.summary || {};

        document.getElementById("total").textContent = data.checks_run ?? 0;
        document.getElementById("pass").textContent = summary.pass ?? 0;
        document.getElementById("fail").textContent = summary.fail ?? 0;
        document.getElementById("review").textContent = summary.review ?? 0;
        document.getElementById("unknown").textContent = summary.unknown ?? 0;
        document.getElementById("version").textContent = "VERSION " + (data.version || "unknown");

        findings.replaceChildren();
        if (Array.isArray(data.findings) && data.findings.length) {
          for (const item of data.findings) {
            findings.appendChild(renderFinding(item));
          }
        } else {
          findings.appendChild(makeElement("div", "empty", "The scan returned no findings."));
        }

        const time = data.scanned_at ? new Date(data.scanned_at).toLocaleString() : "time unavailable";
        info.textContent = "Last scan: " + time;
      } catch (error) {
        findings.replaceChildren(
          makeElement("div", "empty", "Could not complete the scan: " + error.message)
        );
        info.textContent = "Scan failed";
      } finally {
        button.disabled = false;
        button.textContent = "Run security scan again";
      }
    }
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

