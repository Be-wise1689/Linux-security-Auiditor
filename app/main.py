"""FastAPI backend for the Linux Security Configuration Auditor."""

from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.scanner.checks import run_security_checks

app = FastAPI(
    title="Linux Security Configuration Auditor",
    description=(
        "A read-only Linux security configuration scanner "
        "that reports evidence and recommendations."
    ),
    version="0.1.0",
)


@app.get("/", response_class=HTMLResponse)
def homepage():
    """Serve a simple initial dashboard."""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Linux Security Auditor</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          max-width: 900px;
          margin: 40px auto;
          padding: 0 18px;
          background: #f3f6fb;
          color: #172033;
        }
        section {
          background: white;
          padding: 24px;
          border-radius: 12px;
        }
        button {
          padding: 12px 18px;
          border: 0;
          border-radius: 7px;
          background: #174ea6;
          color: white;
          cursor: pointer;
        }
        pre {
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          background: #eef2f7;
          padding: 15px;
          border-radius: 8px;
        }
      </style>
    </head>
    <body>
      <h1>Linux Security Configuration Auditor</h1>
      <p>Inspect selected Linux security configurations.</p>
      <section>
        <h2>Security scan</h2>
        <p>
          The scanner uses read-only checks. Results may be unknown
          when the environment does not expose enough evidence.
        </p>
        <button onclick="runScan()">Run security scan</button>
        <p><a href="/docs">Open API documentation</a></p>
        <pre id="results">Ready to scan.</pre>
      </section>
      <script>
        async function runScan() {
          const output = document.getElementById("results");
          output.textContent = "Scanning...";
          try {
            const response = await fetch("/api/scan");
            if (!response.ok) {
              throw new Error("Request failed: " + response.status);
            }
            const data = await response.json();
            output.textContent = JSON.stringify(data, null, 2);
          } catch (error) {
            output.textContent = "Error: " + error.message;
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
