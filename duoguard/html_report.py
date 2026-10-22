"""
Interactive HTML Executive Security Dashboard Formatter for DuoGuard.
Produces self-contained, responsive DevSecOps reports with filters,
reachability indicators, and GitLab Duo remediation diffs.
"""

import html
from pathlib import Path
from typing import List
from duoguard.reachability import Finding
from duoguard.remediation import RemediationEngine


def generate_html_report(findings: List[Finding], target_root: Path) -> str:
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    total = len(findings)

    finding_rows = []
    for idx, f in enumerate(findings, 1):
        try:
            rel = str(Path(f.file_path).relative_to(target_root))
        except ValueError:
            rel = Path(f.file_path).name

        sev_class = "sev-crit" if f.severity == "CRITICAL" else ("sev-high" if f.severity == "HIGH" else "sev-med")
        fix = RemediationEngine.generate_fix(f)

        escaped_code = html.escape(f.code_snippet)
        escaped_replacement = html.escape(fix["replacement_code"])
        escaped_explanation = html.escape(fix["explanation"])

        row_html = f"""
        <div class="card finding-card {sev_class}" data-severity="{f.severity}">
          <div class="card-header">
            <div class="card-title">
              <span class="badge {sev_class}">{f.severity}</span>
              <span class="vuln-name">{html.escape(f.name)}</span>
              <span class="cwe-pill">{html.escape(f.cwe)}</span>
            </div>
            <div class="reachability-pill">Reachability: {int(f.reachability * 100)}% ({html.escape(f.confidence)})</div>
          </div>
          <div class="location-bar">
            <span>File: <code>{html.escape(rel)}</code></span>
            <span>Line: <strong>{f.line_number}</strong></span>
            <span>CVSS Score: <strong>{f.cvss}</strong></span>
          </div>
          <div class="code-preview">
            <div class="code-label">Vulnerable Sink Expression:</div>
            <pre><code>{escaped_code}</code></pre>
          </div>
          <div class="remediation-box">
            <div class="remediation-title">🦊 GitLab Duo Suggested Remediation:</div>
            <p class="remediation-desc">{escaped_explanation}</p>
            <pre class="patch"><code>{escaped_replacement}</code></pre>
          </div>
        </div>
        """
        finding_rows.append(row_html)

    body_rows = "\n".join(finding_rows) if finding_rows else "<div class='empty-state'>✅ Zero security vulnerabilities detected! Codebase is production clean.</div>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DuoGuard DevSecOps Executive Security Report</title>
<style>
  :root {{
    --bg: #070a12;
    --card: #0d1222;
    --card-border: #1e293b;
    --text: #f1f5f9;
    --muted: #94a3b8;
    --crit: #ef4444;
    --high: #f59e0b;
    --med: #06b6d4;
    --green: #10b981;
    --indigo: #6366f1;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: radial-gradient(circle at 50% 0%, #151d38, var(--bg));
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 32px 16px;
    min-height: 100vh;
  }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  header {{
    text-align: center;
    margin-bottom: 28px;
  }}
  h1 {{ font-size: 28px; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 6px; }}
  .subtitle {{ color: var(--muted); font-size: 14px; }}
  
  .scorecard {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }}
  .stat-card {{
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 16px;
    text-align: center;
  }}
  .stat-val {{ font-size: 28px; font-weight: 800; }}
  .stat-label {{ font-size: 11px; text-transform: uppercase; color: var(--muted); font-weight: 600; margin-top: 4px; }}

  .controls {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
    flex-wrap: wrap;
    gap: 8px;
  }}
  .filter-btn {{
    background: #0b101f;
    border: 1px solid var(--card-border);
    color: var(--muted);
    padding: 6px 14px;
    border-radius: 8px;
    font-size: 12px;
    cursor: pointer;
    transition: all 0.2s;
  }}
  .filter-btn.active {{
    background: var(--indigo);
    color: #fff;
    border-color: var(--indigo);
  }}

  .finding-card {{
    background: var(--card);
    border: 1px solid var(--card-border);
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 14px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
  }}
  .finding-card.sev-crit {{ border-left: 4px solid var(--crit); }}
  .finding-card.sev-high {{ border-left: 4px solid var(--high); }}
  .finding-card.sev-med {{ border-left: 4px solid var(--med); }}

  .card-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
    flex-wrap: wrap;
    gap: 8px;
  }}
  .card-title {{ display: flex; align-items: center; gap: 8px; }}
  .badge {{
    font-size: 10px;
    font-weight: 800;
    text-transform: uppercase;
    padding: 2px 8px;
    border-radius: 6px;
  }}
  .badge.sev-crit {{ background: rgba(239,68,68,0.2); color: var(--crit); }}
  .badge.sev-high {{ background: rgba(245,158,11,0.2); color: var(--high); }}
  .badge.sev-med {{ background: rgba(6,182,212,0.2); color: var(--med); }}
  .vuln-name {{ font-weight: 700; font-size: 15px; }}
  .cwe-pill {{ font-family: monospace; font-size: 11px; background: #1e293b; padding: 2px 6px; border-radius: 4px; color: var(--muted); }}
  .reachability-pill {{ font-size: 11px; color: var(--green); font-weight: 600; background: rgba(16,185,129,0.1); padding: 4px 10px; border-radius: 999px; }}

  .location-bar {{
    font-size: 12px;
    color: var(--muted);
    display: flex;
    gap: 16px;
    margin-bottom: 12px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    padding-bottom: 8px;
  }}
  code {{ font-family: "JetBrains Mono", Consolas, monospace; color: #a5b4fc; }}
  pre {{
    background: #05070e;
    border: 1px solid #172033;
    padding: 10px 14px;
    border-radius: 8px;
    overflow-x: auto;
    font-size: 12px;
    margin-top: 4px;
  }}
  .code-label {{ font-size: 11px; color: var(--muted); font-weight: 600; margin-top: 6px; }}
  
  .remediation-box {{
    margin-top: 14px;
    background: rgba(99,102,241,0.06);
    border: 1px dashed rgba(99,102,241,0.3);
    border-radius: 10px;
    padding: 12px;
  }}
  .remediation-title {{ font-size: 12px; font-weight: 700; color: #818cf8; margin-bottom: 4px; }}
  .remediation-desc {{ font-size: 12px; color: var(--muted); margin-bottom: 6px; }}
  pre.patch {{ background: #080c18; border-color: rgba(99,102,241,0.4); color: #34d399; }}

  footer {{
    text-align: center;
    color: var(--muted);
    font-size: 11px;
    margin-top: 36px;
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🦊 DuoGuard Security Audit Dashboard</h1>
    <div class="subtitle">Autonomous AST Taint Tracking & Exploitability Analysis · Powered by GitLab Duo</div>
  </header>

  <div class="scorecard">
    <div class="stat-card">
      <div class="stat-val" style="color: var(--crit);">{crit_count}</div>
      <div class="stat-label">Critical Findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color: var(--high);">{high_count}</div>
      <div class="stat-label">High Findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color: var(--med);">{med_count}</div>
      <div class="stat-label">Medium Findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color: #fff;">{total}</div>
      <div class="stat-label">Total Verified Sinks</div>
    </div>
  </div>

  <div class="findings-list">
    {body_rows}
  </div>

  <footer>
    DuoGuard DevSecOps Agent · Official GitLab Transcend Hackathon Package 2026
  </footer>
</div>
</body>
</html>"""
