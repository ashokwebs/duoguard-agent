"""
GitLab Merge Request Bot Commentary & Review Formatter.
Posts structured security reviews and inline code suggestions to GitLab MRs.
"""

import os
import urllib.request
import urllib.parse
import json
from typing import List, Dict, Any
from pathlib import Path
from duoguard.reachability import Finding
from duoguard.remediation import RemediationEngine


def format_mr_security_comment(findings: List[Finding], target_root: Path) -> str:
    """Format markdown summary for GitLab Merge Request discussion note."""
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    total = len(findings)

    status_icon = "🚨 **VULNERABILITIES DETECTED**" if total > 0 else "✅ **ALL SECURITY CHECKS PASSED**"
    
    md = [
        f"## 🦊 DuoGuard Agent Security Review — {status_icon}\n",
        f"> **Autonomous DevSecOps & AST Taint Analysis Summary**",
        f"> - **Critical Risk:** {crit_count} | **High Risk:** {high_count} | **Medium Risk:** {med_count} | **Total:** {total}\n",
    ]

    if total == 0:
        md.append("🎉 No security vulnerabilities, unescaped sinks, or hardcoded secrets were detected in this merge request.")
        return "\n".join(md)

    md.append("### 🔍 Prioritized Findings & Exploitability Analysis\n")
    md.append("| Severity | Finding | CWE | Location | Reachability |")
    md.append("| :--- | :--- | :--- | :--- | :--- |")

    for f in findings:
        try:
            rel = str(Path(f.file_path).relative_to(target_root))
        except ValueError:
            rel = Path(f.file_path).name
        
        sev_badge = f"**{f.severity}**"
        loc = f"`{rel}:{f.line_number}`"
        reach_badge = f"{int(f.reachability * 100)}% ({f.confidence})"
        md.append(f"| {sev_badge} | {f.name} | `{f.cwe}` | {loc} | {reach_badge} |")

    md.append("\n### 🛠️ Automated GitLab Duo Remediation Suggestions\n")

    for idx, f in enumerate(findings[:5], 1):
        try:
            rel = str(Path(f.file_path).relative_to(target_root))
        except ValueError:
            rel = Path(f.file_path).name

        fix = RemediationEngine.generate_fix(f)
        md.append(f"#### Finding #{idx}: {f.name} (`{rel}:{f.line_number}`)")
        md.append(f"*{f.description}*")
        md.append(f"\n**Suggested Fix:** {fix['explanation']}\n")
        md.append(f"```suggestion:-0+0\n{fix['replacement_code']}\n```\n")

    if len(findings) > 5:
        md.append(f"\n*... and {len(findings) - 5} additional findings logged to `gl-sast-report.json`.*\n")

    md.append("\n---\n*Report generated autonomously by [DuoGuard DevSecOps Agent](https://github.com/ashokwebs/duoguard-agent) powered by GitLab Duo.*")
    return "\n".join(md)


def post_to_gitlab_mr(comment_md: str) -> bool:
    """Post markdown commentary to GitLab MR API if running inside GitLab CI."""
    api_url = os.environ.get("CI_API_V4_URL")
    project_id = os.environ.get("CI_PROJECT_ID")
    mr_iid = os.environ.get("CI_MERGE_REQUEST_IID")
    token = os.environ.get("GITLAB_TOKEN") or os.environ.get("CI_JOB_TOKEN")

    if not (api_url and project_id and mr_iid and token):
        return False

    url = f"{api_url}/projects/{urllib.parse.quote_plus(project_id)}/merge_requests/{mr_iid}/notes"
    headers = {
        "JOB-TOKEN": token,
        "Content-Type": "application/json",
    }
    data = json.dumps({"body": comment_md}).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201)
    except Exception:
        return False
