"""
GitLab SAST Report Formatter (Schema v15.0.4).
Generates official GitLab-compliant `gl-sast-report.json` artifacts for native
GitLab Vulnerability Reports and Merge Request Security Dashboards.
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any
from duoguard.reachability import Finding
from duoguard.remediation import RemediationEngine


def generate_gitlab_sast_report(findings: List[Finding], target_root: Path) -> Dict[str, Any]:
    """Serializes findings into official GitLab SAST JSON specification v15.0.4."""
    now_iso = datetime.now(timezone.utc).isoformat()

    vulnerabilities = []
    remediations_list = []

    for f in findings:
        # Determine relative path from repo root
        try:
            rel_file = str(Path(f.file_path).relative_to(target_root))
        except ValueError:
            rel_file = Path(f.file_path).name

        # Stable fingerprint
        fingerprint_input = f"{f.cwe}:{rel_file}:{f.line_number}:{f.name}"
        vuln_id = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()

        # Extract numeric CWE ID
        cwe_num = "".join(filter(str.isdigit, f.cwe)) or "0"

        # Capitalize severity to GitLab spec: Critical, High, Medium, Low, Info
        sev_mapped = f.severity.capitalize()

        # Generate remediation diff
        remediation_meta = RemediationEngine.generate_fix(f)
        diff_base64 = ""
        if remediation_meta.get("diff"):
            import base64
            diff_base64 = base64.b64encode(remediation_meta["diff"].encode("utf-8")).decode("utf-8")

        vuln_entry = {
            "id": vuln_id,
            "category": "sast",
            "name": f.name,
            "message": f"{f.name}: {f.description}",
            "description": f.description,
            "cve": f.cwe,
            "severity": sev_mapped,
            "confidence": f.confidence,
            "scanner": {
                "id": "duoguard-ast",
                "name": "DuoGuard AST DevSecOps Agent"
            },
            "location": {
                "file": rel_file,
                "start_line": f.line_number,
                "end_line": f.line_number,
            },
            "identifiers": [
                {
                    "type": "cwe",
                    "name": f.cwe,
                    "value": cwe_num,
                    "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                }
            ],
            "solution": remediation_meta.get("explanation", ""),
            "cvss_vectors": [
                {
                    "vendor": "GitLab DuoGuard",
                    "vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (Score: {f.cvss})"
                }
            ]
        }
        vulnerabilities.append(vuln_entry)

        if diff_base64:
            remediations_list.append({
                "fixes": [{"cve": f.cwe}],
                "summary": remediation_meta.get("explanation", "Automated code patch"),
                "diff": diff_base64
            })

    report = {
        "schema": "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.0.4/dist/sast-report-format.json",
        "version": "15.0.4",
        "vulnerabilities": vulnerabilities,
        "remediations": remediations_list,
        "scan": {
            "scanner": {
                "id": "duoguard-agent",
                "name": "DuoGuard Agentic DevSecOps",
                "version": "1.0.0",
                "vendor": {
                    "name": "DuoGuard DevSecOps Platform"
                }
            },
            "type": "sast",
            "status": "success",
            "start_time": now_iso,
            "end_time": now_iso,
        }
    }
    return report


def save_gitlab_sast_report(findings: List[Finding], target_root: Path, output_file: Path) -> None:
    """Save the report JSON to the specified path."""
    report = generate_gitlab_sast_report(findings, target_root)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
