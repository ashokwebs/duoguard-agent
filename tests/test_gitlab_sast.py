import pytest
import json
from pathlib import Path
from duoguard.reachability import ReachabilityAnalyzer
from duoguard.gitlab_sast import generate_gitlab_sast_report, save_gitlab_sast_report

FIXTURE_DIR = Path(__file__).parent.parent / "test-fixtures" / "sample_app"

def test_generate_gitlab_sast_schema():
    analyzer = ReachabilityAnalyzer(str(FIXTURE_DIR))
    findings = analyzer.analyze_file(FIXTURE_DIR / "vulnerable_app.py")

    report = generate_gitlab_sast_report(findings, FIXTURE_DIR)
    
    assert report["version"] == "15.0.4"
    assert "schema" in report
    assert "vulnerabilities" in report
    assert len(report["vulnerabilities"]) > 0

    vuln = report["vulnerabilities"][0]
    assert "id" in vuln
    assert vuln["category"] == "sast"
    assert "severity" in vuln
    assert "location" in vuln
    assert "identifiers" in vuln

def test_save_gitlab_sast_report(tmp_path):
    analyzer = ReachabilityAnalyzer(str(FIXTURE_DIR))
    findings = analyzer.analyze_file(FIXTURE_DIR / "vulnerable_app.py")

    out_file = tmp_path / "gl-sast-report.json"
    save_gitlab_sast_report(findings, FIXTURE_DIR, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["scan"]["type"] == "sast"
    assert data["scan"]["status"] == "success"
