import pytest
from pathlib import Path
from duoguard.reachability import ReachabilityAnalyzer
from duoguard.html_report import generate_html_report

FIXTURE_DIR = Path(__file__).parent.parent / "test-fixtures" / "sample_app"

def test_generate_html_report():
    analyzer = ReachabilityAnalyzer(str(FIXTURE_DIR))
    findings = analyzer.analyze_file(FIXTURE_DIR / "vulnerable_app.py")

    html_out = generate_html_report(findings, FIXTURE_DIR)
    assert "<!doctype html>" in html_out
    assert "DuoGuard Security Audit Dashboard" in html_out
    assert "Critical Findings" in html_out
    assert "remediation-box" in html_out
    assert "GitLab Duo" in html_out
