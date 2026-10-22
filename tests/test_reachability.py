import pytest
from pathlib import Path
from duoguard.reachability import ReachabilityAnalyzer

FIXTURE_DIR = Path(__file__).parent.parent / "test-fixtures" / "sample_app"

def test_reachability_on_vulnerable_app():
    analyzer = ReachabilityAnalyzer(str(FIXTURE_DIR))
    vuln_path = FIXTURE_DIR / "vulnerable_app.py"
    findings = analyzer.analyze_file(vuln_path)

    # Should detect AWS secret, Command injection, Subprocess shell, SQLi, Path traversal, Pickle
    cwes = {f.cwe for f in findings}
    assert "CWE-798" in cwes  # Hardcoded secret
    assert "CWE-78" in cwes   # Command injection
    assert "CWE-89" in cwes   # SQL injection
    assert "CWE-22" in cwes   # Path traversal
    assert "CWE-502" in cwes  # Insecure deserialization

    # All flagged findings should have reachability > 0.7
    for f in findings:
        assert f.reachability >= 0.7
        assert f.is_exploitable is True

def test_reachability_on_safe_app_zero_false_positives():
    analyzer = ReachabilityAnalyzer(str(FIXTURE_DIR))
    safe_path = FIXTURE_DIR / "safe_app.py"
    findings = analyzer.analyze_file(safe_path)

    # In safe_app.py, shlex.quote, shell=False, parameterized SQL, os.environ, os.path.basename, and json.loads are used
    # Therefore, ZERO high-severity exploitable vulnerabilities should be reported!
    critical_and_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    assert len(critical_and_high) == 0, f"Expected 0 false positives, got: {critical_and_high}"
