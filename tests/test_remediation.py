import pytest
from pathlib import Path
from duoguard.reachability import Finding
from duoguard.remediation import RemediationEngine

def test_remediation_generation_for_secrets():
    finding = Finding(
        id="TEST-001",
        name="AWS Access Key",
        cwe="CWE-798",
        severity="CRITICAL",
        cvss=9.8,
        confidence="Confirmed",
        reachability=1.0,
        is_exploitable=True,
        file_path="app.py",
        line_number=2,
        column_offset=0,
        code_snippet='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        description="Hardcoded AWS key"
    )
    fix = RemediationEngine.generate_fix(finding, original_file_content='import os\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert "os.environ.get" in fix["replacement_code"]
    assert "```suggestion" in fix["gitlab_suggestion"]
    assert len(fix["diff"]) > 0

def test_remediation_generation_for_command_injection():
    finding = Finding(
        id="TEST-002",
        name="Command Injection",
        cwe="CWE-78",
        severity="CRITICAL",
        cvss=9.8,
        confidence="Confirmed",
        reachability=1.0,
        is_exploitable=True,
        file_path="app.py",
        line_number=5,
        column_offset=0,
        code_snippet='os.system("echo " + user_input)',
        description="Shell execution"
    )
    fix = RemediationEngine.generate_fix(finding)
    assert "subprocess.run" in fix["replacement_code"] or "shlex.quote" in fix["replacement_code"]

def test_apply_patch_to_file(tmp_path):
    test_file = tmp_path / "target.py"
    test_file.write_text('key = "AKIA1111111111111111"\nprint(key)\n', encoding="utf-8")

    success = RemediationEngine.apply_patch_to_file(
        test_file,
        line_number=1,
        replacement_code='key = os.environ.get("AWS_KEY")'
    )
    assert success is True
    updated = test_file.read_text(encoding="utf-8")
    assert 'key = os.environ.get("AWS_KEY")' in updated
