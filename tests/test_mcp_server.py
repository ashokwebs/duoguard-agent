import pytest
from pathlib import Path
from duoguard.mcp_server import handle_tool_call, TOOLS

FIXTURE_DIR = Path(__file__).parent.parent / "test-fixtures" / "sample_app"

def test_mcp_tools_declaration():
    assert len(TOOLS) == 4
    tool_names = [t["name"] for t in TOOLS]
    assert "duoguard_scan_path" in tool_names
    assert "duoguard_verify_reachability" in tool_names
    assert "duoguard_generate_remediation" in tool_names
    assert "duoguard_apply_patch" in tool_names

def test_mcp_scan_path_call():
    res = handle_tool_call("duoguard_scan_path", {"path": str(FIXTURE_DIR / "vulnerable_app.py")})
    assert res["findings_count"] > 0
    assert len(res["findings"]) > 0

def test_mcp_verify_reachability_call():
    src = "import os\ndef do_action(cmd):\n    os.system(cmd)"
    res = handle_tool_call("duoguard_verify_reachability", {"source_code": src})
    assert res["flows_evaluated"] >= 1
    flow = res["flows"][0]
    assert flow["cwe"] == "CWE-78"
    assert flow["is_sanitized"] is False

def test_mcp_generate_remediation_call():
    res = handle_tool_call(
        "duoguard_generate_remediation",
        {
            "file_path": "fake.py",
            "line_number": 1,
            "cwe": "CWE-78",
            "code_snippet": 'os.system("echo " + user_input)'
        }
    )
    assert "replacement_code" in res
    assert "gitlab_suggestion" in res
