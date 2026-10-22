import pytest
from duoguard.ast_engine import analyze_python_ast

def test_ast_detects_command_injection():
    code = """
def run_action(user_cmd):
    import os
    os.system("echo " + user_cmd)
"""
    findings = analyze_python_ast(code)
    assert len(findings) >= 1
    f = findings[0]
    assert f.sink == "os.system"
    assert f.cwe == "CWE-78"
    assert f.source_var == "user_cmd"
    assert not f.is_sanitized

def test_ast_detects_subprocess_shell_true():
    code = """
import subprocess
def ping_host(host_param):
    subprocess.run(f"ping {host_param}", shell=True)
"""
    findings = analyze_python_ast(code)
    assert any(f.cwe == "CWE-78" for f in findings)

def test_ast_recognizes_sanitizers():
    code = """
import os
import shlex

def safe_run(user_cmd):
    clean = shlex.quote(user_cmd)
    os.system(clean)
"""
    findings = analyze_python_ast(code)
    # The finding should either be marked sanitized or not flagged as exploitable
    for f in findings:
        if f.source_var == "clean":
            assert f.is_sanitized is True
            assert f.sanitizer_used == "shlex.quote"

def test_ast_detects_sqli():
    code = """
def query_db(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
"""
    findings = analyze_python_ast(code)
    assert any(f.cwe == "CWE-89" for f in findings)
