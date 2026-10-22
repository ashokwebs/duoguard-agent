"""
Sample Vulnerable Application for DuoGuard Security Testing.
Contains intentional security flaws to evaluate AST taint detection and reachability.
"""

import os
import sqlite3
import subprocess
import pickle

# Hardcoded secret flaw (CWE-798)
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"


def handle_user_command(user_input: str):
    # Command Injection flaw (CWE-78)
    os.system("ping -c 1 " + user_input)


def handle_subproc_command(cmd_param: str):
    # Subprocess Shell=True flaw (CWE-78)
    subprocess.run(f"echo {cmd_param}", shell=True)


def lookup_user_record(cursor: sqlite3.Cursor, user_id: str):
    # SQL Injection flaw (CWE-89)
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)


def read_uploaded_file(filename_param: str):
    # Path Traversal flaw (CWE-22)
    with open("/var/data/" + filename_param, "r") as f:
        return f.read()


def restore_user_session(session_payload: bytes):
    # Insecure Deserialization flaw (CWE-502)
    return pickle.loads(session_payload)
