"""
Sample Secure Application for DuoGuard Zero-False-Positive Testing.
Demonstrates hardened code using proper sanitizers and parameterized queries.
"""

import os
import shlex
import sqlite3
import subprocess
import json

# Secure secret lookup via environment variable
AWS_SECRET = os.environ.get("AWS_ACCESS_KEY_ID")


def handle_user_command(user_input: str):
    # Secure command execution with shlex.quote and parameter array
    clean_input = shlex.quote(user_input)
    subprocess.run(["ping", "-c", "1", clean_input], check=True)


def handle_subproc_command(cmd_param: str):
    # Safe subprocess execution without shell=True
    subprocess.run(["echo", cmd_param], shell=False)


def lookup_user_record(cursor: sqlite3.Cursor, user_id: str):
    # Parameterized SQL query preventing SQLi
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def read_uploaded_file(filename_param: str):
    # Safe path handling using basename
    safe_name = os.path.basename(filename_param)
    safe_path = os.path.join("/var/data", safe_name)
    with open(safe_path, "r") as f:
        return f.read()


def restore_user_session(session_payload: str):
    # Safe JSON deserialization
    return json.loads(session_payload)
