"""
Vulnerability and Secret Patterns for Multi-Language Analysis in DuoGuard.
Maps findings to official CWE identifiers and standard CVSS 3.1 base metrics.
"""

import re
from typing import List, Dict, Any

VULNERABILITY_CATALOG: List[Dict[str, Any]] = [
    # 1. Hardcoded Secrets (CWE-798)
    {
        "id": "DUO-SEC-001",
        "name": "Hardcoded Private Key",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "exts": {".py", ".ts", ".js", ".json", ".env", ".yaml", ".yml", ".rs", ".go"},
        "description": "Cryptographic private key found embedded in source code, risking credential compromise.",
    },
    {
        "id": "DUO-SEC-002",
        "name": "GitLab Personal Access Token",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "regex": re.compile(r"\bglpat-[0-9a-zA-Z\-_]{20,}\b"),
        "exts": {".py", ".ts", ".js", ".json", ".env", ".yaml", ".yml", ".rs", ".go"},
        "description": "GitLab Personal Access Token (glpat) committed in code, granting unauthorized API control.",
    },
    {
        "id": "DUO-SEC-003",
        "name": "AWS Access Key ID",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "exts": {".py", ".ts", ".js", ".json", ".env", ".yaml", ".yml"},
        "description": "AWS IAM Access Key exposed directly in code.",
    },
    {
        "id": "DUO-SEC-004",
        "name": "High-Entropy API Secret Assignment",
        "cwe": "CWE-798",
        "severity": "HIGH",
        "cvss": 7.5,
        "regex": re.compile(r"""(?:api_key|secret_key|auth_token|client_secret)\s*=\s*['"][A-Za-z0-9_\-]{24,}['"]""", re.IGNORECASE),
        "exts": {".py", ".ts", ".js", ".rs", ".go"},
        "description": "High-entropy secret token assigned directly to variable without environment variable lookup.",
    },

    # 2. Command Injection (CWE-78)
    {
        "id": "DUO-INJ-001",
        "name": "Command Injection via Shell Execution",
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "regex": re.compile(r"""(?:subprocess\.(?:Popen|run|call|check_output)\s*\([^)]*shell\s*=\s*True|os\.system\s*\()"""),
        "exts": {".py"},
        "description": "Unescaped command execution invoking system shell, allowing arbitrary remote code execution.",
    },
    {
        "id": "DUO-INJ-002",
        "name": "Node.js Child Process Command Injection",
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "regex": re.compile(r"""\b(?:exec|execSync)\s*\(\s*`[^`]*\${"""),
        "exts": {".ts", ".js"},
        "description": "Interpolated template literal passed to Node.js child_process exec without parameter isolation.",
    },

    # 3. SQL Injection (CWE-89)
    {
        "id": "DUO-SQL-001",
        "name": "SQL Injection via Unparameterized Query",
        "cwe": "CWE-89",
        "severity": "HIGH",
        "cvss": 8.8,
        "regex": re.compile(r"""(?:execute|raw|query)\s*\(\s*(?:f['"]|['"].*%|['"].*\+).*?(?:SELECT|INSERT|UPDATE|DELETE|FROM)""", re.IGNORECASE),
        "exts": {".py", ".ts", ".js"},
        "description": "Raw SQL query formatted with string concatenation or f-strings instead of parameterized arguments.",
    },

    # 4. Path Traversal (CWE-22)
    {
        "id": "DUO-PATH-001",
        "name": "Path Traversal via Unvalidated File Path",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "cvss": 7.5,
        "regex": re.compile(r"""(?:open|readFile|readFileSync|createReadStream)\s*\([^)]*(?:req\.|params|filename|user_path)"""),
        "exts": {".py", ".ts", ".js"},
        "description": "User-controllable input supplied directly to file system operations without canonicalization.",
    },
    {
        "id": "DUO-PATH-002",
        "name": "Arbitrary File Overwrite via Archive Extraction (Zip Slip)",
        "cwe": "CWE-22",
        "severity": "CRITICAL",
        "cvss": 8.5,
        "regex": re.compile(r"""\.(?:extractall|extract)\s*\([^)]*\)"""),
        "exts": {".py"},
        "description": "Archive extraction without checking member filenames against directory traversal escapes (../).",
    },

    # 5. Insecure Deserialization (CWE-502)
    {
        "id": "DUO-SER-001",
        "name": "Insecure Deserialization via Python Pickle",
        "cwe": "CWE-502",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "regex": re.compile(r"""\bpickle\.(?:loads|load)\s*\("""),
        "exts": {".py"},
        "description": "Deserialization of untrusted data using Python pickle allows arbitrary bytecode execution.",
    },

    # 6. Dynamic Code Evaluation (CWE-94)
    {
        "id": "DUO-EVAL-001",
        "name": "Unsafe Dynamic Code Evaluation",
        "cwe": "CWE-94",
        "severity": "HIGH",
        "cvss": 8.6,
        "regex": re.compile(r"""\b(?:eval|exec)\s*\([^)]+\)"""),
        "exts": {".py", ".ts", ".js"},
        "description": "Dynamic evaluation of code strings allowing execution of arbitrary syntax.",
    },

    # 7. Server-Side Request Forgery / SSRF (CWE-918)
    {
        "id": "DUO-SSRF-001",
        "name": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "severity": "HIGH",
        "cvss": 8.6,
        "regex": re.compile(r"""(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post)|urllib\.request\.urlopen|fetch)\s*\([^)]*(?:target_url|user_url|url_param|req\.query)"""),
        "exts": {".py", ".ts", ".js"},
        "description": "Outbound HTTP request dispatched to user-supplied endpoint without host allowlisting.",
    },
]
