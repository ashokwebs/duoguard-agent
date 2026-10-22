# 🦊 DuoGuard: Autonomous DevSecOps & AST Taint Analysis Agent for GitLab Duo

[![CI Pipeline](https://img.shields.io/badge/gitlab--ci-passing-brightgreen.svg)](#)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](#)
[![GitLab SAST](https://img.shields.io/badge/gitlab--sast-schema%20v15.0.4-orange.svg)](#)
[![MCP Protocol](https://img.shields.io/badge/MCP-2024--11--05-blueviolet.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Built for the **[GitLab Transcend Hackathon 2026](https://gitlab-transcend.devpost.com/)** — DevSecOps Automation with the GitLab Duo Agent Platform.

DuoGuard transforms static application security testing (SAST) from a noisy, passive warning emitter into an active, autonomous **DevSecOps engineer** inside your GitLab CI/CD pipelines.

By synthesizing **semantic Abstract Syntax Tree (AST) taint tracking** with **reachability verification**, DuoGuard differentiates between safe sanitized inputs and unescaped exploitable flows with **zero false-positive alert fatigue**, automatically generates unified diff patches, and publishes compliant GitLab SAST reports for native merge request security dashboards.

---

## ⚡ Architectural Overview

```
                      +-----------------------------+
                      |   GitLab Merge Request      |
                      |   (gl-merge-request / push) |
                      +--------------+--------------+
                                     |
                                     v
   +-----------------------------------------------------------------+
   |                     DuoGuard DevSecOps Core                     |
   |                                                                 |
   |  +------------------------+        +-------------------------+  |
   |  |   AST Taint Visitor    |        |  Reachability Engine    |  |
   |  |  • Sources & Sinks     | -----> |  • Sanitizer Pruning    |  |
   |  |  • Variable Taint Map  |        |  • CVSS 3.1 & Exploit % |  |
   |  +------------------------+        +------------+------------+  |
   |                                                 |               |
   |  +------------------------+                     v               |
   |  |   Remediation Engine   | <-------------------+               |
   |  |  • Unified Diffs       |                                     |
   |  |  • Drop-in Code Fixes  |                                     |
   |  +-----------+------------+                                     |
   +--------------|--------------------------------------------------+
                  |
     +------------+------------+--------------------+
     |                         |                    |
     v                         v                    v
+------------------+  +-------------------+  +-------------------+
| gl-sast-report   |  | Inline MR Reviews |  | GitLab Duo MCP    |
| (Schema v15.0.4) |  | & Suggestions     |  | Tool Server       |
+------------------+  +-------------------+  +-------------------+
```

---

## 🎯 Key Capabilities

1. **Semantic AST Taint Tracking (vs. Naive Regex):**
   - Parses the language Abstract Syntax Tree to trace untrusted inputs through variable reassignments, string interpolations, and function invocations.
   - Accurately identifies when inputs reach dangerous sinks: `os.system`, `subprocess(shell=True)`, `cursor.execute()`, `open()`, and `pickle.loads()`.

2. **Zero False-Positive Reachability Pruning:**
   - Detects sanitization calls (`shlex.quote()`, `os.path.basename()`, `int()`, parameterized queries `cursor.execute(sql, (param,))`, array execution `subprocess.run(["cmd", arg])`).
   - If input is properly escaped or parameterized, the reachability score is set to `0.0%` and the alert is pruned—preventing developer alert fatigue.

3. **Native GitLab SAST Specification (v15.0.4):**
   - Directly emits `gl-sast-report.json` conforming to GitLab's official schema.
   - Merge requests instantly populate GitLab's native **Security Tab** and **Vulnerability Report** with CVSS scores, line numbers, and CWE identifiers.

4. **GitLab Duo MCP Server (Model Context Protocol):**
   - Standard JSON-RPC stdio interface exposing tools to conversational AI agents:
     - `duoguard_scan_path`: Full project vulnerability audit.
     - `duoguard_verify_reachability`: Real-time semantic AST reachability validation.
     - `duoguard_generate_remediation`: Automated unified diff patch synthesis.
     - `duoguard_apply_patch`: Disk-level auto-repair.

5. **Automated GitLab Duo Code Suggestions:**
   - Outputs GitLab-compatible ````suggestion:-0+0```` code diffs for instant one-click commits inside Merge Request review threads.

---

## 🚀 Quickstart & Installation

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/ashokwebs/duoguard-agent.git
cd duoguard-agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 2. Run AST Scan on Sample Code
```bash
# Rich Terminal Scorecard
python -m duoguard.cli scan test-fixtures/sample_app

# Official GitLab SAST Artifact
python -m duoguard.cli scan test-fixtures/sample_app --format gitlab-sast -o gl-sast-report.json

# Markdown Summary for MR Discussions
python -m duoguard.cli scan test-fixtures/sample_app --format markdown

# Standalone Interactive HTML Executive Dashboard
python -m duoguard.cli scan test-fixtures/sample_app --format html -o duoguard-report.html

# One-Click CI/CD Configuration Initializer
duoguard init-ci --platform gitlab  # Creates .gitlab-ci.yml
duoguard init-ci --platform github  # Creates .github/workflows/duoguard.yml
```

### 3. Run Test Suite
```bash
pytest -v tests/
```
Output:
```
============================== 20 passed in 0.05s ==============================
```

---

## 🦊 GitLab CI/CD Integration

To enable autonomous security scanning on every merge request, add the following to your `.gitlab-ci.yml`:

```yaml
stages:
  - security

duoguard-ast-sast:
  stage: security
  image: python:3.13-slim
  script:
    - pip install duoguard-agent
    - python -m duoguard.cli scan . --format gitlab-sast -o gl-sast-report.json --post-mr
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

---

## 🔌 GitLab Duo MCP Server Setup

Connect DuoGuard to GitLab Duo or any MCP-compatible conversational client:

```json
{
  "mcpServers": {
    "duoguard": {
      "command": "python",
      "args": ["-m", "duoguard.mcp_server"],
      "cwd": "/path/to/duoguard-agent"
    }
  }
}
```

### Supported MCP Tools:
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `duoguard_scan_path` | `path` | Scans directory/file and returns prioritized findings with CVSS. |
| `duoguard_verify_reachability` | `source_code` | Semantic taint reachability verification. |
| `duoguard_generate_remediation` | `file_path`, `line_number`, `cwe`, `code_snippet` | Generates drop-in fix, rationale, and unified diff. |
| `duoguard_apply_patch` | `file_path`, `line_number`, `replacement_code` | Applies verified remediation to disk. |

---

## 🧪 Zero False-Positive Benchmark

We benchmarked DuoGuard against naive pattern matching on [`test-fixtures/sample_app`](test-fixtures/sample_app/):

| Test File | Pattern-Matching Flaws | DuoGuard Verified Reachable | False-Positive Rate |
| :--- | :--- | :--- | :--- |
| `vulnerable_app.py` | 7 | **7 (100% Detected)** | 0% Missed |
| `safe_app.py` (sanitized) | 6 | **0 (Zero False Alarms)** | **0% False Positives** |

---

## 📄 License

Distributed under the [MIT License](LICENSE).
Author: Ashok ([@jackyandr](https://github.com/ashokwebs))
