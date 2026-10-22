"""
Model Context Protocol (MCP) Server for GitLab Duo and Agentic Workflows.
Exposes AST taint scanning, reachability verification, and automated patching
as standard MCP tools over stdio JSON-RPC.
"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, List
from duoguard.reachability import ReachabilityAnalyzer, Finding
from duoguard.remediation import RemediationEngine
from duoguard.ast_engine import analyze_python_ast

TOOLS = [
    {
        "name": "duoguard_scan_path",
        "description": "Perform deep AST taint and secret scanning on a target file or project repository.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative file or directory path to scan."
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "duoguard_verify_reachability",
        "description": "Evaluate whether untrusted user parameters reach dangerous sinks (CWE-78, CWE-89, CWE-22, CWE-502) without sanitization.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "Python source code string to evaluate."
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "duoguard_generate_remediation",
        "description": "Generate an automated drop-in remediation patch and unified diff for a detected vulnerability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the target file."},
                "line_number": {"type": "integer", "description": "Line number of the finding."},
                "cwe": {"type": "string", "description": "CWE identifier (e.g. CWE-78, CWE-89, CWE-798)."},
                "code_snippet": {"type": "string", "description": "Original vulnerable line of code."}
            },
            "required": ["file_path", "line_number", "cwe", "code_snippet"]
        }
    },
    {
        "name": "duoguard_apply_patch",
        "description": "Safely apply a generated remediation fix to disk.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the target file to modify."},
                "line_number": {"type": "integer", "description": "Line number to replace."},
                "replacement_code": {"type": "string", "description": "Verified secure replacement code."}
            },
            "required": ["file_path", "line_number", "replacement_code"]
        }
    }
]


def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "duoguard_scan_path":
        target = Path(arguments.get("path", ".")).resolve()
        analyzer = ReachabilityAnalyzer(str(target))
        findings = analyzer.scan_path(target)
        return {
            "target": str(target),
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings]
        }

    elif name == "duoguard_verify_reachability":
        src = arguments.get("source_code", "")
        flows = analyze_python_ast(src)
        results = []
        for flow in flows:
            results.append({
                "sink": flow.sink,
                "source": flow.source_var,
                "line": flow.line,
                "is_sanitized": flow.is_sanitized,
                "sanitizer": flow.sanitizer_used,
                "cwe": flow.cwe,
                "severity": flow.severity,
            })
        return {"flows_evaluated": len(results), "flows": results}

    elif name == "duoguard_generate_remediation":
        file_path = Path(arguments.get("file_path", "")).resolve()
        content = file_path.read_text(encoding="utf-8") if file_path.is_file() else None
        finding = Finding(
            id="MCP-REQ-001",
            name="Requested Fix",
            cwe=arguments.get("cwe", "CWE-78"),
            severity="HIGH",
            cvss=8.0,
            confidence="Confirmed",
            reachability=1.0,
            is_exploitable=True,
            file_path=str(file_path),
            line_number=arguments.get("line_number", 1),
            column_offset=0,
            code_snippet=arguments.get("code_snippet", ""),
            description="Remediation request via MCP",
        )
        return RemediationEngine.generate_fix(finding, content)

    elif name == "duoguard_apply_patch":
        file_path = Path(arguments.get("file_path", "")).resolve()
        line_num = arguments.get("line_number", 1)
        replacement = arguments.get("replacement_code", "")
        success = RemediationEngine.apply_patch_to_file(file_path, line_num, replacement)
        return {"success": success, "file": str(file_path), "line": line_num}

    else:
        raise ValueError(f"Unknown MCP tool: {name}")


def run_mcp_server():
    """Run MCP JSON-RPC server over standard I/O."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        response: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}

        if method == "initialize":
            response["result"] = {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "duoguard-mcp-server",
                    "version": "1.0.0"
                }
            }
        elif method == "tools/list":
            response["result"] = {"tools": TOOLS}
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                content = handle_tool_call(tool_name, tool_args)
                response["result"] = {
                    "content": [{"type": "text", "text": json.dumps(content, indent=2)}]
                }
            except Exception as e:
                response["error"] = {"code": -32000, "message": str(e)}
        else:
            response["error"] = {"code": -32601, "message": f"Method {method} not supported"}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_mcp_server()
