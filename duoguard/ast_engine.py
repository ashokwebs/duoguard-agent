"""
Deep AST-based Taint and Reachability Analysis Engine for Python.
Performs semantic flow tracking from sources through transformations to sinks,
distinguishing between sanitized and unescaped data flows.
"""

import ast
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, field

DANGEROUS_SINKS = {
    "os.system": {"cwe": "CWE-78", "severity": "CRITICAL", "name": "OS Command Execution"},
    "subprocess.Popen": {"cwe": "CWE-78", "severity": "CRITICAL", "name": "Subprocess Execution"},
    "subprocess.run": {"cwe": "CWE-78", "severity": "CRITICAL", "name": "Subprocess Execution"},
    "subprocess.call": {"cwe": "CWE-78", "severity": "CRITICAL", "name": "Subprocess Execution"},
    "subprocess.check_output": {"cwe": "CWE-78", "severity": "CRITICAL", "name": "Subprocess Execution"},
    "eval": {"cwe": "CWE-94", "severity": "HIGH", "name": "Code Evaluation"},
    "exec": {"cwe": "CWE-94", "severity": "HIGH", "name": "Code Execution"},
    "pickle.loads": {"cwe": "CWE-502", "severity": "CRITICAL", "name": "Pickle Deserialization"},
    "pickle.load": {"cwe": "CWE-502", "severity": "CRITICAL", "name": "Pickle Deserialization"},
    "yaml.load": {"cwe": "CWE-502", "severity": "HIGH", "name": "YAML Deserialization"},
    "execute": {"cwe": "CWE-89", "severity": "HIGH", "name": "SQL Execution Sink"},
    "cursor.execute": {"cwe": "CWE-89", "severity": "HIGH", "name": "SQL Execution Sink"},
    "open": {"cwe": "CWE-22", "severity": "HIGH", "name": "File Open Sink"},
}

KNOWN_SANITIZERS = {
    "shlex.quote",
    "quote",
    "int",
    "float",
    "re.escape",
    "os.path.basename",
    "basename",
    "secure_filename",
    "Path.name",
    "html.escape",
    "escape",
}

TAINT_SOURCE_KEYWORDS = {
    "user", "input", "req", "request", "arg", "param", "payload", "cmd", "filename", "path", "query", "url"
}


@dataclass
class TaintFlowFinding:
    sink: str
    source_var: str
    line: int
    col: int
    cwe: str
    severity: str
    name: str
    is_sanitized: bool
    sanitizer_used: Optional[str] = None
    propagation_path: List[str] = field(default_factory=list)
    code_snippet: str = ""


class PythonASTTaintAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code: str, filename: str = "<unknown>"):
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.filename = filename
        self.tainted_vars: Set[str] = set()
        self.sanitized_vars: Dict[str, str] = {}  # var_name -> sanitizer_name
        self.findings: List[TaintFlowFinding] = []

    def _get_call_name(self, node: ast.Call) -> str:
        """Resolve dotted or simple call function name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            val_name = ""
            if isinstance(node.func.value, ast.Name):
                val_name = node.func.value.id
            elif isinstance(node.func.value, ast.Attribute):
                # e.g., os.path.basename
                sub = node.func.value
                if isinstance(sub.value, ast.Name):
                    val_name = f"{sub.value.id}.{sub.attr}"
            return f"{val_name}.{node.func.attr}" if val_name else node.func.attr
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Scan function parameters for potential taint sources
        for arg in node.args.args:
            name_lower = arg.arg.lower()
            if any(k in name_lower for k in TAINT_SOURCE_KEYWORDS):
                self.tainted_vars.add(arg.arg)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign):
        # Analyze right-hand side
        rhs = node.value

        # Check if RHS is a sanitizer call
        if isinstance(rhs, ast.Call):
            call_name = self._get_call_name(rhs)
            if call_name in KNOWN_SANITIZERS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.sanitized_vars[target.id] = call_name
                        self.tainted_vars.discard(target.id)
                self.generic_visit(node)
                return

            # If it is os.path.join and uses a sanitized var, mark target sanitized
            if call_name in ("os.path.join", "path.join"):
                has_sanitized = any(
                    isinstance(c, ast.Name) and c.id in self.sanitized_vars
                    for c in ast.walk(rhs)
                )
                if has_sanitized:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.sanitized_vars[target.id] = "os.path.join_with_sanitized"
                            self.tainted_vars.discard(target.id)
                    self.generic_visit(node)
                    return

        # Check if RHS propagates taint from an existing tainted var
        tainted_source = None
        for child in ast.walk(rhs):
            if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                tainted_source = child.id
                break

        if tainted_source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # If previously sanitized, keep sanitized unless re-contaminated without sanitizer
                    if target.id not in self.sanitized_vars:
                        self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node)

        # Check if call is a dangerous sink
        matched_sink = None
        for sink_key in DANGEROUS_SINKS:
            if call_name == sink_key or call_name.endswith(f".{sink_key}"):
                matched_sink = sink_key
                break

        if matched_sink:
            sink_meta = DANGEROUS_SINKS[matched_sink]

            # Check if subprocess has shell=True
            shell_true = False
            if matched_sink.startswith("subprocess"):
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True 
                    for kw in node.keywords
                )

            # Check arguments for tainted variables
            for arg_idx, arg in enumerate(node.args):
                tainted_names = [
                    child.id for child in ast.walk(arg) 
                    if isinstance(child, ast.Name) and (child.id in self.tainted_vars or child.id in self.sanitized_vars)
                ]

                # Special check for SQL injection
                is_sql_format = False
                is_parameterized_sql = False
                if matched_sink in ("execute", "cursor.execute"):
                    first_arg = node.args[0] if node.args else None
                    if isinstance(first_arg, ast.JoinedStr):
                        is_sql_format = True
                    elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Mod, ast.Add)):
                        is_sql_format = True
                    elif len(node.args) >= 2 and arg_idx >= 1:
                        # Tainted variable is passed as a bind parameter, not in the query string
                        is_parameterized_sql = True

                # Check subprocess list vs shell argument
                is_safe_subprocess_list = False
                if matched_sink.startswith("subprocess") and not shell_true:
                    if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                        is_safe_subprocess_list = True

                for t_name in tainted_names:
                    is_san = t_name in self.sanitized_vars
                    san_name = self.sanitized_vars.get(t_name)
                    
                    if is_parameterized_sql:
                        is_san = True
                        san_name = "parameterized_query"
                    elif is_sql_format:
                        is_san = False

                    if is_safe_subprocess_list:
                        is_san = True
                        san_name = "execve_array_isolation"

                    line_no = getattr(node, "lineno", 1)
                    col_offset = getattr(node, "col_offset", 0)
                    snippet = self.lines[line_no - 1].strip() if 0 < line_no <= len(self.lines) else ""

                    self.findings.append(
                        TaintFlowFinding(
                            sink=call_name,
                            source_var=t_name,
                            line=line_no,
                            col=col_offset,
                            cwe=sink_meta["cwe"],
                            severity=sink_meta["severity"],
                            name=sink_meta["name"],
                            is_sanitized=is_san,
                            sanitizer_used=san_name,
                            propagation_path=[t_name, call_name],
                            code_snippet=snippet,
                        )
                    )

            # Check keyword arguments (like shell=True explicitly)
            if matched_sink.startswith("subprocess") and shell_true:
                line_no = getattr(node, "lineno", 1)
                col_offset = getattr(node, "col_offset", 0)
                snippet = self.lines[line_no - 1].strip() if 0 < line_no <= len(self.lines) else ""
                self.findings.append(
                    TaintFlowFinding(
                        sink=call_name + "[shell=True]",
                        source_var="subprocess_args",
                        line=line_no,
                        col=col_offset,
                        cwe="CWE-78",
                        severity="CRITICAL",
                        name="Subprocess Shell Execution",
                        is_sanitized=False,
                        propagation_path=["shell=True"],
                        code_snippet=snippet,
                    )
                )

        self.generic_visit(node)


def analyze_python_ast(source_code: str, filename: str = "<unknown>") -> List[TaintFlowFinding]:
    """Parse and run AST taint analysis on Python source string."""
    try:
        tree = ast.parse(source_code, filename=filename)
    except SyntaxError:
        return []
    analyzer = PythonASTTaintAnalyzer(source_code, filename=filename)
    analyzer.visit(tree)
    return analyzer.findings
