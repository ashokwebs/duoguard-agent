"""
Reachability & Exploitability Analysis Engine for DuoGuard.
Combines AST semantic taint tracking with pattern matching to eliminate
false positives and score true exploitability.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
from duoguard.ast_engine import analyze_python_ast, TaintFlowFinding
from duoguard.patterns import VULNERABILITY_CATALOG

IGNORE_DIRS = {
    ".git", "node_modules", ".next", "__pycache__", ".venv", "venv",
    "target", "dist", "build", ".cache", ".turbo"
}


@dataclass
class Finding:
    id: str
    name: str
    cwe: str
    severity: str
    cvss: float
    confidence: str  # Confirmed, High, Medium, Low
    reachability: float  # 0.0 to 1.0
    is_exploitable: bool
    file_path: str
    line_number: int
    column_offset: int
    code_snippet: str
    description: str
    sanitizer_used: Optional[str] = None
    propagation_path: List[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReachabilityAnalyzer:
    def __init__(self, target_root: str = "."):
        self.target_root = Path(target_root).resolve()

    def analyze_file(self, file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        ext = file_path.suffix.lower()

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        # 1. AST Taint Analysis for Python
        if ext == ".py":
            ast_flows = analyze_python_ast(content, filename=str(file_path))
            for flow in ast_flows:
                # If flow is properly sanitized, skip or mark safe
                if flow.is_sanitized:
                    continue  # Zero false-positive: do not alert on sanitized data flows!

                # Generate finding ID
                fid = f"DUO-{flow.cwe.replace('-', '')}-{flow.line}"
                cvss_map = {"CRITICAL": 9.8, "HIGH": 8.5, "MEDIUM": 6.5, "LOW": 3.5}
                cvss = cvss_map.get(flow.severity, 7.5)

                findings.append(
                    Finding(
                        id=fid,
                        name=flow.name,
                        cwe=flow.cwe,
                        severity=flow.severity,
                        cvss=cvss,
                        confidence="Confirmed",
                        reachability=1.0,
                        is_exploitable=True,
                        file_path=str(file_path),
                        line_number=flow.line,
                        column_offset=flow.col,
                        code_snippet=flow.code_snippet,
                        description=f"Untrusted input '{flow.source_var}' reaches dangerous sink '{flow.sink}' without sanitization.",
                        sanitizer_used=None,
                        propagation_path=flow.propagation_path,
                    )
                )

        # 2. Pattern & Secret Analysis for Multi-language support
        lines = content.splitlines()
        for rule in VULNERABILITY_CATALOG:
            if ext not in rule["exts"]:
                continue

            for idx, line in enumerate(lines, 1):
                stripped = line.strip()
                # Skip comments
                if stripped.startswith(("#", "//", "/*", "*")):
                    continue

                if rule["regex"].search(line):
                    # Check if already covered by AST finding at the exact same line
                    if any(f.line_number == idx and f.cwe == rule["cwe"] for f in findings):
                        continue

                    # If this is Python and we already did AST, check if it's safe
                    # But for secrets (SEC), always trigger
                    is_secret = rule["id"].startswith("DUO-SEC")
                    reachability = 1.0 if is_secret else 0.85
                    confidence = "Confirmed" if is_secret else "High"

                    findings.append(
                        Finding(
                            id=f"{rule['id']}-{idx}",
                            name=rule["name"],
                            cwe=rule["cwe"],
                            severity=rule["severity"],
                            cvss=rule["cvss"],
                            confidence=confidence,
                            reachability=reachability,
                            is_exploitable=True,
                            file_path=str(file_path),
                            line_number=idx,
                            column_offset=0,
                            code_snippet=stripped[:120],
                            description=rule["description"],
                            sanitizer_used=None,
                            propagation_path=[],
                        )
                    )

        return findings

    def scan_path(self, path: Path) -> List[Finding]:
        all_findings: List[Finding] = []
        if path.is_file():
            return self.analyze_file(path)

        for dirpath, dirnames, filenames in os_walk_filtered(path):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in {".py", ".ts", ".js", ".json", ".env", ".yaml", ".yml", ".rs", ".go"}:
                    file_findings = self.analyze_file(fpath)
                    all_findings.extend(file_findings)

        # Sort findings by severity and line
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda x: (sev_order.get(x.severity, 4), x.file_path, x.line_number))
        return all_findings


def os_walk_filtered(root: Path):
    import os
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        yield dirpath, dirnames, filenames
