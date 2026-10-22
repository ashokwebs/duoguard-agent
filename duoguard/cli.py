"""
Command Line Interface for DuoGuard DevSecOps Agent.
Supports interactive terminal audits, GitLab SAST artifact generation,
automated patching, and MCP server activation.
"""

import sys
import os
import argparse
from pathlib import Path
from duoguard.reachability import ReachabilityAnalyzer
from duoguard.gitlab_sast import save_gitlab_sast_report, generate_gitlab_sast_report
from duoguard.gitlab_bot import format_mr_security_comment, post_to_gitlab_mr
from duoguard.remediation import RemediationEngine
from duoguard.mcp_server import run_mcp_server


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    RED = "\033[91m"
    DIM = "\033[2m"
    WHITE = "\033[97m"


def print_banner():
    banner = f"""
{C.CYAN}{C.BOLD}  _____             _____                 _ 
 |  __ \\           / ____|               | |
 | |  | |_   _  ___| |  __ _   _  __ _ _ __| |
 | |  | | | | |/ _ \\ | |_ | | | |/ _` | '__| |
 | |__| | |_| | (_) | |__| | |_| | (_| | |  |_|
 |_____/ \\__,_|\\___/ \\_____|\\__,_|\\__,_|_|  (_) {C.RESET}
{C.DIM}Autonomous DevSecOps & AST Taint Security Agent for GitLab Duo{C.RESET}
"""
    print(banner)


def cmd_scan(args):
    target = Path(args.repo or args.path or ".").resolve()
    print_banner()
    print(f"[*] Scanning codebase at: {C.WHITE}{target}{C.RESET}")

    analyzer = ReachabilityAnalyzer(str(target))
    findings = analyzer.scan_path(target)

    # Filter by minimum severity if specified
    sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    if args.min_severity:
        threshold = sev_rank.get(args.min_severity.upper(), 0)
        findings = [f for f in findings if sev_rank.get(f.severity.upper(), 0) >= threshold]

    crit_cnt = sum(1 for f in findings if f.severity == "CRITICAL")
    high_cnt = sum(1 for f in findings if f.severity == "HIGH")
    med_cnt = sum(1 for f in findings if f.severity == "MEDIUM")

    # Output formatting
    if args.format == "gitlab-sast":
        out_path = Path(args.output or "gl-sast-report.json").resolve()
        save_gitlab_sast_report(findings, target, out_path)
        print(f"\n{C.GREEN}[+] Official GitLab SAST report generated: {out_path}{C.RESET}")
        print(f"    Total findings logged: {len(findings)}")

    elif args.format == "json":
        import json
        res = [f.to_dict() for f in findings]
        if args.output:
            Path(args.output).write_text(json.dumps(res, indent=2), encoding="utf-8")
            print(f"[+] JSON report saved to {args.output}")
        else:
            print(json.dumps(res, indent=2))

    elif args.format == "markdown":
        md = format_mr_security_comment(findings, target)
        if args.output:
            Path(args.output).write_text(md, encoding="utf-8")
            print(f"[+] Markdown report saved to {args.output}")
        else:
            print(md)

    else:
        # Default: Rich Terminal Console
        print("\n" + "=" * 70)
        print(f" {C.BOLD}DUOGUARD DEVSECOPS SECURITY AUDIT SCORECARD{C.RESET}")
        print("=" * 70)
        print(f" Target Path       : {C.WHITE}{target}{C.RESET}")
        print(f" Vulnerabilities   : {C.RED if crit_cnt else C.GREEN}{crit_cnt} Critical{C.RESET} | "
              f"{C.YELLOW if high_cnt else C.GREEN}{high_cnt} High{C.RESET} | "
              f"{C.CYAN if med_cnt else C.GREEN}{med_cnt} Medium{C.RESET}")
        print("-" * 70)

        if not findings:
            print(f" {C.GREEN}✅ 0 vulnerabilities detected! Codebase clean and production ready.{C.RESET}\n")
        else:
            print(f" {C.BOLD}High-Confidence Taint Flows & Sinks:{C.RESET}\n")
            for idx, f in enumerate(findings, 1):
                sev_color = C.RED if f.severity == "CRITICAL" else (C.YELLOW if f.severity == "HIGH" else C.CYAN)
                try:
                    rel_p = Path(f.file_path).relative_to(target)
                except ValueError:
                    rel_p = Path(f.file_path).name

                print(f"  {idx}. [{sev_color}{C.BOLD}{f.severity}{C.RESET}] {C.WHITE}{f.name}{C.RESET} ({f.cwe})")
                print(f"     Location     : {C.CYAN}{rel_p}:{f.line_number}{C.RESET}")
                print(f"     Reachability : {C.GREEN}{int(f.reachability * 100)}% ({f.confidence}){C.RESET}")
                print(f"     Snippet      : {C.DIM}{f.code_snippet}{C.RESET}")
                
                # Show quick fix recommendation
                fix = RemediationEngine.generate_fix(f)
                print(f"     {C.BOLD}Suggested Fix{C.RESET}: {fix['explanation']}")
                print()

        print("=" * 70 + "\n")

    # Optionally post to GitLab MR
    if args.post_mr:
        comment = format_mr_security_comment(findings, target)
        if post_to_gitlab_mr(comment):
            print(f"{C.GREEN}[+] Successfully posted security review note to GitLab Merge Request!{C.RESET}")
        else:
            print(f"{C.YELLOW}[!] GitLab CI variables not present; skipped MR commentary post.{C.RESET}")

    # Exit code: 1 if critical/high findings exist and --strict is set
    if args.strict and (crit_cnt > 0 or high_cnt > 0):
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="DuoGuard: Autonomous DevSecOps & AST Security Agent for GitLab Duo",
        prog="duoguard"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Scan command
    scan_p = subparsers.add_parser("scan", help="Scan repository or file for AST vulnerabilities and secrets")
    scan_p.add_argument("path", nargs="?", default=".", help="Target directory or file path")
    scan_p.add_argument("--repo", help="Alias for path")
    scan_p.add_argument("--format", choices=["console", "gitlab-sast", "json", "markdown"], default="console", help="Report format")
    scan_p.add_argument("-o", "--output", help="Output destination file path")
    scan_p.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Filter by severity")
    scan_p.add_argument("--strict", action="store_true", help="Exit with non-zero status on critical/high findings")
    scan_p.add_argument("--post-mr", action="store_true", help="Post review comment directly to GitLab MR")

    # MCP Server command
    mcp_p = subparsers.add_parser("mcp", help="Start the DuoGuard Model Context Protocol (MCP) server")

    args = parser.parse_args()

    if args.command == "scan" or (args.command is None and len(sys.argv) > 1 and not sys.argv[1].startswith("-")):
        if args.command is None:
            args.repo = sys.argv[1]
            args.path = sys.argv[1]
            args.format = "console"
            args.output = None
            args.min_severity = None
            args.strict = False
            args.post_mr = False
        cmd_scan(args)
    elif args.command == "mcp":
        run_mcp_server()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
