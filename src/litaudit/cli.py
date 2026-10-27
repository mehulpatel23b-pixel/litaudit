#!/usr/bin/env python3
"""litaudit CLI — audit LiteLLM / LLM-gateway config files.

Usage:
    litaudit config.yaml [another.yaml ...] [--json] [--fail-on LEVEL]
                          [--quiet]

Exit codes:
    0 — no findings at or above the --fail-on threshold
    1 — at least one finding at or above the threshold
    2 — usage or parse errors
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .scanner import scan_config, SEVERITY_ORDER

FAIL_LEVELS = ("low", "medium", "high", "critical")

_RULE_SUMMARY = {
    "LIT-001": ("master key committed to config", "critical"),
    "LIT-002": ("provider api_key literal", "high"),
    "LIT-003": ("credential-bearing database_url", "high"),
    "LIT-004": ("plaintext secret in environment_variables", "critical"),
    "LIT-005": ("plaintext http:// provider endpoint", "medium"),
    "LIT-006": ("no master_key configured", "high"),
    "LIT-007": ("wildcard model route", "medium"),
    "LIT-008": ("no spend/rate controls", "medium"),
    "LIT-009": ("telemetry not explicitly disabled", "low"),
    "LIT-010": ("callback ships data to remote URL", "medium"),
    "LIT-011": ("weak/placeholder credential", "high"),
}

_SEV_COLOR = {
    "critical": "\033[91m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _colorize(severity: str, text: str, tty: bool) -> str:
    if not tty:
        return text
    return f"{_SEV_COLOR.get(severity, '')}{text}{_RESET}"


def _print_text(path: str, result: dict, tty: bool) -> int:
    findings = result["findings"]
    if result["error"]:
        print(f"{_colorize('high', '[PARSE ERROR]', tty)} {path}: {result['error']}")
        return 2
    if not findings:
        print(f"{_colorize('low', '[PASS]', tty)} {path} — no findings")
        return 0
    counts: dict = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    worst = max(findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity
    header = f"{_colorize(worst, '[FAIL]', tty)} {_BOLD if tty else ''}{path}{_RESET if tty else ''} — {len(findings)} finding(s): "
    header += ", ".join(f"{counts[s]} {s}" for s in
                        sorted(counts, key=lambda s: -SEVERITY_ORDER[s]))
    print(header)
    print()
    for f in sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity]):
        print(f"  {_colorize(f.severity, f.severity.upper().ljust(8), tty)} "
              f"{_colorize(f.severity, f.rule, tty)}  {f.where}")
        print(f"         {f.message}")
        print(f"         fix: {f.fix}")
        print()
    return 1


def main(argv: List[str] | None = None) -> int:
    if "--version" in (argv if argv is not None else sys.argv[1:]):
        from . import __version__
        print(__version__)
        return 0

    p = argparse.ArgumentParser(
        prog="litaudit",
        description="Zero-dependency security auditor for LiteLLM / LLM-gateway "
                    "config files.")
    p.add_argument("configs", nargs="+", help="one or more config.yaml files")
    p.add_argument("--json", action="store_true",
                   help="machine-readable JSON output instead of text")
    p.add_argument("--fail-on", choices=FAIL_LEVELS, default="medium",
                   help="audit fails when findings at/above this severity exist "
                        "(default: medium)")
    p.add_argument("--quiet", action="store_true",
                   help="suppress the per-finding detail in text mode")
    p.add_argument("--version", action="store_true", help="print version and exit")
    args = p.parse_args(argv)

    if args.version:
        from . import __version__
        print(__version__)
        return 0

    threshold = SEVERITY_ORDER[args.fail_on]
    exit_code = 0
    payload = {"files": []}
    for path in args.configs:
        result = scan_config(path)
        payload["files"].append({
            "path": path,
            "error": result["error"],
            "findings": [f.as_dict() for f in result["findings"]],
        })
        for f in result["findings"]:
            if SEVERITY_ORDER[f.severity] >= threshold:
                exit_code = 1
        if result["error"]:
            exit_code = 2
        if args.json:
            continue
        if args.quiet:
            continue
        code = _print_text(path, result, sys.stdout.isatty())
        exit_code = max(exit_code, 0) if code == 0 else exit_code

    if args.json:
        print(json.dumps(payload, indent=2))

    return exit_code


def run() -> int:
    try:
        return main()
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(run())
