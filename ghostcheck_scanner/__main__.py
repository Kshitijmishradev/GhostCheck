"""GhostCheck CLI — `python -m ghostcheck_scanner scan <path>`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scan import scan_repo
from .report import render_terminal, to_json, to_html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ghostcheck",
        description="Code-aware endpoint security scanner. Finds injectable endpoints "
                    "and generates a proof-of-concept exploit for each.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a repository for vulnerable endpoints")
    scan.add_argument("path", help="Path to the application source directory")
    scan.add_argument("--json", metavar="FILE", help="Write JSON findings to FILE")
    scan.add_argument("--html", metavar="FILE", help="Write an HTML report to FILE")
    scan.add_argument("--no-color", action="store_true", help="Disable coloured output")
    scan.add_argument("--fail-on", default="HIGH",
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                      help="Exit non-zero if a finding at/above this severity exists (default: HIGH)")

    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.path)
        if not target.exists():
            print(f"error: path not found: {target}", file=sys.stderr)
            return 2
        result = scan_repo(str(target))
        print(render_terminal(result, color=False if args.no_color else None))

        if args.json:
            Path(args.json).write_text(to_json(result), encoding="utf-8")
            print(f"  → JSON written to {args.json}")
        if args.html:
            Path(args.html).write_text(to_html(result), encoding="utf-8")
            print(f"  → HTML report written to {args.html}")

        if args.fail_on != "NONE":
            from .findings import SEVERITY_ORDER
            threshold = SEVERITY_ORDER[args.fail_on]
            if any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in result.findings):
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
