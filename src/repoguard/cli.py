"""Partner B: command line interface."""
from __future__ import annotations

import argparse
import sys

from repoguard import __version__
from repoguard.fetcher import load_local
from repoguard.scanner import scan_files
from repoguard.scoring import score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="repoguard", description="Static scanner for suspicious repos.")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a local folder")
    scan.add_argument("path")
    args = parser.parse_args(argv)

    findings = scan_files(load_local(args.path))
    for f in findings:
        print(f"[{f.severity.upper()}] {f.rule_id}  {f.file}:{f.line}")
        print(f"    {f.snippet}")
        print(f"    Why: {f.explanation}")
        print(f"    Do:  {f.advice}")
    risk = score(findings)
    print(f"\nRisk: {risk.level.upper()} ({risk.points} points, {len(findings)} findings)")
    return 0 if risk.level == "low" else 1


if __name__ == "__main__":
    sys.exit(main())
