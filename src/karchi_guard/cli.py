"""Command line: karchi-guard scan [folder] | karchi-guard report ..."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import report
from . import scan as scanner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="karchi-guard", description="What can an AI agent in your Supabase repo read or destroy?")
    commands = parser.add_subparsers(dest="command", required=True)

    s = commands.add_parser("scan", help="agent blast-radius scan of a folder (reads files only)")
    s.add_argument("folder", nargs="?", default=".")
    s.add_argument("--home", action="store_true", help="also read agent configs in your home folder (~/.claude.json, ~/.cursor/mcp.json, ...)")
    s.add_argument("--json", action="store_true", help="print JSON instead of text")

    r = commands.add_parser("report", help="one Markdown report from scan, Supabase Advisor and rlsgrid results")
    r.add_argument("--scan", help="output of: karchi-guard scan --json")
    r.add_argument("--advisors", help="output of: supabase db advisors --type security --output-format json")
    r.add_argument("--rlsgrid", help="output of: rlsgrid check --json (run on a local copy only)")
    r.add_argument("--project", default="your project", help="name shown at the top of the report")
    r.add_argument("--out", help="write the report here instead of printing it")

    args = parser.parse_args(argv)
    if args.command == "report":
        if not (args.scan or args.advisors or args.rlsgrid):
            parser.error("report needs at least one of --scan, --advisors, --rlsgrid")
        text = report.build(args.project, report.load_json(args.scan), report.load_json(args.advisors), report.load_json(args.rlsgrid))
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            print(text)
        return 0
    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"karchi-guard: not a folder: {folder}", file=sys.stderr)
        return 2
    findings = scanner.scan(folder, home=Path.home() if args.home else None)
    print(scanner.to_json(folder, findings) if args.json else scanner.render(folder, findings))
    return 1 if any(f.severity == scanner.CRITICAL for f in findings) else 0
