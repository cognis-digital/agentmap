"""Command-line interface for agentmap."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ConfigError,
    SEVERITY_ORDER,
    build_graph,
    to_mermaid,
    to_sarif,
    to_table,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Map agent-to-agent / agent-to-MCP communications and "
                    "flag shadow AI (unauthenticated / unmonitored / "
                    "undeclared links).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    mapcmd = sub.add_parser(
        "map", help="Discover config sources under a path and map the graph.")
    mapcmd.add_argument(
        "path",
        help="Directory (or single file) holding mcp.json / agent configs / "
             ".env / observations.json.")
    mapcmd.add_argument(
        "--format", choices=("table", "json", "mermaid", "sarif"),
        default="table", help="Output format (default: table).")
    mapcmd.add_argument(
        "--out", help="Write output to this file instead of stdout.")
    mapcmd.add_argument(
        "--min-severity", choices=tuple(SEVERITY_ORDER), default="info",
        help="Only report findings at or above this severity.")
    mapcmd.add_argument(
        "--fail-on", choices=tuple(SEVERITY_ORDER), default="high",
        help="Exit non-zero if any finding is at or above this severity "
             "(default: high).")
    return p


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + ("\n" if not text.endswith("\n") else ""))
    else:
        print(text)


def _run_map(args: argparse.Namespace) -> int:
    try:
        graph = build_graph(args.path)
    except (OSError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    threshold = SEVERITY_ORDER[args.min_severity]
    graph.findings = [
        f for f in graph.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]

    if args.format == "json":
        _emit(json.dumps(graph.to_dict(), indent=2), args.out)
    elif args.format == "mermaid":
        _emit(to_mermaid(graph), args.out)
    elif args.format == "sarif":
        _emit(json.dumps(to_sarif(graph), indent=2), args.out)
    else:
        _emit(to_table(graph), args.out)

    fail_threshold = SEVERITY_ORDER[args.fail_on]
    worst = min((SEVERITY_ORDER.get(f.severity, 99)
                 for f in graph.findings), default=99)
    return 1 if worst <= fail_threshold else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "map":
        return _run_map(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
