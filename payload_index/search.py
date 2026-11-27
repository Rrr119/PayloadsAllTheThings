"""Structured + full-text search over the generated index.

Examples:
    python -m payload_index.search --vector sql_injection --executability direct
    python -m payload_index.search --context html --requires requires_callback_server
    python -m payload_index.search --text "union select" --format json --limit 5
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .taxonomy import (
    CONTEXTS,
    EXECUTABILITY,
    INJECTION_POINTS,
    PRECONDITIONS,
    PROTOCOLS,
    REPO_ROOT,
    VECTORS,
)
from .validator import INDEX_PATH, load_index


def _check_choice(value: str, allowed: set[str], flag: str) -> str:
    if value not in allowed:
        options = ", ".join(sorted(allowed))
        raise SystemExit(f"{flag} {value!r} is not in the vocabulary: {options}")
    return value


def search(
    text: str | None = None,
    vector: str | None = None,
    context: str | None = None,
    protocol: str | None = None,
    injection_point: str | None = None,
    executability: str | None = None,
    requires: list[str] | None = None,
    excludes: list[str] | None = None,
    kind: str | None = None,
) -> list[dict]:
    entries = load_index()
    needle = text.lower() if text else None
    required = set(requires or [])
    excluded = set(excludes or [])
    results = []
    for entry in entries:
        surface = entry["attack_surface"]
        if vector and surface["vector"] != vector:
            continue
        if context and surface["context"] != context:
            continue
        if protocol and surface["protocol"] != protocol:
            continue
        if injection_point and surface["injection_point"] != injection_point:
            continue
        if executability and entry["executability"] != executability:
            continue
        if kind and entry["entry_kind"] != kind:
            continue
        preconditions = set(entry["preconditions"])
        if required and not required.issubset(preconditions):
            continue
        if excluded and preconditions & excluded:
            continue
        if needle:
            haystack = " ".join(
                [
                    entry["id"],
                    entry["preview"],
                    entry["source"]["path"],
                    entry["source"]["heading"],
                    " ".join(entry["technologies"]),
                ]
            ).lower()
            if needle not in haystack:
                continue
        results.append(entry)
    return results


def render_table(entries: list[dict]) -> str:
    lines = []
    for entry in entries:
        surface = entry["attack_surface"]
        source = entry["source"]
        lines.append(
            " | ".join(
                [
                    entry["id"],
                    surface["vector"],
                    surface["context"],
                    entry["executability"],
                    f"{source['path']}:{source['start_line']}",
                    entry["preview"][:70].replace("\n", " "),
                ]
            )
        )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Search the structured payload index")
    parser.add_argument("--text", help="full-text needle matched against id/preview/source")
    parser.add_argument("--vector", type=lambda v: _check_choice(v, VECTORS, "--vector"))
    parser.add_argument("--context", type=lambda v: _check_choice(v, CONTEXTS, "--context"))
    parser.add_argument("--protocol", type=lambda v: _check_choice(v, PROTOCOLS, "--protocol"))
    parser.add_argument(
        "--injection-point",
        type=lambda v: _check_choice(v, INJECTION_POINTS, "--injection-point"),
    )
    parser.add_argument(
        "--executability",
        type=lambda v: _check_choice(v, EXECUTABILITY, "--executability"),
    )
    parser.add_argument(
        "--requires",
        action="append",
        default=[],
        help="precondition that must be declared (repeatable)",
    )
    parser.add_argument(
        "--excludes",
        action="append",
        default=[],
        help="precondition that must NOT be declared (repeatable)",
    )
    parser.add_argument(
        "--kind",
        choices=sorted({"payload", "wordlist", "code_sample", "detection_string"}),
    )
    parser.add_argument("--format", choices=["table", "json"], default="table")
    parser.add_argument("--limit", type=int, default=20)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for precondition in args.requires + args.excludes:
        _check_choice(precondition, PRECONDITIONS, "--requires/--excludes")
    if not INDEX_PATH.exists():
        raise SystemExit("Index missing: run 'python -m payload_index.build' first")
    results = search(
        text=args.text,
        vector=args.vector,
        context=args.context,
        protocol=args.protocol,
        injection_point=args.injection_point,
        executability=args.executability,
        requires=args.requires,
        excludes=args.excludes,
        kind=args.kind,
    )
    limited = results[: args.limit]
    if args.format == "json":
        json.dump(limited, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print(render_table(limited) if limited else "no matching entries")
    print(f"\n{len(results)} match(es)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
