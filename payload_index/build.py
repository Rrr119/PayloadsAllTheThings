"""Build ``payload_index/payload_index.jsonl`` from the repository sources.

The index is generated data: sources remain the single source of truth and the
existing chapter directories are not moved or modified. Run with
``python -m payload_index.build``; ``--check`` verifies a committed index is up
to date without rewriting it (used by CI).
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from .annotator import annotate_all
from .extractor import extract_all
from .taxonomy import REPO_ROOT
from .validator import validate

INDEX_PATH = REPO_ROOT / "payload_index" / "payload_index.jsonl"
REPORT_PATH = REPO_ROOT / "payload_index" / "validation_report.json"


def build_index() -> list[dict]:
    raw_entries = extract_all()
    entries = annotate_all(raw_entries)
    entries.sort(key=lambda entry: entry["id"])
    return entries


def write_index(entries: list[dict]) -> None:
    lines = [json.dumps(entry, ensure_ascii=False, sort_keys=True) for entry in entries]
    INDEX_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_summary(entries: list[dict]) -> None:
    kinds = Counter(entry["entry_kind"] for entry in entries)
    executability = Counter(entry["executability"] for entry in entries)
    vectors = Counter(entry["attack_surface"]["vector"] for entry in entries)
    print(f"Indexed units : {len(entries)}")
    for kind, count in sorted(kinds.items()):
        print(f"  {kind:<18} {count}")
    print("Executability:")
    for label, count in sorted(executability.items()):
        print(f"  {label:<18} {count}")
    print(f"Attack vectors: {len(vectors)} chapters")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the structured payload index")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail instead of rewriting when the committed index is stale",
    )
    args = parser.parse_args()

    entries = build_index()
    serialized = [
        json.dumps(entry, ensure_ascii=False, sort_keys=True) for entry in entries
    ]
    if args.check:
        committed = INDEX_PATH.read_text(encoding="utf-8").strip().splitlines()
        if committed != serialized:
            print("Index is stale: run 'python -m payload_index.build'")
            return 1
        print("Index is up to date.")
        return 0

    write_index(entries)
    print_summary(entries)

    violations, stats = validate()
    REPORT_PATH.write_text(
        json.dumps(
            {"stats": stats, "violations": [v.as_dict() for v in violations]},
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"\nValidation: {stats['violations']} violation(s) -> {REPORT_PATH.relative_to(REPO_ROOT)}")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
