"""Validate the generated payload index.

The validator is the acceptance gate for three guarantees:

1. *Coverage* - every extractable payload/wordlist in the repository has an
   index entry and every indexed entry still points at unchanged content
   (rules E001/E007).
2. *Honest preconditions* - any dependency marker found in the content forces
   a declared precondition (rule E002). This is the check that detects
   "dependency premise not written down" annotation errors.
3. *Controlled, filterable vocabulary* - attack surface and executability use
   only the closed enums, and executability agrees with the markers (E003-E006).

The validator returns structured violations and exits non-zero on CI when at
least one violation exists.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .annotator import load_overrides
from .extractor import content_hash, extract_all
from .markers import required_preconditions
from .taxonomy import (
    CONTEXTS,
    ENTRY_KINDS,
    EXECUTABILITY,
    INJECTION_POINTS,
    PRECONDITIONS,
    PROTOCOLS,
    REPO_ROOT,
    VECTORS,
)

INDEX_PATH = REPO_ROOT / "payload_index" / "payload_index.jsonl"


@dataclass
class Violation:
    code: str
    entry_id: str
    message: str

    def as_dict(self) -> dict:
        return {"code": self.code, "entry_id": self.entry_id, "message": self.message}


def load_index() -> list[dict]:
    entries = []
    for line in INDEX_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def validate() -> tuple[list[Violation], dict]:
    raw_entries = extract_all()
    raw_by_id = {raw.entry_id: raw for raw in raw_entries}
    index_entries = load_index()
    index_by_id = {entry["id"]: entry for entry in index_entries}
    overrides = load_overrides()
    violations: list[Violation] = []

    _validate_coverage(raw_by_id, index_by_id, violations)
    for entry in index_entries:
        raw = raw_by_id.get(entry["id"])
        if raw is None:
            continue
        _validate_vocabulary(entry, violations)
        _validate_preconditions(entry, raw, violations)
        _validate_executability(entry, raw, violations)
        _validate_source_anchor(entry, raw, violations)
    _validate_overrides(overrides, index_by_id, violations)

    stats = _build_stats(index_entries, raw_entries, violations)
    return violations, stats


def _validate_coverage(raw_by_id: dict, index_by_id: dict, violations: list[Violation]) -> None:
    for entry_id in sorted(raw_by_id):
        if entry_id not in index_by_id:
            violations.append(
                Violation("E001", entry_id, "extractable unit missing from index")
            )
    for entry_id in sorted(index_by_id):
        if entry_id not in raw_by_id:
            violations.append(
                Violation("E001", entry_id, "indexed entry no longer exists in sources")
            )


def _validate_vocabulary(entry: dict, violations: list[Violation]) -> None:
    entry_id = entry["id"]
    if entry["entry_kind"] not in ENTRY_KINDS:
        violations.append(Violation("E003", entry_id, f"unknown entry_kind {entry['entry_kind']!r}"))
    if entry["executability"] not in EXECUTABILITY:
        violations.append(
            Violation("E003", entry_id, f"unknown executability {entry['executability']!r}")
        )
    surface = entry["attack_surface"]
    vocab_checks = {
        "vector": VECTORS,
        "context": CONTEXTS,
        "protocol": PROTOCOLS,
        "injection_point": INJECTION_POINTS,
    }
    for field_name, allowed in vocab_checks.items():
        if surface.get(field_name) not in allowed:
            violations.append(
                Violation(
                    "E004",
                    entry_id,
                    f"attack_surface.{field_name}={surface.get(field_name)!r} outside vocabulary",
                )
            )
    for precondition in entry["preconditions"]:
        if precondition not in PRECONDITIONS:
            violations.append(
                Violation("E004", entry_id, f"unknown precondition {precondition!r}")
            )


def _validate_preconditions(entry: dict, raw, violations: list[Violation]) -> None:
    if entry["entry_kind"] == "wordlist":
        return
    heading = " > ".join(raw.heading_path)
    required = required_preconditions(raw.content, heading)
    declared = set(entry["preconditions"])
    for precondition, evidence in sorted(required.items()):
        if precondition not in declared:
            violations.append(
                Violation(
                    "E002",
                    entry["id"],
                    (
                        f"content requires {precondition} "
                        f"(marker evidence: {'; '.join(evidence[:3])}) but it is not declared"
                    ),
                )
            )


def _validate_executability(entry: dict, raw, violations: list[Violation]) -> None:
    entry_id = entry["id"]
    executability = entry["executability"]
    kind = entry["entry_kind"]
    declared = set(entry["preconditions"])

    if kind == "wordlist" and executability != "fuzz_list":
        violations.append(
            Violation("E005", entry_id, "wordlist entries must be annotated fuzz_list")
        )
    if kind == "code_sample" and executability != "not_executable":
        violations.append(
            Violation("E005", entry_id, "code_sample entries must be annotated not_executable")
        )
    if "requires_placeholder_replacement" in declared and executability == "direct":
        violations.append(
            Violation(
                "E005",
                entry_id,
                "entry contains placeholders but is annotated direct instead of templated",
            )
        )
    if (
        "requires_placeholder_replacement" not in declared
        and executability == "templated"
        and kind == "payload"
    ):
        violations.append(
            Violation(
                "E005",
                entry_id,
                "templated payload without requires_placeholder_replacement precondition",
            )
        )


def _validate_source_anchor(entry: dict, raw, violations: list[Violation]) -> None:
    entry_id = entry["id"]
    source = entry["source"]
    if (source["start_line"], source["end_line"]) != (raw.start_line, raw.end_line):
        violations.append(
            Violation(
                "E006",
                entry_id,
                (
                    f"stale line anchor {source['start_line']}-{source['end_line']} "
                    f"vs source {raw.start_line}-{raw.end_line}"
                ),
            )
        )
    if entry["content_sha256_12"] != content_hash(raw.content):
        violations.append(Violation("E006", entry_id, "content hash drift; rebuild the index"))


def _validate_overrides(overrides: dict, index_by_id: dict, violations: list[Violation]) -> None:
    allowed_fields = {
        "entry_kind",
        "executability",
        "attack_surface",
        "add_preconditions",
        "remove_preconditions",
        "technologies",
    }
    for entry_id, override in overrides.items():
        if entry_id not in index_by_id:
            violations.append(
                Violation("E007", entry_id, "override references an unknown entry id")
            )
        unknown = set(override) - allowed_fields
        if unknown:
            violations.append(
                Violation("E007", entry_id, f"override uses unknown fields {sorted(unknown)}")
            )


def _build_stats(index_entries: list[dict], raw_entries: list, violations: list[Violation]) -> dict:
    payload_count = sum(1 for entry in index_entries if entry["entry_kind"] == "payload")
    return {
        "indexed_entries": len(index_entries),
        "extracted_units": len(raw_entries),
        "payload_entries": payload_count,
        "wordlist_entries": sum(1 for entry in index_entries if entry["entry_kind"] == "wordlist"),
        "code_sample_entries": sum(
            1 for entry in index_entries if entry["entry_kind"] == "code_sample"
        ),
        "detection_string_entries": sum(
            1 for entry in index_entries if entry["entry_kind"] == "detection_string"
        ),
        "violations": len(violations),
        "violation_codes": sorted({violation.code for violation in violations}),
    }
