"""Acceptance tests for the structured payload index.

These tests run purely against the standard library and never touch the
network. Two guarantees are exercised end to end:

* the committed index covers every extractable payload and validates clean;
* every class of mis-annotation (missing precondition, bad vocabulary, stale
  anchor, drift, unknown override) is detected with a non-empty violation list.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from payload_index import validator
from payload_index.extractor import extract_all
from payload_index.markers import required_preconditions
from payload_index.taxonomy import REPO_ROOT


class IndexHealthTest(unittest.TestCase):
    def test_committed_index_validates_clean(self) -> None:
        violations, stats = validator.validate()
        self.assertEqual(violations, [v.as_dict() for v in violations] and [])
        self.assertEqual(stats["violations"], 0)

    def test_acceptance_threshold_at_least_500_payloads(self) -> None:
        violations, stats = validator.validate()
        self.assertGreaterEqual(
            stats["payload_entries"],
            500,
            f"only {stats['payload_entries']} payloads indexed, 500 required",
        )

    def test_every_extracted_unit_is_indexed(self) -> None:
        raw_ids = {raw.entry_id for raw in extract_all()}
        indexed_ids = {entry["id"] for entry in validator.load_index()}
        self.assertEqual(raw_ids, indexed_ids)


class MisannotationDetectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.good_entries = validator.load_index()
        cls.payload_entries = [
            entry for entry in cls.good_entries if entry["entry_kind"] == "payload"
        ]

    def _validate_temp_index(self, entries: list[dict], overrides: dict | None = None):
        with tempfile.TemporaryDirectory() as tmp:
            index_path = Path(tmp) / "payload_index.jsonl"
            index_path.write_text(
                "\n".join(json.dumps(entry) for entry in entries) + "\n",
                encoding="utf-8",
            )
            original_index = validator.INDEX_PATH
            original_overrides = validator.load_overrides
            validator.INDEX_PATH = index_path
            if overrides is not None:
                validator.load_overrides = lambda: overrides
            try:
                return validator.validate()
            finally:
                validator.INDEX_PATH = original_index
                validator.load_overrides = original_overrides

    def test_missing_dependency_precondition_is_detected(self) -> None:
        # Find a real payload whose content forces at least one precondition.
        source = next(
            entry for entry in self.payload_entries if entry["preconditions"]
        )
        broken = dict(source)
        broken["preconditions"] = []
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        codes = {violation.code for violation in violations}
        self.assertIn("E002", codes)
        missing = next(violation for violation in violations if violation.code == "E002")
        self.assertEqual(missing.entry_id, source["id"])
        self.assertIn("not declared", missing.message)

    def test_callback_dependency_without_precondition_is_detected(self) -> None:
        # Synthetic regression: a collaborator payload with no premise written.
        raw = next(
            raw
            for raw in extract_all()
            if "requires_callback_server" in required_preconditions(raw.content, " > ".join(raw.heading_path))
        )
        source = next(entry for entry in self.good_entries if entry["id"] == raw.entry_id)
        broken = dict(source)
        broken["preconditions"] = [
            item
            for item in broken["preconditions"]
            if item != "requires_callback_server"
        ]
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        self.assertTrue(
            any(
                violation.code == "E002"
                and "requires_callback_server" in violation.message
                for violation in violations
            )
        )

    def test_unknown_vocabulary_is_detected(self) -> None:
        broken = dict(self.payload_entries[0])
        broken["attack_surface"] = dict(broken["attack_surface"])
        broken["attack_surface"]["vector"] = "made_up_vector"
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        self.assertIn("E004", {violation.code for violation in violations})

    def test_unknown_executability_is_detected(self) -> None:
        broken = dict(self.payload_entries[0])
        broken["executability"] = "runs_on_fridays"
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        self.assertIn("E003", {violation.code for violation in violations})

    def test_placeholder_payload_marked_direct_is_detected(self) -> None:
        source = next(
            entry
            for entry in self.payload_entries
            if "requires_placeholder_replacement" in entry["preconditions"]
        )
        broken = dict(source)
        broken["executability"] = "direct"
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        self.assertIn("E005", {violation.code for violation in violations})

    def test_stale_line_anchor_is_detected(self) -> None:
        broken = dict(self.payload_entries[0])
        broken["source"] = dict(broken["source"])
        broken["source"]["start_line"] += 5
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        self.assertIn("E006", {violation.code for violation in violations})

    def test_content_drift_is_detected(self) -> None:
        broken = dict(self.payload_entries[0])
        broken["content_sha256_12"] = "000000000000"
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        self.assertIn("E006", {violation.code for violation in violations})

    def test_missing_index_entry_is_detected(self) -> None:
        violations, _ = self._validate_temp_index(self.good_entries[:-1])
        self.assertIn("E001", {violation.code for violation in violations})

    def test_unknown_override_target_is_detected(self) -> None:
        violations, _ = self._validate_temp_index(
            self.good_entries,
            overrides={"does_not_exist-999": {"executability": "direct"}},
        )
        self.assertIn("E007", {violation.code for violation in violations})

    def test_wordlist_must_be_fuzz_list(self) -> None:
        wordlist = next(entry for entry in self.good_entries if entry["entry_kind"] == "wordlist")
        broken = dict(wordlist)
        broken["executability"] = "direct"
        violations, _ = self._validate_temp_index(self.good_entries[:-1] + [broken])
        self.assertIn("E005", {violation.code for violation in violations})


if __name__ == "__main__":
    unittest.main()
