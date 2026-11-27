"""Command line entry point for index validation.

Exit code is non-zero when at least one violation is found, which makes the
command directly usable in CI or pre-commit hooks.
"""

from __future__ import annotations

import json

from .taxonomy import REPO_ROOT
from .validator import validate

REPORT_PATH = REPO_ROOT / "payload_index" / "validation_report.json"


def main() -> int:
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
    print(json.dumps(stats, indent=2))
    if violations:
        for violation in violations:
            print(f"[{violation.code}] {violation.entry_id}: {violation.message}")
        print(f"\nReport written to {REPORT_PATH.relative_to(REPO_ROOT)}")
        return 1
    print(f"OK - report written to {REPORT_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
