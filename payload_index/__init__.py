"""Structured index for the Payloads All The Things repository.

Modules:
    taxonomy   - controlled vocabularies (attack surface, preconditions, ...)
    markers    - content marker -> precondition rules, shared by build/validate
    extractor  - read fenced blocks and fuzz wordlists from the existing tree
    annotator  - deterministic annotation plus manual overrides
    validator  - coverage / annotation / vocabulary acceptance checks
    build      - CLI producing payload_index.jsonl
    search     - structured filtering plus full-text fallback search
"""

__all__ = [
    "taxonomy",
    "markers",
    "extractor",
    "annotator",
    "validator",
    "build",
    "search",
]
