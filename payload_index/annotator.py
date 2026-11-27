"""Turn raw extracted units into fully annotated index entries.

Annotation is rule based and deterministic. Every rule lives next to the
marker it interprets (see :mod:`payload_index.markers`), and the validator
re-runs the same rules so a bad annotation can never pass silently.
"""

from __future__ import annotations

import json
import re

from .extractor import RawEntry, content_hash
from .markers import (
    TEMPLATE_ENGINE_PATTERN,
    TOOL_PATTERNS,
    UPLOAD_PATTERN,
    detect_technologies,
    required_preconditions,
)
from .taxonomy import (
    LANGUAGE_CONTEXT,
    REPO_ROOT,
    chapter_slug,
)

OVERRIDES_PATH = REPO_ROOT / "payload_index" / "overrides.json"


def load_overrides() -> dict:
    if not OVERRIDES_PATH.exists():
        return {}
    return json.loads(OVERRIDES_PATH.read_text(encoding="utf-8"))


def _vector_for(raw: RawEntry) -> str:
    return chapter_slug(REPO_ROOT / raw.source_path.split("/")[0])


def _context_for(raw: RawEntry) -> str:
    text = raw.content
    stripped_lines = [line.strip() for line in text.splitlines() if line.strip()]
    # The house style of this repo is to wrap raw URLs / HTTP requests in
    # powershell/ps1 fences; the content is more informative than the tag.
    if raw.language in {"ps1", "powershell", ""}:
        if all(line.startswith(("http://", "https://")) for line in stripped_lines):
            return "url"
        if text.lstrip().startswith(("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ")):
            return "http"
        first = stripped_lines[0] if stripped_lines else ""
        if re.match(r"^(\.?/|[\w.-]+\s+--?\w|sudo\s|\$\s)", first):
            return "shell"
    if raw.language in LANGUAGE_CONTEXT:
        return LANGUAGE_CONTEXT[raw.language]
    heading = " ".join(raw.heading_path).lower()
    lowered = text.lower()
    if "ldap" in heading or "ldap" in lowered[:200]:
        return "ldap_filter"
    if "xpath" in heading:
        return "xpath_expr"
    if "graphql" in heading:
        return "graphql"
    if "nosql" in heading or "mongodb" in lowered[:200]:
        return "nosql_query"
    if raw.source_path.split("/")[0] == "JSON Web Token":
        return "token"
    if any(scheme in lowered for scheme in ("gopher://", "dict://", "file://", "netdoc://", "jar://")):
        return "url"
    if "header" in heading or lowered.startswith(("host:", "cookie:", "x-")):
        return "header"
    if "../" in raw.content or "..\\" in raw.content:
        return "file_path"
    if TEMPLATE_ENGINE_PATTERN.search(raw.content):
        return "template"
    if lowered.startswith(("http://", "https://")):
        return "url"
    return "other"


def _protocol_for(raw: RawEntry, context: str) -> str:
    text = raw.content.lower()
    for scheme in (
        "gopher",
        "dict",
        "ldap",
        "netdoc",
        "jar",
        "data",
        "javascript",
        "vbscript",
        "file",
        "ftp",
        "smtp",
        "dns",
        "wss",
        "ws",
        "https",
        "http",
    ):
        if f"{scheme}://" in text:
            return "websocket" if scheme in {"ws", "wss"} else scheme
    if context == "shell":
        return "cli"
    if context in {"file_path", "file_content", "binary", "config", "yaml"}:
        return "local"
    if raw.kind_hint == "wordlist":
        return "other"
    return "http"


def _injection_point_for(raw: RawEntry, context: str) -> str:
    heading = " ".join(raw.heading_path).lower()
    text = raw.content.lower()
    if "host header" in heading or text.startswith("host:"):
        return "host_header"
    if "cookie" in heading or text.startswith("cookie:"):
        return "cookie"
    if "header" in heading or text.startswith(("x-", "authorization:", "content-type:")):
        return "http_header"
    if "upload" in heading or UPLOAD_PATTERN.search(raw.content):
        return "multipart_upload"
    if context == "json" or "json" in heading:
        return "json_field"
    if "websocket" in heading or "web socket" in heading:
        return "websocket_message"
    if "graphql" in heading:
        return "graphql_variable"
    if context == "file_path" or "filename" in heading:
        return "url_path"
    if context in {"template", "expression"}:
        return "template_variable"
    if context in {"config", "yaml"}:
        return "configuration_file"
    if raw.content.startswith(("http://", "https://")) and "?" in raw.content:
        return "query_param"
    if context == "url":
        return "url_path"
    if context in {"http", "header"}:
        return "http_header"
    return "other"


def _executability_for(raw: RawEntry, preconditions: set[str]) -> str:
    if raw.kind_hint == "wordlist":
        return "fuzz_list"
    if raw.kind_hint == "code_sample":
        return "not_executable"
    text = raw.content
    stripped_lower = text.strip().lower()
    # Benign markers used only to prove reflection / execution.
    if stripped_lower in {"<script>alert(1)</script>", "alert(1)", "id", "whoami", "test"}:
        return "verification_only"
    if any(pattern.search(text) for pattern in TOOL_PATTERNS):
        return "tool_generated"
    if "requires_placeholder_replacement" in preconditions:
        return "templated"
    # Raw HTTP requests with several headers/steps are chains, not paste-and-go.
    if text.startswith(("POST ", "PUT ", "GET ", "PATCH ", "DELETE ")) and text.count("\n") >= 4:
        return "multi_step"
    return "direct"


def _entry_kind(raw: RawEntry, executability: str) -> str:
    if raw.kind_hint == "wordlist":
        return "wordlist"
    if executability == "not_executable":
        return "code_sample"
    if executability == "verification_only":
        return "detection_string"
    return "payload"


def annotate(raw: RawEntry, overrides: dict) -> dict:
    heading = " > ".join(raw.heading_path)
    vector = _vector_for(raw)
    context = _context_for(raw)
    protocol = _protocol_for(raw, context)
    injection_point = _injection_point_for(raw, context)

    if raw.kind_hint == "wordlist":
        derived: dict[str, list[str]] = {}
        preconditions: list[str] = []
    else:
        derived = required_preconditions(raw.content, heading)
        preconditions = sorted(derived.keys())
    technologies = detect_technologies(raw.content, heading)
    executability = _executability_for(raw, set(preconditions))
    kind = _entry_kind(raw, executability)

    entry = {
        "id": raw.entry_id,
        "entry_kind": kind,
        "attack_surface": {
            "vector": vector,
            "context": context,
            "protocol": protocol,
            "injection_point": injection_point,
        },
        "preconditions": preconditions,
        "executability": executability,
        "technologies": technologies,
        "source": {
            "path": raw.source_path,
            "start_line": raw.start_line,
            "end_line": raw.end_line,
            "heading": heading,
            "language": raw.language or "plain",
        },
        "content_sha256_12": content_hash(raw.content),
        "preview": raw.content.splitlines()[0][:160] if raw.content else "",
    }

    override = overrides.get(raw.entry_id)
    if override:
        _apply_override(entry, override)
    return entry


def _apply_override(entry: dict, override: dict) -> None:
    for field_name in ("entry_kind", "executability"):
        if field_name in override:
            entry[field_name] = override[field_name]
    if "attack_surface" in override:
        entry["attack_surface"].update(override["attack_surface"])
    if "add_preconditions" in override:
        entry["preconditions"] = sorted(
            set(entry["preconditions"]) | set(override["add_preconditions"])
        )
    if "remove_preconditions" in override:
        entry["preconditions"] = sorted(
            set(entry["preconditions"]) - set(override["remove_preconditions"])
        )
    if "technologies" in override:
        entry["technologies"] = override["technologies"]
    entry["overridden"] = True


def annotate_all(raw_entries: list[RawEntry]) -> list[dict]:
    overrides = load_overrides()
    entries = [annotate(raw, overrides) for raw in raw_entries]
    return entries
