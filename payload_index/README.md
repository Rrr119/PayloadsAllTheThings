# Structured Payload Index

This folder adds a **structured index** on top of the existing payload
collection without moving or rewriting any chapter. The Markdown files and
`Intruder` wordlists stay the single source of truth; every index entry points
back at the exact file and line range it was extracted from.

## What is indexed

| Unit | Source | Index entry kind |
| --- | --- | --- |
| Fenced code block | Every chapter `*.md` (excluding meta folders) | `payload`, `code_sample` or `detection_string` |
| Fuzz wordlist | Every chapter `*.txt` file | `wordlist` |

Each unit receives a stable identifier such as
`server_side_request_forgery_readme-002` or
`xss_injection_intruders_rsnake_xss-wl`. The numbering follows the order of
fenced blocks inside a file, so an id only changes when blocks are inserted or
removed above it.

## Index schema

One JSON object per line in [`payload_index.jsonl`](payload_index.jsonl):

```json
{
  "id": "server_side_request_forgery_readme-002",
  "entry_kind": "payload",
  "attack_surface": {
    "vector": "server_side_request_forgery",
    "context": "url",
    "protocol": "http",
    "injection_point": "url_path"
  },
  "preconditions": ["requires_internal_network_access"],
  "executability": "direct",
  "technologies": [],
  "source": {
    "path": "Server Side Request Forgery/README.md",
    "start_line": 68,
    "end_line": 70,
    "heading": "Server-Side Request Forgery > Methodology",
    "language": "ps1"
  },
  "content_sha256_12": "195fe4b8c8c0",
  "preview": "http://169.254.169.254/latest/meta-data/"
}
```

### Attack surface (structured, filterable)

- `vector`: vulnerability chapter, derived from the top level directory and
  validated against the on-disk chapter list (see `taxonomy.VECTORS`).
- `context`: interpreter of the attacker data, e.g. `sql`, `html`,
  `javascript`, `template`, `shell`, `url`, `ldap_filter`, `token`.
- `protocol`: delivery scheme, e.g. `http`, `websocket`, `dns`, `gopher`,
  `file`, `cli`, `local`.
- `injection_point`: concrete input location, e.g. `query_param`,
  `http_header`, `cookie`, `multipart_upload`, `json_field`.

### Preconditions (the dependencies that must be written down)

Closed vocabulary in `taxonomy.PRECONDITIONS`, including
`requires_callback_server`, `requires_attacker_hosted_file`,
`requires_placeholder_replacement`, `requires_authenticated_session`,
`requires_internal_network_access`, `requires_specific_technology`,
`requires_file_upload_capability`, `requires_deserialization_gadget`,
`requires_template_engine`, `requires_vulnerable_software_version`,
`requires_dns_control`, `requires_browser_interaction`,
`requires_outbound_connectivity` and `requires_interactive_tool`.

Markers are matched against the payload content and the surrounding Markdown
heading in `markers.py`. Both the builder and the validator use the same
marker rules, so an annotation cannot silently disagree with the content.

### Executability annotation

| Value | Meaning |
| --- | --- |
| `direct` | Paste-and-go, no substitution needed |
| `templated` | Works once bracketed placeholders are replaced |
| `multi_step` | One step of a multi-request exploit chain |
| `tool_generated` | Must be produced by an external tool (sqlmap, ysoserial, ...) |
| `fuzz_list` | Reusable wordlist, not a standalone payload |
| `verification_only` | Benign marker used to observe reflection/execution |
| `not_executable` | Explanatory vulnerable/helper code |

## Usage

Rebuild the index after editing a chapter (standard library only):

```bash
python -m payload_index.build
```

Structured queries, all flags validated against the controlled vocabulary:

```bash
python -m payload_index.search --vector sql_injection --executability direct
python -m payload_index.search --context html --requires requires_callback_server
python -m payload_index.search --text "union select" --kind payload --format json
```

Full-text search remains available through `--text`; structured filters and
full text can be combined.

## Manual overrides

Automatic annotation is deterministic but cannot understand every edge case.
`overrides.json` maps an entry id to a correction, for example:

```json
{
  "some_chapter_readme-004": {
    "attack_surface": {"injection_point": "http_header"},
    "add_preconditions": ["requires_authenticated_session"]
  }
}
```

Overrides can only **add** preconditions on top of marker-derived ones (or
re-classify executability/attack surface); they cannot suppress a marker-driven
precondition, so dependency evidence can never be hidden. Unknown entry ids and
unknown fields fail validation with code `E007`.

## Validation and acceptance rules

`python -m payload_index.validate` (also run at the end of every build)
evaluates:

| Code | Check |
| --- | --- |
| `E001` | Every extracted unit has an index entry and vice versa |
| `E002` | Every content marker has its precondition declared (missing dependency premise) |
| `E003` | `entry_kind` / `executability` belong to the enum |
| `E004` | Attack surface values and preconditions belong to the enum |
| `E005` | Executability agrees with markers (placeholders, wordlists, code samples) |
| `E006` | Line anchor and content hash still match the source (drift detection) |
| `E007` | Overrides reference existing entries and known fields |

Any violation makes the command exit non-zero and is written to
`validation_report.json`. The test suite proves each violation class is
actually raised:

```bash
python -m unittest discover -s payload_index/tests -v
```

## Compatibility with the existing layout

- No chapter, image or wordlist is moved, renamed or duplicated.
- The index is generated data under `payload_index/`; deleting it and running
  the builder reproduces it byte for byte.
- `payload_index/` is outside the MkDocs chapter navigation and the
  markdownlint scope (only its own README is Markdown), so existing docs builds
  are unaffected.
