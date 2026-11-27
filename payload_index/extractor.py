"""Extract raw indexable units from the repository, without annotating them.

Two kinds of units are extracted:

* fenced code blocks inside the chapter Markdown files (payloads, detection
  strings and explanatory code samples);
* ``*.txt`` fuzz wordlists (one index entry per file, the file itself stays
  the source of truth and is never copied or re-organized).

The existing directory layout is only read, never modified.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .taxonomy import NON_CHAPTER_DIRS, PROGRAMMING_LANGUAGES, REPO_ROOT

FENCE_CHARS = ("```", "~~~")

TEMPLATE_MARKER = re.compile(r"(\{\{[^}]*\}\}|<%[=!]?[^%]*%>|#\{[^}\n]+\}|\$\{[^}\n]+\})")
PROGRAM_CONTROL = re.compile(
    r"(;\s*$|^\s*\$?(?:output|result|data|cmd|res|resp)\s*=|function\s+\w+\s*\(|"
    r"^\s*(def|class|import|require|include|public|private|return|echo|print)\b|"
    r"\$_(?:GET|POST|REQUEST|SERVER|COOKIE)|->\s*\w+\s*\()",
    re.MULTILINE,
)


@dataclass
class RawEntry:
    """One indexable unit, located precisely enough to re-open it."""

    entry_id: str
    source_path: str
    start_line: int
    end_line: int
    language: str
    content: str
    heading_path: list[str] = field(default_factory=list)
    kind_hint: str = "payload"


def slugify(text: str) -> str:
    text = str(text)
    cleaned = []
    for char in text.lower():
        if char.isalnum():
            cleaned.append(char)
        elif char in " -_/.":
            cleaned.append("_")
    slug = "".join(cleaned).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug


def iter_markdown_files() -> list[Path]:
    files = []
    for path in sorted(REPO_ROOT.rglob("*.md")):
        relative = path.relative_to(REPO_ROOT)
        if len(relative.parts) < 2:
            continue
        top = relative.parts[0]
        if top in NON_CHAPTER_DIRS:
            continue
        files.append(path)
    return files


def iter_wordlist_files() -> list[Path]:
    files = []
    for path in sorted(REPO_ROOT.rglob("*.txt")):
        relative = path.relative_to(REPO_ROOT)
        if relative.parts[0] in NON_CHAPTER_DIRS:
            continue
        files.append(path)
    return files


def _heading_stack_titles(stack: list[tuple[int, str]]) -> list[str]:
    return [title for _, title in stack]


def _looks_like_program(language: str, content: str) -> bool:
    """Heuristic separating programs from attacker-controlled input."""
    stripped = content.strip()
    # A fenced block whose every line is a template expression is a payload
    # collection, even when the fence carries a programming language tag.
    if TEMPLATE_MARKER.search(stripped) and not PROGRAM_CONTROL.search(stripped):
        return False
    # Single-line template/test expressions ({{7*7}}, ${7*7}) are payloads.
    if "\n" not in stripped and re.fullmatch(r"[`'\"{}$0-9a-zA-Z _.*=()\[\]:,/+-]+", stripped):
        if not any(keyword in stripped for keyword in ("function", "class", "import", "def ", "return")):
            return False
    lowered = language.lower()
    if language in PROGRAMMING_LANGUAGES or lowered in PROGRAMMING_LANGUAGES:
        return True
    # Untagged / shell blocks can still be full scripts.
    script_markers = (
        "<?php",
        "import ",
        "def ",
        "func ",
        "function ",
        "class ",
        "require(",
        "console.log",
        "System.out",
        "Runtime.getRuntime",
    )
    if any(marker in content for marker in script_markers):
        return True
    return False


def extract_fenced_entries() -> list[RawEntry]:
    entries: list[RawEntry] = []
    for markdown_path in iter_markdown_files():
        entries.extend(_extract_from_file(markdown_path))
    return entries


def _extract_from_file(markdown_path: Path) -> list[RawEntry]:
    relative = markdown_path.relative_to(REPO_ROOT)
    file_slug = slugify(relative.with_suffix(""))
    lines = markdown_path.read_text(encoding="utf-8", errors="replace").splitlines()

    heading_stack: list[tuple[int, str]] = []
    entries: list[RawEntry] = []
    counter = 0
    in_fence = False
    fence_marker = ""
    fence_language = ""
    fence_start = 0
    buffer: list[str] = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if not in_fence:
            if stripped.startswith("#"):
                level = len(stripped) - len(stripped.lstrip("#"))
                title = stripped[level:].strip()
                while heading_stack and heading_stack[-1][0] >= level:
                    heading_stack.pop()
                heading_stack.append((level, title))
                continue
            if stripped.startswith(FENCE_CHARS):
                marker = "```" if stripped.startswith("```") else "~~~"
                in_fence = True
                fence_marker = marker
                fence_language = stripped[len(marker):].strip().lower()
                fence_start = line_number
                buffer = []
                continue
        else:
            if stripped.startswith(fence_marker):
                content = "\n".join(buffer).strip("\n")
                if content.strip():
                    counter += 1
                    kind_hint = (
                        "code_sample"
                        if _looks_like_program(fence_language, content)
                        else "payload"
                    )
                    entries.append(
                        RawEntry(
                            entry_id=f"{file_slug}-{counter:03d}",
                            source_path=str(relative),
                            start_line=fence_start,
                            end_line=line_number,
                            language=fence_language,
                            content=content,
                            heading_path=_heading_stack_titles(heading_stack),
                            kind_hint=kind_hint,
                        )
                    )
                in_fence = False
                fence_marker = ""
                fence_language = ""
                buffer = []
                continue
            buffer.append(line)
    return entries


def extract_wordlist_entries() -> list[RawEntry]:
    entries: list[RawEntry] = []
    for path in iter_wordlist_files():
        relative = path.relative_to(REPO_ROOT)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        meaningful = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
        content = "\n".join(meaningful)
        entries.append(
            RawEntry(
                entry_id=f"{slugify(relative.with_suffix(''))}-wl",
                source_path=str(relative),
                start_line=1,
                end_line=len(lines),
                language="wordlist",
                content=content,
                heading_path=[relative.parts[0]],
                kind_hint="wordlist",
            )
        )
    return entries


def content_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:12]


def extract_all() -> list[RawEntry]:
    return extract_fenced_entries() + extract_wordlist_entries()
