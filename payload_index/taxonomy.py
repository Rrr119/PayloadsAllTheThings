"""Controlled vocabularies for the payload index.

Every indexed payload is described with values drawn from the enums below.
Keeping a closed vocabulary is what makes the index *structured* instead of
another full-text dump: validation can prove that every entry is filterable.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Top level directories that are documentation/meta folders, not attack
# surfaces. Everything else at the repository root is treated as a chapter.
NON_CHAPTER_DIRS = {
    ".git",
    ".github",
    "artifacts",
    "payload_index",
    "_LEARNING_AND_SOCIALS",
    "_template_vuln",
}

# Fenced code blocks written in these languages describe programs (vulnerable
# code, listeners, helper scripts) rather than attacker-controlled input.
PROGRAMMING_LANGUAGES = {
    "python",
    "py",
    "php",
    "java",
    "ruby",
    "rb",
    "csharp",
    "cs",
    "go",
    "rs",
    "rust",
    "c",
    "cpp",
    "groovy",
    "erlang",
    "scala",
    "kotlin",
    "perl",
    "swift",
    "lua",
}

# Fenced code blocks whose language tag already tells us the execution context.
LANGUAGE_CONTEXT = {
    "sql": "sql",
    "html": "html",
    "xml": "xml",
    "javascript": "javascript",
    "js": "javascript",
    "json": "json",
    "css": "css",
    "tex": "latex",
    "yaml": "yaml",
    "yml": "yaml",
    "ini": "config",
    "apache": "config",
    "twig": "template",
    "handlebars": "template",
    "http": "http",
    "bash": "shell",
    "sh": "shell",
    "ps1": "shell",
}

# Where the attacker-controlled data ends up being interpreted.
CONTEXTS = {
    "sql",
    "html",
    "javascript",
    "xml",
    "json",
    "css",
    "latex",
    "template",
    "http",
    "shell",
    "header",
    "url",
    "file_path",
    "file_content",
    "config",
    "yaml",
    "ldap_filter",
    "xpath_expr",
    "graphql",
    "nosql_query",
    "expression",
    "token",
    "domain",
    "binary",
    "other",
}

# How the payload reaches the target.
PROTOCOLS = {
    "http",
    "https",
    "websocket",
    "dns",
    "smtp",
    "ftp",
    "file",
    "gopher",
    "dict",
    "ldap",
    "netdoc",
    "jar",
    "data",
    "javascript",
    "vbscript",
    "cli",
    "local",
    "other",
}

# Concrete injection point of an HTTP-borne payload.
INJECTION_POINTS = {
    "query_param",
    "post_body",
    "json_field",
    "http_header",
    "cookie",
    "url_path",
    "host_header",
    "multipart_upload",
    "fragment",
    "websocket_message",
    "graphql_variable",
    "file_name",
    "template_variable",
    "environment",
    "configuration_file",
    "other",
}

# What has to exist / be prepared before the payload can work.
PRECONDITIONS = {
    # Infrastructure the tester must operate.
    "requires_callback_server",
    "requires_attacker_hosted_file",
    # Payload hygiene.
    "requires_placeholder_replacement",
    # Target state.
    "requires_authenticated_session",
    "requires_internal_network_access",
    "requires_specific_technology",
    "requires_file_upload_capability",
    "requires_deserialization_gadget",
    "requires_template_engine",
    "requires_vulnerable_software_version",
    "requires_dns_control",
    "requires_browser_interaction",
    "requires_outbound_connectivity",
    "requires_interactive_tool",
}

ENTRY_KINDS = {"payload", "wordlist", "code_sample", "detection_string"}

EXECUTABILITY = {
    # Paste-and-go, no substitution or extra step required.
    "direct",
    # Works as soon as bracketed placeholders are replaced.
    "templated",
    # One step of a multi-request / multi-stage exploit chain.
    "multi_step",
    # Must be fed through an external tool first (sqlmap, ysoserial, ...).
    "tool_generated",
    # Reusable fuzz wordlist, not a single standalone payload.
    "fuzz_list",
    # Explanatory vulnerable/helper code; not directly executable as attack.
    "not_executable",
    # Benign marker used only to observe reflection / execution.
    "verification_only",
}


def chapter_slug(path: Path) -> str:
    """Stable snake_case identifier for a chapter directory."""
    relative = path.relative_to(REPO_ROOT)
    return relative.parts[0].lower().replace(" ", "_").replace("-", "_")


def discover_chapters() -> list[str]:
    """Return the controlled vector vocabulary from the on-disk chapters."""
    chapters = []
    for child in sorted(REPO_ROOT.iterdir()):
        if not child.is_dir() or child.name in NON_CHAPTER_DIRS:
            continue
        chapters.append(chapter_slug(child))
    return sorted(chapters)


VECTORS = set(discover_chapters())
