"""Content markers and the precondition rules derived from them.

This module is the single source of truth shared by the index builder and the
index validator. A marker is a regex searched in a payload's text (and, for
some markers, in the surrounding Markdown heading). When a marker matches, the
mapped precondition *must* be declared on the entry. Validator rule E002 fails
any entry whose content carries a marker without the matching precondition -
that is exactly the "dependency premise not written down" class of error.
"""

from __future__ import annotations

import re

# --- Placeholder / sanitization markers ------------------------------------
# UPPERCASE_TOKENS covers [ATTACKER.DOMAIN.TLD], {FILE}, %USERID%, etc.
UPPERCASE_TOKENS = re.compile(r"[A-Z][A-Z0-9_]{2,}(?:\.[A-Z0-9_]+)*")
BRACKET_PLACEHOLDERS = re.compile(r"[\[{<][A-Za-z0-9_ .\-/]{2,40}[\]}>]")
CANONICAL_IPS = re.compile(r"\b10\.10\.10\.(10|11)\b")

# --- Callback / external interaction ---------------------------------------
CALLBACK_PATTERNS = [
    re.compile(r"attacker\.domain\.tld", re.IGNORECASE),
    re.compile(r"burpcollaborator", re.IGNORECASE),
    re.compile(r"xss\s?hunter", re.IGNORECASE),
    re.compile(r"interact\.sh", re.IGNORECASE),
    re.compile(r"canarytokens", re.IGNORECASE),
    re.compile(r"ngrok", re.IGNORECASE),
    re.compile(r"webhook\.site", re.IGNORECASE),
    re.compile(r"requestbin", re.IGNORECASE),
    re.compile(r"\bcallback\b", re.IGNORECASE),
    re.compile(r"\bcollaborator\b", re.IGNORECASE),
]

# --- Attacker hosted resources ----------------------------------------------
HOSTED_FILE_PATTERNS = [
    re.compile(r"https?://[^\s'\"]*evil[^/\s]*", re.IGNORECASE),
    re.compile(r"\bevil\.(com|php|js|txt|sh|exe|dll|jar|html)\b", re.IGNORECASE),
    re.compile(r"attacker-server", re.IGNORECASE),
    re.compile(r"https?://[^\s'\"]*malicious[^/\s]*", re.IGNORECASE),
]

# --- Authentication ----------------------------------------------------------
AUTH_PATTERNS = [
    re.compile(r"\bauthorization\s*:", re.IGNORECASE),
    re.compile(r"\bbearer\s+[a-z0-9._-]", re.IGNORECASE),
    re.compile(r"^cookie\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"\bset-cookie\s*:", re.IGNORECASE),
    re.compile(r"^sessionid\s*=", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^access_token\s*[:=]", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^xsrf-token\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^csrf[-_]token\s*:", re.IGNORECASE | re.MULTILINE),
]

# --- Internal network targets ------------------------------------------------
# Loopback names are only a real precondition when the payload asks the target
# to make a request (SSRF-like). In a browser payload "localhost" is simply the
# tester's own listener and must not imply internal network access.
LOOPBACK_PATTERNS = [
    re.compile(r"\b127\.0\.0\.1\b"),
    re.compile(r"\blocalhost\b", re.IGNORECASE),
    re.compile(r"\[::1\]"),
    re.compile(r"\b0\.0\.0\.0\b"),
    re.compile(r"\b0x7f\b", re.IGNORECASE),
]
INTERNAL_PATTERNS = [
    re.compile(r"\b169\.254\.169\.254\b"),
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\bmetadata\.google\.internal\b", re.IGNORECASE),
]
SERVER_SIDE_FETCH_HINT = re.compile(
    r"(ssrf|server[- ]side|curl|wget|fetch\s*\(|requests\.get|urllib|"
    r"gopher|dict|netdoc|metadata|webhook|forward|proxy)",
    re.IGNORECASE,
)

# --- External tooling --------------------------------------------------------
TOOL_PATTERNS = [
    re.compile(r"\bsqlmap\b", re.IGNORECASE),
    re.compile(r"\bysoserial\b", re.IGNORECASE),
    re.compile(r"\bburp\s?(suite|intruder|collaborator)\b", re.IGNORECASE),
    re.compile(r"\bnuclei\b", re.IGNORECASE),
    re.compile(r"\bgopherus\b", re.IGNORECASE),
    re.compile(r"\bffuf\b", re.IGNORECASE),
    re.compile(r"\bgobuster\b", re.IGNORECASE),
    re.compile(r"\bhydra\b", re.IGNORECASE),
    re.compile(r"\bmetasploit\b", re.IGNORECASE),
    re.compile(r"\bmsfconsole\b", re.IGNORECASE),
    re.compile(r"\bimpacket\b", re.IGNORECASE),
]

# --- Vulnerable version / CVE ------------------------------------------------
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# --- Specific technologies ---------------------------------------------------
# Two tiers on purpose:
# * STRONG_TECHNOLOGY_PATTERNS name concrete products/runtimes. A match in the
#   content is a real deployment precondition.
# * GENERIC_LANGUAGE_PATTERNS cover language names (PHP, Java, ...) that are
#   too common to force a precondition on their own: they only count when the
#   surrounding heading scopes the payload to that technology.
STRONG_TECHNOLOGY_PATTERNS = [
    (re.compile(r"\bapache\b", re.IGNORECASE), "Apache"),
    (re.compile(r"\bnginx\b", re.IGNORECASE), "Nginx"),
    (re.compile(r"\bIIS\b"), "IIS"),
    (re.compile(r"\btomcat\b", re.IGNORECASE), "Tomcat"),
    (re.compile(r"\bspring\b", re.IGNORECASE), "Spring"),
    (re.compile(r"\bstruts\b", re.IGNORECASE), "Struts"),
    (re.compile(r"\bjboss\b", re.IGNORECASE), "JBoss"),
    (re.compile(r"\bjetty\b", re.IGNORECASE), "Jetty"),
    (re.compile(r"\bwordpress\b", re.IGNORECASE), "WordPress"),
    (re.compile(r"\bdrupal\b", re.IGNORECASE), "Drupal"),
    (re.compile(r"\bjoomla\b", re.IGNORECASE), "Joomla"),
    (re.compile(r"\bnode\.?js\b", re.IGNORECASE), "Node.js"),
    (re.compile(r"\.net\b", re.IGNORECASE), ".NET"),
    (re.compile(r"\bmysql\b", re.IGNORECASE), "MySQL"),
    (re.compile(r"\bmssql\b", re.IGNORECASE), "MSSQL"),
    (re.compile(r"\bpostgre", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"\boracle\s?(db|database)?\b", re.IGNORECASE), "Oracle"),
    (re.compile(r"\bsqlite\b", re.IGNORECASE), "SQLite"),
    (re.compile(r"\bmongodb\b", re.IGNORECASE), "MongoDB"),
    (re.compile(r"\bredis\b", re.IGNORECASE), "Redis"),
    (re.compile(r"\belasticsearch\b", re.IGNORECASE), "Elasticsearch"),
    (re.compile(r"\bkubernetes\b", re.IGNORECASE), "Kubernetes"),
    (re.compile(r"\bdocker\b", re.IGNORECASE), "Docker"),
    (re.compile(r"\baws\b", re.IGNORECASE), "AWS"),
    (re.compile(r"\bgcp\b", re.IGNORECASE), "GCP"),
    (re.compile(r"\bazure\b", re.IGNORECASE), "Azure"),
    (re.compile(r"\bactive\s?directory\b", re.IGNORECASE), "Active Directory"),
    (re.compile(r"\bexchange\b", re.IGNORECASE), "Exchange"),
    (re.compile(r"\bweblogic\b", re.IGNORECASE), "WebLogic"),
    (re.compile(r"\bwebpack\b", re.IGNORECASE), "Webpack"),
    (re.compile(r"\bflash\b", re.IGNORECASE), "Flash"),
    (re.compile(r"\bsilverlight\b", re.IGNORECASE), "Silverlight"),
    (re.compile(r"\bsymfony\b", re.IGNORECASE), "Symfony"),
    (re.compile(r"\blaravel\b", re.IGNORECASE), "Laravel"),
    (re.compile(r"\bdjango\b", re.IGNORECASE), "Django"),
    (re.compile(r"\bflask\b", re.IGNORECASE), "Flask"),
    (re.compile(r"\brails\b", re.IGNORECASE), "Rails"),
    (re.compile(r"\bshiro\b", re.IGNORECASE), "Shiro"),
    (re.compile(r"\bfastjson\b", re.IGNORECASE), "Fastjson"),
    (re.compile(r"\blog4j\b", re.IGNORECASE), "Log4j"),
    (re.compile(r"\bwebview\b", re.IGNORECASE), "WebView"),
]

GENERIC_LANGUAGE_PATTERNS = [
    (re.compile(r"\bjava\b", re.IGNORECASE), "Java"),
    (re.compile(r"\bphp\b", re.IGNORECASE), "PHP"),
    (re.compile(r"\bpython\b", re.IGNORECASE), "Python"),
    (re.compile(r"\bruby\b", re.IGNORECASE), "Ruby"),
]

# --- Upload / deserialization / template engine ------------------------------
UPLOAD_PATTERN = re.compile(
    r"(multipart/form-data|filename=|enctype|content-disposition:\s*form-data|"
    r"move_uploaded_file|\.htaccess|web\.config)",
    re.IGNORECASE,
)
DESERIALIZATION_PATTERN = re.compile(
    r"(objectinputstream|readobject|ysoserial|pickle\.loads|marshal\.loads|"
    r"unserialize|__php_incomplete_class|java\.serialization|"
    r"binaryformatter|typehandler)",
    re.IGNORECASE,
)
TEMPLATE_ENGINE_PATTERN = re.compile(
    r"(\{\{[^}]*[*=(:0-9][^}]*\}\}|<%=.*%>|#\{[^}]*[a-zA-Z(][^}]*\}|freemarker|"
    r"velocity|thymeleaf|jinja2?|twig|smarty|mako|cheetah|pug|handlebars|mustache)",
    re.IGNORECASE,
)
DNS_CONTROL_PATTERN = re.compile(r"(dns\s?rebind|rebind|rbndr|nip\.io)", re.IGNORECASE)
OUTBOUND_CONNECTIVITY_PATTERN = re.compile(
    r"(curl\s+https?://|wget\s+https?://|Invoke-WebRequest|certutil\s+-urlcache|"
    r"bitsadmin\s+/transfer|\bnc\s+-e\b|bash -i\s+>&\s*/dev/tcp/|/dev/tcp/)",
    re.IGNORECASE,
)
BROWSER_INTERACTION_PATTERN = re.compile(
    r"(victim|user\s+(?:visits|clicks)|open\s+(?:the|this)\s+link|"
    r"send\s+(?:the\s+)?link|csrf\s+poc)",
    re.IGNORECASE,
)

# Markers that force a precondition on every matching entry.
PRECONDITION_RULES = [
    ("requires_callback_server", CALLBACK_PATTERNS),
    ("requires_attacker_hosted_file", HOSTED_FILE_PATTERNS),
    ("requires_authenticated_session", AUTH_PATTERNS),
    ("requires_internal_network_access", INTERNAL_PATTERNS),
    ("requires_interactive_tool", TOOL_PATTERNS),
]


def has_placeholder(text: str) -> bool:
    """True when the payload needs a substitution before it can run."""
    if CANONICAL_IPS.search(text):
        return True
    for match in BRACKET_PLACEHOLDERS.finditer(text):
        token = match.group(0)
        inner = token[1:-1]
        # Real language syntax such as array[0] or obj["k"] is not a
        # placeholder: require at least one letter and a space/dot/underscore
        # or an all-caps token.
        if re.search(r"[A-Za-z]", inner) and (
            " " in inner or "_" in inner or "." in inner or inner.isupper()
        ):
            return True
    for match in UPPERCASE_TOKENS.finditer(text):
        token = match.group(0)
        # SQL keywords and HTTP verbs are uppercase but not placeholders.
        if token in {"SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "FROM",
                     "WHERE", "OR", "AND", "NULL", "HTTP", "HTTPS", "GET",
                     "POST", "PUT", "HEAD", "HOST", "SET", "DROP", "TABLE",
                     "EXEC", "EXECUTE", "WAITFOR", "DELAY", "CONCAT",
                     "VERSION", "DATABASE", "USER", "COUNT", "GROUP",
                     "ORDER", "BY", "ON", "INTO", "VALUES", "CAST", "CHAR",
                     "COOKIE", "HTML", "URL", "URI", "JSON", "XML", "CSS",
                     "PHP", "API", "ID", "UUID", "JWT", "CSRF", "XSS",
                     "SSRF", "RCE", "SQL", "DNS", "IP", "TCP", "UDP",
                     "LDAP", "SAML", "SSO", "S3", "EC2", "IAM", "FTP",
                     "SMTP", "DOS", "XXE", "CORS", "CSP", "DOM"}:
            continue
        return True
    return False


def detect_technologies(text: str, heading: str) -> list[str]:
    """Ordered, de-duplicated technology names referenced by an entry."""
    found: list[str] = []
    for pattern, name in STRONG_TECHNOLOGY_PATTERNS:
        if pattern.search(text) and name not in found:
            found.append(name)
    for pattern, name in GENERIC_LANGUAGE_PATTERNS:
        if pattern.search(f"{heading}\n{text}") and name not in found:
            found.append(name)
    return found


def required_preconditions(text: str, heading: str) -> dict[str, list[str]]:
    """Derive every precondition forced by content markers.

    Returns a mapping of precondition -> matched marker strings. The matched
    strings are surfaced by the validator so an annotation failure points at
    the exact dependency that was not written down.
    """
    required: dict[str, list[str]] = {}

    def add(precondition: str, evidence: str) -> None:
        required.setdefault(precondition, []).append(evidence)

    if has_placeholder(text):
        add("requires_placeholder_replacement", "placeholder token")

    for precondition, patterns in PRECONDITION_RULES:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                add(precondition, match.group(0))
                break

    loopback_hit = next((p.search(text) for p in LOOPBACK_PATTERNS if p.search(text)), None)
    if loopback_hit and SERVER_SIDE_FETCH_HINT.search(f"{heading}\n{text}"):
        add("requires_internal_network_access", loopback_hit.group(0))

    # Upload capability only applies when the payload itself is the uploaded
    # artifact or an upload request, not when a filename merely appears.
    if UPLOAD_PATTERN.search(text):
        add("requires_file_upload_capability", "upload marker")
    if DESERIALIZATION_PATTERN.search(text):
        add("requires_deserialization_gadget", "deserialization marker")
    if TEMPLATE_ENGINE_PATTERN.search(text):
        add("requires_template_engine", "template expression")
    if CVE_PATTERN.search(text):
        add("requires_vulnerable_software_version", CVE_PATTERN.search(text).group(0))
    if DNS_CONTROL_PATTERN.search(f"{heading}\n{text}"):
        add("requires_dns_control", "dns rebinding marker")
    if OUTBOUND_CONNECTIVITY_PATTERN.search(text):
        add("requires_outbound_connectivity", "egress fetch marker")
    if BROWSER_INTERACTION_PATTERN.search(f"{heading}\n{text}"):
        add("requires_browser_interaction", "victim interaction marker")

    technologies = detect_technologies(text, heading)
    if technologies:
        add("requires_specific_technology", ", ".join(technologies[:5]))

    return required
