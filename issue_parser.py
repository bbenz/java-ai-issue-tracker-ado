"""Parse security vulnerability descriptions from ADO work items."""

import html
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    title: str
    severity: str  # Critical | High | Medium | Low
    snyk_url: str
    vulnerable_package: str  # groupId:artifactId
    vulnerable_version: str
    dependency_chain: str
    fix_version: str
    root_dependency: str


@dataclass
class WorkItemAnalysis:
    work_item_id: int
    work_item_title: str
    priority: int
    parent_project: str  # SpringAI | LangChain4j | Unknown
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    # Per-vulnerability results: list of (vuln, category, detail, extra_info)
    results: list[tuple] = field(default_factory=list)
    overall_category: str = "PARSE_ERROR"
    is_resolved: bool = False
    raw_description: str = ""


# -- HTML stripping -----------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]+>")
_ENTITY_RE = re.compile(r"&\w+;")


def _strip_html(text: str) -> str:
    """Remove HTML tags and decode entities."""
    text = _TAG_RE.sub(" ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


# -- Snyk description parser -------------------------------------------------

# Pattern: matches [Severity Severity][url] in pkg@ver introduced by chain
# Fix version line is optional (some Snyk entries don't have it)
_BODY_RE = re.compile(
    r"\[(Critical|High|Medium|Low)\s+Severity\]\s*"
    r"\[(https?://security\.snyk\.io/vuln/[^\]]+)\]\s*"
    r"in\s+([\w._-]+:[\w._-]+)@([\w._+-]+)\s+"
    r"introduced\s+by\s+(.+?)"
    r"(?:\s+This\s+issue\s+was\s+fixed\s+in\s+versions?:\s*([\d][\w._-]*))?",
    re.DOTALL,
)

# Secondary pattern to catch "Upgrade X to Y to fix" directives
_UPGRADE_RE = re.compile(
    r"Upgrade\s+([\w._-]+:[\w._-]+)@[\w._+-]+\s+to\s+"
    r"([\w._-]+:[\w._-]+)@([\w._+-]+)\s+to\s+fix"
)

# Known vulnerability title keywords (used for title extraction)
_KNOWN_TITLES = [
    "Denial of Service (DoS)",
    "Denial of Service",
    "Information Exposure",
    "Information Disclosure",
    "Remote Code Execution",
    "Cross-site Scripting (XSS)",
    "Cross-site Scripting",
    "SQL Injection",
    "Path Traversal",
    "Directory Traversal",
    "XML External Entity (XXE)",
    "XML External Entity",
    "Server-Side Request Forgery (SSRF)",
    "Server-Side Request Forgery",
    "Prototype Pollution",
    "Regular Expression Denial of Service (ReDoS)",
    "Regular Expression Denial of Service",
    "Authentication Bypass",
    "Buffer Overflow",
    "Command Injection",
    "Insecure Defaults",
    "Integer Overflow",
    "Memory Leak",
    "Out-of-bounds Read",
    "Out-of-bounds Write",
    "Race Condition",
    "Type Confusion",
    "Use After Free",
    "Uncontrolled Resource Consumption",
    "Improper Input Validation",
    "Arbitrary Code Execution",
    "Deserialization of Untrusted Data",
    "Insufficient Verification of Data Authenticity",
    "Allocation of Resources Without Limits or Throttling",
    "Remote Code Execution (RCE)",
    "XML External Entity (XXE) Injection",
    "Stack-based Buffer Overflow",
    "Incorrect Authorization",
    "Relative Path Traversal",
    "Open Redirect",
    "Improper Output Neutralization for Logs",
    "Cross-Site Tracing (XST)",
    "Multipart Content Pollution",
    "Improper Handling of Case Sensitivity",
    "Uncontrolled Recursion",
    "External Initialization of Trusted Variables or Data Stores",
]


def _extract_title(pre_text: str) -> str:
    """Extract the vulnerability title from text preceding a [Severity] marker."""
    if not pre_text:
        return "Unknown"

    # Check for known title at end of pre_text
    for known in sorted(_KNOWN_TITLES, key=len, reverse=True):
        if pre_text.rstrip().endswith(known):
            return known

    # Fallback: take the last "phrase" after removing package identifiers
    cleaned = re.sub(r"[\w._-]+:[\w._-]+(?:@[\w._+-]+)?", "", pre_text)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if cleaned:
        parts = [p.strip() for p in re.split(r"\s{2,}|\n", cleaned) if p.strip()]
        if parts:
            return parts[-1]

    return "Unknown"


def parse_issue_description(description: str) -> list[Vulnerability]:
    """Parse a security scanner work item description into vulnerability records."""
    text = _strip_html(description)
    if not text:
        return []

    # Strategy: find all [Severity][url] markers and parse from each
    severity_re = re.compile(
        r"\[(Critical|High|Medium|Low)\s+Severity\]\s*"
        r"\[(https?://security\.snyk\.io/vuln/[^\]]+)\]\s*"
        r"in\s+([\w._-]+:[\w._-]+)@([\w._+-]+)\s+"
        r"introduced\s+by\s+"
    )

    markers = list(severity_re.finditer(text))
    if not markers:
        logger.debug("No vulnerability pattern found in description")
        return []

    vulns: list[Vulnerability] = []
    seen_keys: set[str] = set()  # deduplicate by snyk_url
    prev_end = 0

    for i, m in enumerate(markers):
        # Extract the chain text: from end of "introduced by" to start of next marker
        chain_start = m.end()
        if i + 1 < len(markers):
            # Find the boundary — look for known title keywords or next severity marker
            chain_end = markers[i + 1].start()
        else:
            chain_end = len(text)

        chain_text = text[chain_start:chain_end].strip()

        # Clean up chain text — stop at "This issue was fixed" or "Upgrade X to Y"
        # or at the next vulnerability title
        fix_version = ""
        fix_match = re.search(
            r"\s*This\s+issue\s+was\s+fixed\s+in\s+versions?:\s*([\d][\w._-]*)",
            chain_text,
        )
        if fix_match:
            fix_version = fix_match.group(1)
            chain_text = chain_text[: fix_match.start()].strip()

        # Check for "Upgrade X to Y@version to fix" pattern
        if not fix_version:
            upgrade_match = _UPGRADE_RE.search(chain_text)
            if upgrade_match:
                fix_version = upgrade_match.group(3)
                chain_text = chain_text[: upgrade_match.start()].strip()

        # Trim chain at known title boundaries (next vuln starts here)
        for known in sorted(_KNOWN_TITLES, key=len, reverse=True):
            idx = chain_text.find(known)
            if idx > 0:
                chain_text = chain_text[:idx].strip()
                break

        # Also trim at "org.springframework.ai:" which is a module name separator
        module_match = re.search(
            r"\s+(?:org\.springframework\.ai|dev\.langchain4j):[a-z]",
            chain_text,
        )
        if module_match:
            chain_text = chain_text[: module_match.start()].strip()

        # Clean up: remove trailing "and X other path(s)"
        chain_text = re.sub(r"\s+and\s+\d+\s+other\s+path\(s\)\s*$", "", chain_text).strip()

        # Extract title from pre-match text
        pre_text = text[prev_end : m.start()].strip()
        title = _extract_title(pre_text)

        # Root dependency
        if ">" in chain_text:
            root = chain_text.split(">")[0].strip().split("@")[0].strip()
        else:
            root = chain_text.split("@")[0].strip() if "@" in chain_text else chain_text

        # Deduplicate
        snyk_url = m.group(2)
        dedup_key = snyk_url
        if dedup_key in seen_keys:
            prev_end = m.end()
            continue
        seen_keys.add(dedup_key)

        vulns.append(
            Vulnerability(
                title=title,
                severity=m.group(1),
                snyk_url=snyk_url,
                vulnerable_package=m.group(3),
                vulnerable_version=m.group(4),
                dependency_chain=chain_text,
                fix_version=fix_version,
                root_dependency=root,
            )
        )
        prev_end = m.end()

    return vulns


# -- Parent project detection ------------------------------------------------

# Map of known field values to canonical project names
_PROJECT_MAP = {
    "springai": ("SpringAI", "spring-projects", "spring-ai"),
    "langchain4j": ("LangChain4j", "langchain4j", "langchain4j"),
}


def detect_parent_project(
    work_item_fields: dict, project_field: str | None = None
) -> tuple[str, str, str]:
    """
    Detect which target project a work item belongs to.

    Returns (display_name, github_owner, github_repo) or ("Unknown", "", "").
    """
    # If a specific field name is given, check it first
    if project_field:
        value = work_item_fields.get(project_field, "")
        if value:
            key = value.strip().lower()
            if key in _PROJECT_MAP:
                return _PROJECT_MAP[key]

    # Auto-detect: scan all field values for known project names
    for _field_name, value in work_item_fields.items():
        if not isinstance(value, str):
            continue
        key = value.strip().lower()
        if key in _PROJECT_MAP:
            return _PROJECT_MAP[key]

    return ("Unknown", "", "")
