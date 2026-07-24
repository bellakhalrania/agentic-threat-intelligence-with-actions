"""
intelligence/ioc_extractor.py
Deterministic IOC extraction module.

Extracts IPv4, IPv6, domains, URLs, email addresses, MD5, SHA1, and SHA256
from normalized security events using regex and Python libraries only.
No LLM calls. Validates every IOC before returning it. Deduplicates.
Returns a list of IOCModel instances with type, value, source_event_id,
and confidence.
"""

import ipaddress
import re
from typing import Any, Dict, List, Set

from databases.models import IOCModel


# ── Regex patterns ──────────────────────────────────────────────────────

# IPv4: four octets 0-255
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# IPv6: stricter pattern to avoid false positives from command-line syntax like "::debug"
# Matches proper IPv6 structure with word boundaries and minimum length
IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"  # Full form (8 groups)
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"  # Leading groups with :: at end
    r"\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|"  # :: at start with trailing groups
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|"  # :: in middle
    r"\[?[0-9a-fA-F:]{2,}\]?"  # Bracketed form (for URLs)
)

# MD5: exactly 32 hex chars
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# SHA1: exactly 40 hex chars
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")

# SHA256: exactly 64 hex chars
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# URL: protocol://... stopping at whitespace or common delimiters
URL_RE = re.compile(r"https?://[^\s\"'<>\[\]{}|\\^`]+")

# Domain: at least two labels, no trailing dot, TLD at least 2 alpha chars
# Excludes common file extensions (.exe, .dll, .ps1, etc.) to avoid false positives
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)

# Common file extensions to exclude from domain extraction
FILE_EXTENSIONS = {
    "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "jar", "sh", "py", "pl",
    "rb", "php", "asp", "aspx", "jsp", "html", "htm", "css", "json", "xml",
    "txt", "log", "cfg", "ini", "conf", "bin", "dat", "tmp", "bak", "old",
    "zip", "tar", "gz", "rar", "7z", "iso", "img", "pdf", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "mdb", "accdb", "sql", "db", "sqlite"
}

# Email: local@domain.tld, per RFC 5322 simplified
EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\."
    r"[a-zA-Z]{2,}\b"
)


# ── IP validation helpers ───────────────────────────────────────────────


def _is_valid_ipv4(candidate: str) -> bool:
    """Return True if candidate is a valid, routable IPv4 address.

    Excludes loopback, private (RFC 1918), link-local, multicast,
    and unspecified addresses — these are not actionable as threat IOCs.
    Documentation / TEST-NET ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) ARE allowed since they appear in real security tooling.
    """
    try:
        addr = ipaddress.IPv4Address(candidate)
    except ipaddress.AddressValueError:
        return False
    if addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    # Exclude RFC 1918 private ranges, but allow TEST-NET ranges
    if addr.is_private:
        # TEST-NET ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
        test_net_ranges = [
            ipaddress.IPv4Network("192.0.2.0/24"),
            ipaddress.IPv4Network("198.51.100.0/24"),
            ipaddress.IPv4Network("203.0.113.0/24"),
        ]
        if not any(addr in net for net in test_net_ranges):
            return False
    return True


def _is_valid_ipv6(candidate: str) -> bool:
    """Return True if candidate is a valid, non-private IPv6 address.
    
    Excludes loopback, link-local, unique-local, multicast, and unspecified.
    Allows documentation ranges (2001:db8::/32) for testing.
    Allows IPv4-mapped addresses (::ffff:x.x.x.x) as they represent public IPv4.
    """
    clean = candidate.strip("[]")
    
    # Additional validation: reject obviously invalid patterns
    # Reject single-letter or very short segments that are likely command-line syntax
    if "::" in clean:
        parts = clean.split("::")
        # If any segment is a single hex char, it's likely command syntax like "e::debug"
        for part in parts:
            if part and len(part) == 1 and part in "0123456789abcdefABCDEF":
                return False
    
    try:
        addr = ipaddress.IPv6Address(clean)
    except (ipaddress.AddressValueError, ValueError):
        return False
    if addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_unspecified:
        return False
    # IPv4-mapped addresses (::ffff:x.x.x.x) are allowed - they represent public IPv4
    if addr.ipv4_mapped is not None:
        # Validate the underlying IPv4 is public
        return _is_valid_ipv4(str(addr.ipv4_mapped))
    # Exclude unique-local (fc00::/7) but allow documentation (2001:db8::/32)
    if addr.is_private:
        # Documentation range: 2001:db8::/32
        doc_range = ipaddress.IPv6Network("2001:db8::/32")
        if addr not in doc_range:
            return False
    # Must have at least one colon to be a valid IPv6
    if ":" not in candidate:
        return False
    return True


# ── Value-to-string helpers ─────────────────────────────────────────────


def _flatten_to_strings(value: Any) -> List[str]:
    """Recursively flatten a value into a list of its string representations.

    Handles nested dicts, lists, tuples, None, bool, int, etc.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        result: List[str] = []
        for item in value:
            result.extend(_flatten_to_strings(item))
        return result
    if isinstance(value, dict):
        result: List[str] = []
        for v in value.values():
            result.extend(_flatten_to_strings(v))
        return result
    # bool must come before int because bool is a subclass of int
    if isinstance(value, bool):
        return []
    if isinstance(value, (int, float)):
        # Don't extract IOCs from pure numbers, but keep as string context
        return [str(value)]
    return [str(value)]


def _build_text_blob(event: Dict) -> str:
    """Build a single searchable text string from all values in the event.

    Recursively flattens nested dicts and lists.
    """
    parts: List[str] = []
    for v in event.values():
        parts.extend(_flatten_to_strings(v))
    return " ".join(parts)


# ── Main extraction ─────────────────────────────────────────────────────


def extract_iocs(events: List[Dict]) -> List[IOCModel]:
    """Extract and validate IOCs from a list of normalized event dicts.

    For each event, the function scans all string values for IOC patterns,
    validates each candidate, deduplicates across all events, and returns
    a flat list of ``IOCModel`` instances.

    Args:
        events: List of normalized event dictionaries (as produced by
            ``CollectionAgent.run``).

    Returns:
        A list of deduplicated, validated ``IOCModel`` instances.
    """
    seen: Set[str] = set()
    results: List[IOCModel] = []

    for event in events:
        event_id = event.get("event_id") or event.get("source_event_id")
        blob = _build_text_blob(event)

        # ── IPv4 ─────────────────────────────────────────────────────
        for candidate in IPV4_RE.findall(blob):
            if candidate in seen:
                continue
            if not _is_valid_ipv4(candidate):
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="ipv4", value=candidate, source_event_id=event_id)
            )

        # ── IPv6 ─────────────────────────────────────────────────────
        # First, try to match IPv4-mapped addresses specifically
        ipv4_mapped_re = re.compile(r"::ffff:(?:\d{1,3}\.){3}\d{1,3}")
        for candidate in ipv4_mapped_re.findall(blob):
            if candidate in seen:
                continue
            if not _is_valid_ipv6(candidate):
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="ipv6", value=candidate, source_event_id=event_id)
            )
        
        # Then match regular IPv6 patterns
        for candidate in IPV6_RE.findall(blob):
            if candidate in seen:
                continue
            if not _is_valid_ipv6(candidate):
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="ipv6", value=candidate, source_event_id=event_id)
            )

        # ── SHA256 (check before SHA1/MD5 to prevent shorter hash collisions) ──
        for candidate in SHA256_RE.findall(blob):
            if candidate in seen:
                continue
            if candidate == candidate[0] * 64:
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="sha256", value=candidate, source_event_id=event_id)
            )

        # ── SHA1 ─────────────────────────────────────────────────────
        for candidate in SHA1_RE.findall(blob):
            if candidate in seen:
                continue
            _underlying = SHA256_RE.search(blob)
            if _underlying and candidate in _underlying.group():
                continue
            if candidate == candidate[0] * 40:
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="sha1", value=candidate, source_event_id=event_id)
            )

        # ── MD5 ─────────────────────────────────────────────────────
        for candidate in MD5_RE.findall(blob):
            if candidate in seen:
                continue
            _underlying = SHA1_RE.search(blob) or SHA256_RE.search(blob)
            if _underlying and candidate in _underlying.group():
                continue
            if candidate == candidate[0] * 32:
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="md5", value=candidate, source_event_id=event_id)
            )

        # ── URLs (before domains, since domains can be extracted from URLs) ──
        for candidate in URL_RE.findall(blob):
            if candidate in seen:
                continue
            host_part = candidate.split("://", 1)[-1].split("/")[0].split("?")[0]
            if "." not in host_part:
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="url", value=candidate, source_event_id=event_id)
            )

        # ── Email addresses ──────────────────────────────────────────
        for candidate in EMAIL_RE.findall(blob):
            if candidate in seen:
                continue
            if any("://" + candidate.split("@")[-1] in s for s in seen):
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="email", value=candidate, source_event_id=event_id)
            )

        # ── Domains ──────────────────────────────────────────────────
        for candidate in DOMAIN_RE.findall(blob):
            if candidate in seen:
                continue
            if any(candidate in s for s in seen):
                continue
            if IPV4_RE.fullmatch(candidate):
                continue
            # Skip domains that are part of email addresses
            skip_domain = False
            if "@" in blob:
                for email_match in EMAIL_RE.finditer(blob):
                    email = email_match.group()
                    email_domain = email.split("@")[-1]
                    if candidate == email_domain or candidate in email_domain:
                        skip_domain = True
                        break
            if skip_domain:
                continue
            # Skip common file extensions (e.g., powershell.exe)
            tld = candidate.split(".")[-1].lower()
            if tld in FILE_EXTENSIONS:
                continue
            seen.add(candidate)
            results.append(
                IOCModel(type="domain", value=candidate, source_event_id=event_id)
            )

    return results


# ── Convenience alias to match old import style ─────────────────────────
def extract_iocs_from_event(event: Dict) -> List[IOCModel]:
    """Extract IOCs from a single event dict.

    Wraps the event in a list and delegates to ``extract_iocs``.
    """
    return extract_iocs([event])