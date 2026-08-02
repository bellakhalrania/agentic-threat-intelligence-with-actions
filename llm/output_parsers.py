"""
llm/output_parsers.py
LLMs occasionally wrap JSON in markdown fences or add stray prose. These
helpers defensively extract and parse JSON from raw model output.
"""

import json
import re
from typing import Any


def _sanitize_json_for_parse(raw: str) -> str:
    """Pre-process LLM JSON text to handle common escape issues.

    The most common problem is unescaped backslashes in Windows file
    paths (e.g. ``C:\\Users\\...``) which ``json.loads`` interprets as
    invalid escape sequences like ``\\U``.  We fix these by escaping
    lone backslashes before the standard JSON parser runs.
    """
    # Double any backslash that is NOT already part of a valid JSON escape
    # (\\, \", \/, \b, \f, \n, \r, \t, \uXXXX)
    # This regex matches a backslash followed by any char that is NOT
    # one of the valid JSON escape continuations.
    result = []
    i = 0
    while i < len(raw):
        if raw[i] == "\\":
            if i + 1 < len(raw):
                nxt = raw[i + 1]
                if nxt in ('"', '\\', '/', 'b', 'f', 'n', 'r', 't'):
                    # Valid JSON escape — keep as-is
                    result.append(raw[i])
                    result.append(nxt)
                    i += 2
                    continue
                elif nxt == "u":
                    # Could be \uXXXX — check if we have 4 hex digits
                    if i + 5 < len(raw) and all(c in "0123456789abcdefABCDEF" for c in raw[i+2:i+6]):
                        # Valid \uXXXX — keep as-is
                        result.append(raw[i])
                        result.append(nxt)
                        result.extend(raw[i+2:i+6])
                        i += 6
                        continue
                # Otherwise this is an unescaped backslash (e.g. in C:\Users)
                # Escape it by doubling it
                result.append("\\\\")
                result.append(nxt)
                i += 2
                continue
            else:
                # Trailing single backslash at end of string — escape it
                result.append("\\\\")
                i += 1
                continue
        result.append(raw[i])
        i += 1
    return "".join(result)


def extract_json(text: str) -> Any:
    """Extract and parse the first JSON object or array found in `text`."""
    cleaned = text.strip()

    # Strip ```json ... ``` or ``` ... ``` fences
    fence_match = re.search(r"```(?:json)?\s*(.*?)```", cleaned, re.DOTALL)
    if fence_match:
        cleaned = fence_match.group(1).strip()

    # Sanitize backslash escapes before JSON parsing
    sanitized = _sanitize_json_for_parse(cleaned)

    try:
        return json.loads(sanitized)
    except json.JSONDecodeError:
        pass

    # Fall back to grabbing the first {...} or [...] block
    obj_match = re.search(r"(\{.*\}|\[.*\])", cleaned, re.DOTALL)
    if obj_match:
        try:
            sanitized_block = _sanitize_json_for_parse(obj_match.group(1))
            return json.loads(sanitized_block)
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse JSON from LLM output: {text[:300]}")
