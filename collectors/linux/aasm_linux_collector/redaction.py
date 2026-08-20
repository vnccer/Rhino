from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|token|api[_-]?key|secret|authorization|cookie)\b\s*[:=]\s*)([^\s,;]+)"
)
_OPTION = re.compile(
    r"(?i)(--?(?:password|passwd|token|api[_-]?key|secret|authorization|cookie)(?:\s+|=))([^\s]+)"
)
_BEARER = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+")
_HEADER = re.compile(r"(?i)(\b(?:Authorization|Cookie|Set-Cookie)\s*:\s*)([^'\"\r\n]+)")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_KNOWN_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?(?:-----END(?: [A-Z0-9]+)? PRIVATE KEY-----|$)",
    re.DOTALL,
)


def redact_text(value: str, max_length: int = 512) -> tuple[str, int]:
    count = 0

    def replace_secret(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return f"{match.group(1)}{REDACTED}"

    result = _PRIVATE_KEY.sub(REDACTED, value)
    if result != value:
        count += 1
    result = _HEADER.sub(replace_secret, result)
    result = _ASSIGNMENT.sub(replace_secret, result)
    result = _OPTION.sub(replace_secret, result)
    result = _BEARER.sub(replace_secret, result)
    aws_matches = len(_AWS_KEY.findall(result))
    if aws_matches:
        count += aws_matches
        result = _AWS_KEY.sub(REDACTED, result)
    known_matches = len(_KNOWN_TOKEN.findall(result))
    if known_matches:
        count += known_matches
        result = _KNOWN_TOKEN.sub(REDACTED, result)
    if len(result) > max_length:
        result = result[: max(0, max_length - 11)] + "...[TRUNCATED]"
    return result, count


def redact_mapping(value: Any, max_length: int = 512) -> tuple[Any, int]:
    if isinstance(value, str):
        return redact_text(value, max_length)
    if isinstance(value, list):
        output: list[Any] = []
        count = 0
        for item in value:
            cleaned, item_count = redact_mapping(item, max_length)
            output.append(cleaned)
            count += item_count
        return output, count
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        count = 0
        for key, item in value.items():
            if re.fullmatch(
                r"(?i)(password|passwd|pwd|token|api[_-]?key|secret|authorization|cookie)",
                str(key),
            ):
                output[str(key)] = REDACTED
                count += 1
            else:
                cleaned, item_count = redact_mapping(item, max_length)
                output[str(key)] = cleaned
                count += item_count
        return output, count
    return value, 0
