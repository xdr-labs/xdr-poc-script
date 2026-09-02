"""Raw JSONL bundle content validation before parse/import."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_EXIT_CODE_MARKER = re.compile(rb"\n__EXIT_CODE:\d+\s*$")
_PRE_BLOCK_RE = re.compile(rb"<pre[^>]*>(.*?)</pre>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(rb"<[^>]+>")
_CONTENT_PREVIEW_BYTES = 200

_HTML_PREFIXES = (b"<!doctype", b"<html", b"<head", b"<body")
_SHELL_BANNERS = frozenset({b"ready", b"ok"})
_CAT_NOT_FOUND_MARKERS = (
    b"cat:",
    b"no such file",
    b"cannot open",
    b"not found",
)
_FLASK_MARKERS = (
    b"werkzeug",
    b"flask.debughelpers",
    b"__debugger__",
)


@dataclass(frozen=True)
class JsonlContentValidation:
    """Outcome of validating raw downloaded bundle bytes."""

    valid: bool
    reason: str | None = None
    line_number: int | None = None
    content_preview: str | None = None


def strip_webshell_exit_marker(body: bytes) -> bytes:
    """Remove trailing webshell exit-code markers from command output."""
    return _EXIT_CODE_MARKER.sub(b"", body.rstrip())


def normalize_webshell_command_output(body: bytes | str) -> str:
    """Normalize HTML-wrapped webshell command output for shell parsing."""
    if isinstance(body, str):
        body = body.encode("utf-8", errors="surrogateescape")
    cleaned = strip_webshell_exit_marker(body)
    match = _PRE_BLOCK_RE.search(cleaned)
    if match is not None:
        cleaned = match.group(1)
    else:
        cleaned = _TAG_RE.sub(b"", cleaned)
    return cleaned.decode("utf-8", errors="replace").strip()


def unwrap_jsonl_bundle_content(content: bytes) -> bytes:
    """Return JSONL bytes with HTML ``<pre>`` wrappers removed when present."""
    stripped = content.strip()
    if not _PRE_BLOCK_RE.search(stripped):
        return content
    normalized = normalize_webshell_command_output(content)
    if normalized.lstrip().startswith("{"):
        return normalized.encode("utf-8")
    return content


def content_preview(content: bytes, *, limit: int = _CONTENT_PREVIEW_BYTES) -> str:
    """Return a safe, truncated preview of invalid bundle bytes."""
    sample = content[:limit]
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        text = sample.decode("utf-8", errors="replace")
    if len(content) > limit:
        return f"{text!r}… ({len(content)} bytes total)"
    return repr(text)


def validate_jsonl_content(content: bytes) -> JsonlContentValidation:
    """Validate raw bytes look like a JSONL event bundle before parsing.

    Rejects HTML, empty responses, shell banners, ``cat`` errors, and Flask
    debug wrappers. Every non-empty line must be a JSON object; the first
    non-empty line must start with ``{``.
    """
    stripped = content.strip()
    if _PRE_BLOCK_RE.search(stripped):
        normalized_text = normalize_webshell_command_output(content)
        if normalized_text.lstrip().startswith("{"):
            content = normalized_text.encode("utf-8")
            stripped = content.strip()

    if not stripped:
        return JsonlContentValidation(
            valid=False,
            reason="empty response",
            content_preview=content_preview(content),
        )

    lower = stripped.lower()
    if any(lower.startswith(prefix) for prefix in _HTML_PREFIXES):
        return JsonlContentValidation(
            valid=False,
            reason="HTML response",
            content_preview=content_preview(content),
        )
    if any(marker in lower for marker in _FLASK_MARKERS):
        return JsonlContentValidation(
            valid=False,
            reason="Flask debug wrapper",
            content_preview=content_preview(content),
        )
    if stripped in _SHELL_BANNERS:
        return JsonlContentValidation(
            valid=False,
            reason="webshell banner",
            content_preview=content_preview(content),
        )
    if _looks_like_cat_error(lower):
        return JsonlContentValidation(
            valid=False,
            reason="cat: file not found",
            content_preview=content_preview(content),
        )

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        return JsonlContentValidation(
            valid=False,
            reason=f"invalid UTF-8: {exc}",
            content_preview=content_preview(content),
        )

    saw_line = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if not saw_line:
            saw_line = True
            if not line.startswith("{"):
                return JsonlContentValidation(
                    valid=False,
                    reason=f"first non-empty line does not start with '{{' (line {line_number})",
                    line_number=line_number,
                    content_preview=content_preview(content),
                )
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            return JsonlContentValidation(
                valid=False,
                reason=f"malformed JSON at line {line_number}: {exc.msg}",
                line_number=line_number,
                content_preview=content_preview(content),
            )
        if not isinstance(record, dict):
            return JsonlContentValidation(
                valid=False,
                reason=f"expected JSON object at line {line_number}",
                line_number=line_number,
                content_preview=content_preview(content),
            )

    if not saw_line:
        return JsonlContentValidation(
            valid=False,
            reason="empty response",
            content_preview=content_preview(content),
        )

    return JsonlContentValidation(valid=True)


def _looks_like_cat_error(lower: bytes) -> bool:
    if b"cat:" not in lower:
        return False
    return any(marker in lower for marker in _CAT_NOT_FOUND_MARKERS[1:])
