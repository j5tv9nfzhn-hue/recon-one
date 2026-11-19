"""Fifth redaction layer: shape-based, applied to the finished report.

Why another layer when four exist
---------------------------------
The existing layers are targeted, and each is right in its own place:

1. `jsanalyze.analyze()` masks the secret values it finds and replaces them全文;
2. `report.assemble()` scrubs response headers (`Set-Cookie` values, `Authorization`) and
   every URL it builds itself;
3. header *evidence snippets* go through `scrub_header_block()`;
4. `util.redact()` produces `masked + sha256_12 + length` for `secrets[]`.

What they cannot cover is everything added later: `assets.hosts[].url` comes straight from a
JS string literal, `report.intel` is third-party JSON (a Wayback row can be
`…/reset?token=…`), and `assets.well_known` stores raw file bodies. A field added next year
would leak by default.

So this module walks the finished report twice: once by **shape** (any string that looks like a
URL loses userinfo and sensitive query values; any `bearer`/`basic` credential, JWT, or
`…token=…` pair is masked wherever it appears; any dict key that names a credential has its
value replaced), and once by **literal value** — the credentials this scan actually sent, from
`inject.Injection.secrets()`. Shapes alone cannot see that a page title reading
「你好 S3CRETCOOKIE」 is our own cookie echoed back; the literal pass can. New fields are
covered by default instead of by memory.
What it deliberately does not do
--------------------------------
* It never touches `raw/` artifacts. Those keep the originals so a finding can be re-checked
  byte for byte, are listed in `manifest.json` as such, and are excluded from version control
  by `.gitignore` (`runs/`). That trade-off is stated in the report (`meta.redaction`).
* It does not mask e-mail addresses: `security.txt` exists to publish a contact, so removing
  it would destroy the finding.
* It does not guess at opaque high-entropy strings. Those are the secret rules' job, and a
  length heuristic here would mask hashes and IDs that the report needs to stay checkable.
"""
from __future__ import annotations

import re

from .util import redact_url, redacted_marker, scrub_headers

REDACTION_VERSION = "2"

#: Marker for a value this scan actually sent and the target echoed back. Fixed text, so two
#: runs that both leaked produce the same digest.
SENT_CREDENTIAL_MARKER = "[redacted:sent-credential]"

#: Keys whose *value* is a credential, matched by exact lowercase name so that a field such
#: as `auth_surface` (a check id) is never caught by substring matching.
STRICT_SECRET_KEYS = frozenset({
    "password", "passwd", "pwd", "secret", "client_secret", "token", "access_token",
    "refresh_token", "id_token", "api_key", "apikey", "authorization", "proxy_authorization",
    "cookie", "set-cookie", "private_key", "session", "sid", "jwt", "signature", "otp",
    "pin", "cvv", "ssn", "card_number",
})

#: Keys whose value is a header map, so cookie-aware masking is used instead of a blunt one.
HEADER_MAP_KEYS = frozenset({"headers", "request_headers", "response_headers"})

_BEARER = re.compile(r"(?i)\b(bearer|basic|digest)\s+([A-Za-z0-9._~+/=-]{8,})")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_INLINE_PAIR = re.compile(
    r"(?i)\b([a-z0-9_.-]{0,32}"
    r"(?:token|secret|passw(?:or)?d|pwd|api[-_]?key|access[-_]?key|session[-_]?id|jwt|signature|sig))"
    r"=(?!\[redacted\])"
    r"([^&\s\"'<>;]{3,})")


def scrub_text(text: str) -> str:
    """Mask credential shapes inside one free-text string.

    Order matters: the scheme-level rewrite (`redact_url`) runs last so it sees whatever the
    earlier substitutions left behind, and `key=value` masking never re-processes an already
    masked value.
    """
    out = str(text or "")
    if not out:
        return out
    out = _BEARER.sub(r"\1 [redacted]", out)
    out = _JWT.sub("[redacted:jwt]", out)
    out = _INLINE_PAIR.sub(r"\1=[redacted]", out)
    if "://" in out:
        out = redact_url(out)
    return out


def _scrub_value(value, key: str):
    if isinstance(value, dict):
        if key in HEADER_MAP_KEYS:
            return scrub_headers(value)
        return {k: _scrub_value(v, str(k).lower()) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_scrub_value(item, key) for item in value]
    if isinstance(value, str):
        if key in STRICT_SECRET_KEYS and value and not value.startswith("[redacted"):
            return redacted_marker(value)
        return scrub_text(value)
    return value


def _mask_text(text: str, values: tuple[str, ...]) -> tuple[str, int]:
    hits = 0
    for value in values:
        if value and value in text:
            hits += text.count(value)
            text = text.replace(value, SENT_CREDENTIAL_MARKER)
    return text, hits


def _mask_value(value, values: tuple[str, ...]) -> tuple[object, int]:
    if isinstance(value, dict):
        out, hits = {}, 0
        for key, item in value.items():
            masked, found = _mask_value(item, values)
            out[key] = masked
            hits += found
        return out, hits
    if isinstance(value, (list, tuple)):
        items, hits = [], 0
        for item in value:
            masked, found = _mask_value(item, values)
            items.append(masked)
            hits += found
        return items, hits
    if isinstance(value, str):
        return _mask_text(value, values)
    return value, 0


def mask_sent_credentials(report, secrets):
    """Mask the literal values this scan *sent*, wherever the target echoed them back.

    Layer 5a (`scrub_text`) knows credential *shapes*. It cannot know that `S3CRETCOOKIE` is
    a credential when a page title says "你好 S3CRETCOOKIE" — the shape is just a word. This
    stage supplies the missing half: the actual values, from the session injection, matched
    literally. It is the only place in the codebase where a sent value is used for output,
    and it only ever writes the marker.
    """
    values = tuple(sorted({str(v) for v in (secrets or ()) if v},
                          key=lambda item: (-len(item), item)))
    if not values:
        return report, 0
    return _mask_value(report, values)


def scrub_report(report, secrets=()):
    """Return a deep copy of *report* with credential shapes masked.

    Pure and deterministic: the same report always yields the same output, so the
    `deterministic_digest` keeps meaning "same target, same facts". `secrets` are the values
    this run sent (see `inject.Injection.secrets()`); they are masked literally on top of the
    shape sweep, so a target that echoes our Cookie back into a title cannot leak it.
    """
    out = _scrub_value(report, "")
    values = tuple(sorted({str(v) for v in (secrets or ()) if v},
                          key=lambda item: (-len(item), item)))
    if not values:
        return out
    out, _hits = _mask_value(out, values)
    meta = out.get("meta") if isinstance(out, dict) else None
    if isinstance(meta, dict):
        block = meta.get("redaction")
        if not isinstance(block, dict):
            block = scope_note()
            meta["redaction"] = block
        # Only the count is recorded: the values themselves are the thing being hidden, and
        # a hit counter would make the digest depend on what the server happened to echo.
        block["sent_credentials"] = {"registered": len(values), "masked": True}
    return out


def scope_note() -> dict:
    """Machine-readable statement of what was and was not redacted, for `meta.redaction`."""
    return {
        "version": REDACTION_VERSION,
        "layers": ["js-values", "headers", "urls", "evidence-snippets", "whole-report-shapes"],
        "scope": "report.json / report.md / handoff.md / brief.md",
        "credential_echoes": ("本次扫描实际发出的凭据值（长度 ≥6）按字面量遮蔽，"
                              "目标把 Cookie/Bearer 回显到页面或响应头时同样被遮盖"),
        "raw_artifacts": "unredacted by design (verification only; runs/ is git-ignored)",
        "not_redacted": ["e-mail addresses (security.txt is a contact by definition)"],
    }
