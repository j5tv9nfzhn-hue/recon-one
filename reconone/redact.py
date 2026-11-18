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

So this module walks the finished report and masks by **shape**, not by field name: any
string that looks like a URL loses userinfo and sensitive query values; any `bearer`/`basic`
credential, JWT, or `…token=…` pair is masked wherever it appears; any dict key that names a
credential has its value replaced. New fields are covered by default instead of by memory.

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

REDACTION_VERSION = "1"

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


def scrub_report(report):
    """Return a deep copy of *report* with credential shapes masked.

    Pure and deterministic: the same report always yields the same output, so the
    `deterministic_digest` keeps meaning "same target, same facts".
    """
    return _scrub_value(report, "")


def scope_note() -> dict:
    """Machine-readable statement of what was and was not redacted, for `meta.redaction`."""
    return {
        "version": REDACTION_VERSION,
        "layers": ["js-values", "headers", "urls", "evidence-snippets", "whole-report-shapes"],
        "scope": "report.json / report.md / handoff.md / brief.md",
        "raw_artifacts": "unredacted by design (verification only; runs/ is git-ignored)",
        "not_redacted": ["e-mail addresses (security.txt is a contact by definition)"],
    }
