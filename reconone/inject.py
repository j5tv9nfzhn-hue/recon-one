"""Session injection: the credentials a scan is allowed to carry, and how they are recorded.

Why a module instead of a dict
------------------------------
Injected credentials are the one thing in this tool that must be *sent* and must never be
*stored*. Keeping them in a typed object means:

* `apply()` is the only place headers are merged, so a new request path cannot forget them;
* `describe()` is the only place they are summarised — names and shapes, never values — and it
  is what `meta.session` records. A report that contains `Authorization: Bearer …` is a
  credential leak; a report that contains `{"bearer": true}` is evidence.

Sources, in order of preference (argv is visible in the process list, env is not):
``--cookie`` / ``RECONONE_COOKIE``, ``--bearer`` / ``RECONONE_BEARER``,
``--header "Name: Value"`` (repeatable) / ``RECONONE_HEADERS`` (newline separated).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

#: Header names that count as credentials when describing them (values are never shown).
SECRET_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token",
                  "x-xsrf-token", "proxy-authorization")

#: Values shorter than this are not registered for echo-masking: masking `1` or `admin`
#: would destroy the report's facts without protecting anything.
MIN_SECRET_LEN = 6


@dataclass(frozen=True)
class Injection:
    """Headers to attach to every request. Immutable so it cannot be mutated mid-run."""

    headers: tuple[tuple[str, str], ...] = ()
    source: str = ""

    @property
    def enabled(self) -> bool:
        return bool(self.headers)

    def apply(self, base: dict) -> dict:
        """Merge into *base*; injected headers win, matched case-insensitively."""
        if not self.headers:
            return base
        lowered = {name.lower() for name, _ in self.headers}
        out = {k: v for k, v in base.items() if k.lower() not in lowered}
        out.update({name: value for name, value in self.headers})
        return out

    def describe(self) -> dict:
        """The shape of the injection, safe to put in a report."""
        cookie = ""
        bearer = False
        names: list[str] = []
        for name, value in self.headers:
            low = name.lower()
            names.append(name)
            if low == "cookie":
                cookie = value
            elif low == "authorization" and str(value).lower().startswith("bearer "):
                bearer = True
        cookie_names = []
        opaque = 0
        for chunk in cookie.split(";"):
            key, sep, _value = chunk.partition("=")
            key = key.strip()
            if not key:
                continue
            if sep:
                cookie_names.append(key)
            else:
                # `--cookie "SESSIONTOKEN"` has no name: recording the text would put the
                # value in the report under a field that looks harmless. Count it instead.
                opaque += 1
        return {
            "enabled": self.enabled,
            "source": self.source,
            "headers": names,
            "cookie_names": cookie_names,
            "opaque_cookie_segments": opaque,
            "bearer": bearer,
            "secret_headers": sorted({n for n in names if n.lower() in SECRET_HEADERS}),
            "note": "只记录类型与名称，值永不写入报告。",
        }

    def secrets(self) -> tuple[str, ...]:
        """The literal values this scan sends, for echo-masking. Never serialised.

        Values shorter than `MIN_SECRET_LEN` are left out on purpose: masking `1` or `admin`
        would destroy the report's facts, and a five-character value is not a credential we
        need to hide from ourselves. Longest first, because masking `abc123` before
        `abc123def` would leave a visible tail behind.
        """
        found: set[str] = set()
        for name, value in self.headers:
            low = name.lower()
            text = str(value)
            if low == "cookie":
                pairs = 0
                for chunk in text.split(";"):
                    _key, sep, val = chunk.partition("=")
                    if not sep:
                        continue
                    pairs += 1
                    val = val.strip()
                    if len(val) >= MIN_SECRET_LEN:
                        found.add(val)
                if not pairs:
                    text = text.strip()
                    if len(text) >= MIN_SECRET_LEN:
                        found.add(text)
                continue
            if low == "authorization" and text.lower().startswith("bearer "):
                text = text[7:]
            text = text.strip()
            if len(text) >= MIN_SECRET_LEN:
                found.add(text)
        return tuple(sorted(found, key=lambda item: (-len(item), item)))


def parse_header_specs(specs) -> list[tuple[str, str]]:
    """`["X-Api-Key: abc"]` → `[("X-Api-Key", "abc")]`. Raises ValueError on a bad pair."""
    out: list[tuple[str, str]] = []
    for raw in specs or []:
        text = str(raw or "").strip()
        if not text:
            continue
        name, sep, value = text.partition(":")
        name = name.strip()
        if not sep or not name or not value.strip():
            raise ValueError(f'--header 需要 "Name: Value" 形式，收到：{text[:40]}')
        if "\r" in name or "\n" in name or "\r" in value:
            raise ValueError("header 值不得包含换行")
        out.append((name, value.strip()))
    return out


def _bearer_value(value: str) -> str:
    """`"tok"` / `"Bearer tok"` → `"Bearer tok"`.

    `lstrip("Bearer ")` would strip *characters*, so a token starting with any of
    `B/e/a/r/space` loses its prefix (`envtok` → `nvtok`). Prefix removal must be exact.
    """
    token = str(value or "").strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return "Bearer " + token


def build(cookie: str = "", bearer: str = "", headers=(), source: str = "cli") -> Injection:
    """Assemble the injection from explicit values (env is handled by `from_env`)."""
    pairs: list[tuple[str, str]] = []
    if cookie and cookie.strip():
        pairs.append(("Cookie", cookie.strip()))
    if bearer and bearer.strip():
        pairs.append(("Authorization", _bearer_value(bearer)))
    # Explicit headers come last and win on a name collision: `--header "Authorization: …"`
    # is more specific than the `--bearer` shorthand, so it must not be overwritten by it.
    pairs.extend(parse_header_specs(headers))
    if not pairs:
        return Injection(source=source)
    merged: dict[str, tuple[str, str]] = {}
    for name, value in pairs:
        merged[name.lower()] = (name, value)
    return Injection(headers=tuple(merged.values()), source=source)


def from_env() -> Injection:
    """Read `RECONONE_*` variables; an empty result means nothing was configured."""
    cookie = os.environ.get("RECONONE_COOKIE", "")
    bearer = os.environ.get("RECONONE_BEARER", "")
    raw = os.environ.get("RECONONE_HEADERS", "")
    headers = [line for line in raw.replace("\r", "").split("\n") if line.strip()]
    if not (cookie or bearer or headers):
        return Injection()
    return build(cookie, bearer, headers, source="env")
