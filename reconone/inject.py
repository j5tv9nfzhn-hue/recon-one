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
        for chunk in cookie.split(";"):
            key = chunk.split("=", 1)[0].strip()
            if key:
                cookie_names.append(key)
        return {
            "enabled": self.enabled,
            "source": self.source,
            "headers": names,
            "cookie_names": cookie_names,
            "bearer": bearer,
            "secret_headers": sorted({n for n in names if n.lower() in SECRET_HEADERS}),
            "note": "只记录类型与名称，值永不写入报告。",
        }


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
