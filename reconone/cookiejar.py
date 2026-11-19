"""Set-Cookie session persistence: a small, deliberately boring cookie jar.

Why a jar at all
----------------
`--cookie` sets one static header. Real sites hand out a session cookie on the first response
and expect it back on the second; without a jar every page after the first is anonymous, and a
crawl of a logged-in area reports the login wall instead of the content behind it.

What it is not
--------------
* Not a browser: no `SameSite` enforcement (we are not a cross-site context), no
  `document.cookie` semantics, no third-party partitioning.
* Not a store: values live in memory for the length of one scan and are **never written to the
  report**. `stats()` returns counts and names; the values are exactly the thing being kept out
  of the package (`meta.session.cookies`).
* Not permissive: a `Set-Cookie` whose `Domain` this scan is not allowed to touch is rejected,
  so a hostile response cannot install a cookie for the shared parent (`.com`) or for a host
  outside the target. Accepting those is the "supercookie" failure mode, and a scanner that
  accepts them is a confused deputy.

The rules implemented are the ones that change behaviour on real sites: `Domain`/`Path`
scoping, `Secure`, `Max-Age`/`Expires`, and deletion. Everything else is parsed and ignored.
"""
from __future__ import annotations

import calendar
import threading
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

from .util import host_part, is_ip_literal

#: A site that sets one cookie per request must not grow this without bound. Oldest-first
#: eviction keeps the header deterministic (dict order is insertion order).
MAX_COOKIES = 200


@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str
    secure: bool = False
    host_only: bool = True
    expires: float | None = None          # epoch seconds; None = session cookie

    def key(self) -> tuple[str, str, str]:
        return (self.domain, self.path, self.name)

    def expired(self, now: float) -> bool:
        return self.expires is not None and self.expires <= now


def _default_path(request_path: str) -> str:
    """RFC 6265 §5.1.4: everything up to the last `/`, else `/`."""
    path = request_path or "/"
    if not path.startswith("/"):
        return "/"
    cut = path.rfind("/")
    if cut <= 0:
        return "/"
    return path[:cut]


def _path_matches(entry_path: str, request_path: str) -> bool:
    if request_path == entry_path:
        return True
    if not request_path.startswith(entry_path):
        return False
    if entry_path.endswith("/"):
        return True
    return request_path[len(entry_path):len(entry_path) + 1] == "/"


def _parse_expires(raw: str) -> float | None:
    try:
        stamp = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None
    if stamp is None:
        return None
    return float(calendar.timegm(stamp.utctimetuple()))



def _looks_like_ip(host: str) -> bool:
    """`example.com:8443` is a host:port, not an IP literal."""
    return is_ip_literal(host)


def _normalise_domain(raw: str) -> str:
    return str(raw or "").strip().lstrip(".").lower()


class CookieJar:
    """Per-scan cookie store. Thread-safe: the crawler fetches concurrently."""

    def __init__(self, enabled: bool = False, scope_domain: str = "",
                 max_cookies: int = MAX_COOKIES, clock=None):
        self.enabled = bool(enabled)
        # A target may be `host:port`; the scope is the host part (same rule as the HTTP
        # scope guard). Keeping the port here made `Domain=example.com` look out of scope
        # for every `example.com:8443` scan.
        self.scope = host_part(scope_domain)
        self._scope_is_ip = _looks_like_ip(self.scope)
        self.max_cookies = max(1, int(max_cookies))
        self.clock = clock or time.time
        self._lock = threading.Lock()
        self._cookies: dict[tuple[str, str, str], Cookie] = {}
        self.received = 0        # Set-Cookie headers seen
        self.stored = 0          # accepted (including deletions)
        self.rejected = 0        # domain/scope refusals
        self.carried = 0         # requests that went out with at least one cookie

    def _domain_allowed(self, domain: str) -> bool:
        """May this scan accept a cookie scoped to *domain*?

        `Domain=.com` is the failure mode that matters: it would let one response install a
        cookie for every host in the TLD, and this process would then hand the target's
        session to whatever host the operator later pointed it at. Without a public suffix
        list we cannot prove `.com` is a public suffix, so the rule is deliberately the other
        way round: the attribute may only name the scope itself or something *under* it.
        """
        if not self.scope:
            return True
        if domain == self.scope:
            return True
        if self._scope_is_ip:
            return False                     # an IP literal has no parent domain
        return domain.endswith("." + self.scope)

    # -- writing ---------------------------------------------------------------
    def store(self, host: str, request_path: str, secure: bool,
              set_cookie_values) -> int:
        """Absorb `Set-Cookie` header values from a response to *host*. Returns how many
        were accepted. Rejections are counted, never silently dropped."""
        if not self.enabled:
            return 0
        host = host_part(host)
        default_path = _default_path(request_path)
        accepted = 0
        with self._lock:
            for raw in set_cookie_values or []:
                self.received += 1
                cookie = self._parse(str(raw), host, secure, default_path)
                if cookie is None:
                    self.rejected += 1
                    continue
                accepted += 1
                self.stored += 1
                if cookie.expired(self.clock()):
                    self._cookies.pop(cookie.key(), None)
                    continue
                self._cookies[cookie.key()] = cookie
                self._evict()
        return accepted

    def _parse(self, raw: str, host: str, secure_response: bool,
               default_path: str) -> Cookie | None:
        parts = raw.split(";")
        first = parts[0].strip()
        name, sep, value = first.partition("=")
        name = name.strip()
        if not sep or not name or name.lower() in ("path", "domain", "expires", "max-age"):
            return None
        cookie = Cookie(name=name, value=value.strip(), domain=host, path=default_path)
        now = self.clock()
        for attr in parts[1:]:
            key, _sep, val = attr.partition("=")
            key = key.strip().lower()
            val = val.strip()
            if key == "domain":
                domain = _normalise_domain(val)
                if not domain:
                    return None
                if not (host == domain or host.endswith("." + domain)):
                    return None                      # not this host's name to set
                if not self._domain_allowed(domain):
                    return None          # `Domain=.com` and friends: counted by `store()`
                cookie.domain = domain
                cookie.host_only = False
            elif key == "path":
                cookie.path = val if val.startswith("/") else default_path
            elif key == "secure":
                cookie.secure = True
            elif key == "max-age":
                try:
                    seconds = int(val)
                except ValueError:
                    continue
                cookie.expires = now + seconds if seconds > 0 else 0.0
            elif key == "expires" and cookie.expires is None:
                parsed = _parse_expires(val)
                if parsed is not None:
                    cookie.expires = parsed
        # A `Secure` cookie may only be set over TLS, exactly as a browser requires.
        if cookie.secure and not secure_response:
            return None
        return cookie

    def _evict(self) -> None:
        while len(self._cookies) > self.max_cookies:
            oldest = next(iter(self._cookies))
            self._cookies.pop(oldest, None)

    # -- reading ---------------------------------------------------------------
    def header_for(self, host: str, request_path: str, secure: bool) -> str:
        """The `Cookie` header value for one request, or `""`."""
        if not self.enabled:
            return ""
        host = host_part(host)
        now = self.clock()
        with self._lock:
            live = []
            for key, cookie in list(self._cookies.items()):
                if cookie.expired(now):
                    self._cookies.pop(key, None)
                    continue
                if cookie.host_only:
                    if host != cookie.domain:
                        continue
                elif not (host == cookie.domain or host.endswith("." + cookie.domain)):
                    continue
                if cookie.secure and not secure:
                    continue
                if not _path_matches(cookie.path, request_path or "/"):
                    continue
                live.append(cookie)
            if not live:
                return ""
            # RFC 6265 §5.4: longer paths first, then earlier creation. Sorting by
            # (path length, name) keeps the header stable across identical scans.
            live.sort(key=lambda c: (-len(c.path), c.name))
            self.carried += 1
            return "; ".join(f"{c.name}={c.value}" for c in live)

    # -- reporting -------------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            names = sorted({cookie.name for cookie in self._cookies.values()})
            live = len(self._cookies)
        return {
            "enabled": self.enabled,
            "received": self.received,
            "stored": self.stored,
            "rejected": self.rejected,
            "live": live,
            "carried_requests": self.carried,
            "names": names,
            "note": ("Set-Cookie 会话保持：按 Domain/Path/Secure/过期时间收发，"
                     "越域与超范围的 Domain 直接拒收；只记名称与计数，值永不写入报告。"),
        }
