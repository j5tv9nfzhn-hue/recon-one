"""Light verification: one request per discovered endpoint, bound by RoE and scope.

What "verification" means here
------------------------------
The scan produces *claims*: these paths exist, they look like API surface. A claim becomes
usable evidence only when the server answers it. This engine re-requests each endpoint once
and answers one question per endpoint: **可用（红）** or **不可用（灰）** — nothing else.

It is deliberately the smallest thing that can answer that:

* one request per endpoint, `GET` only (`HEAD` allowed), never a body, never a second try;
* a hard request cap (`RoE.max_requests`) and a hard per-endpoint cost of 1;
* destructive-looking paths (`logout/delete/reset/…`) are **skipped, not probed**;
* everything is recorded, including what was *not* done and why.

Rules of engagement (RoE) + scope guard
--------------------------------------
`RoE` is the machine-readable contract of this stage: scope, allowed methods, cap, exclusions.
Every request is checked against it *and* against `Session.in_scope()` before it is sent; the
per-endpoint audit block records both decisions (`in_scope`, `method_allowed`, `excluded`,
`budget_left`, `requests_used`). The result is a traceable record: for any endpoint you can
say whether it was probed, and if not, which rule stopped it.

No AI, no heuristics on response bodies: the verdict is a status-class table you can read.
"""
from __future__ import annotations

from dataclasses import dataclass, field

VERIFY_VERSION = "1"

USABLE, UNUSABLE, SKIPPED = "usable", "unusable", "skipped"

#: Methods this engine is allowed to send. Anything else is a finding in itself.
ALLOWED_METHODS = ("GET", "HEAD")
DEFAULT_MAX_REQUESTS = 40

#: Status classes that prove something is behind the path (red in the console).
LIVE_STATUS = frozenset({
    200, 201, 202, 203, 204, 205, 206, 300, 301, 302, 303, 304, 307, 308,
    401, 403, 405, 429,          # protected / wrong method / throttled: it exists
})
DEAD_STATUS = frozenset({404, 410})

#: A GET can still have side effects. These are skipped, never "just checked".
EXCLUDED_WORDS = (
    "logout", "signout", "sign-out", "logoff", "delete", "remove", "destroy", "purge",
    "reset", "revoke", "unsubscribe", "shutdown", "disable", "deactivate", "cancel",
)


@dataclass(frozen=True)
class RoE:
    """The rules this verification stage plays by. Serialised into `meta.roe`."""

    scope_domain: str
    allow_external: bool = False
    allowed_methods: tuple[str, ...] = ALLOWED_METHODS
    max_requests: int = DEFAULT_MAX_REQUESTS
    excluded: tuple[str, ...] = EXCLUDED_WORDS
    enabled: bool = True
    source: str = "cli:--verify"

    def method_allowed(self, method: str) -> bool:
        return str(method or "").upper() in self.allowed_methods

    def path_excluded(self, path: str) -> bool:
        low = str(path or "").lower()
        return any(word in low for word in self.excluded)

    def as_dict(self) -> dict:
        return {
            "version": VERIFY_VERSION,
            "enabled": self.enabled,
            "scope_domain": self.scope_domain,
            "allow_external": self.allow_external,
            "allowed_methods": list(self.allowed_methods),
            "max_requests": self.max_requests,
            "excluded": list(self.excluded),
            "source": self.source,
            "note": ("每次验证请求都要同时通过作用域守卫与 RoE；被拦下的请求不发送，"
                     "但会连同原因写进 audit。"),
        }


def build_roe(domain: str, allow_external: bool = False, max_requests: int = DEFAULT_MAX_REQUESTS,
              enabled: bool = True, source: str = "cli:--verify") -> RoE:
    return RoE(scope_domain=str(domain or "").lower(), allow_external=bool(allow_external),
               max_requests=max(0, int(max_requests)), enabled=bool(enabled), source=source)


def _verdict(status: int) -> tuple[str, str]:
    if status in LIVE_STATUS:
        return USABLE, ""
    if status in DEAD_STATUS:
        return UNUSABLE, f"status {status}（不存在）"
    if 400 <= status < 500:
        return UNUSABLE, f"status {status}（需要输入，未证明可用）"
    if status >= 500:
        return UNUSABLE, f"status {status}（服务端错误）"
    return UNUSABLE, f"status {status}"


def run(session, base_url: str, endpoints: list[dict], roe: RoE) -> dict:
    """Probe each endpoint once. Pure bookkeeping; all I/O goes through *session*.

    Returns the block that becomes `report.verification` — plus `by_path`, so the caller can
    stamp `endpoints[].verified` without re-keying anything.
    """
    base = str(base_url or "").rstrip("/")
    results: list[dict] = []
    used = 0
    counts = {USABLE: 0, UNUSABLE: 0, SKIPPED: 0}

    for endpoint in endpoints or []:
        path = str(endpoint.get("path") or "")
        method = "GET"
        audit = {
            "in_scope": None,
            "method_allowed": roe.method_allowed(method),
            "excluded": roe.path_excluded(path),
            "budget_left": max(0, roe.max_requests - used),
            "requests_used": 0,
        }
        entry = {"path": path, "method": method, "status": 0, "ms": 0,
                 "verdict": SKIPPED, "reason": "", "audit": audit}

        if not roe.enabled:
            entry["reason"] = "verification disabled（--no-verify）"
        elif not path.startswith("/"):
            entry["reason"] = "not a site-absolute path"
        elif audit["excluded"]:
            entry["reason"] = "excluded: destructive-looking path（未发送）"
        elif used >= roe.max_requests:
            entry["reason"] = f"budget: reached max_requests={roe.max_requests}（未发送）"
        else:
            url = base + path
            audit["in_scope"] = bool(session.in_scope(url))
            if not audit["in_scope"]:
                entry["reason"] = "scope guard refused the request（未发送）"
            else:
                resp = session.request(url, method=method, max_bytes=64_000)
                used += 1
                audit["requests_used"] = 1
                audit["budget_left"] = max(0, roe.max_requests - used)
                entry["status"] = int(getattr(resp, "status", 0) or 0)
                entry["ms"] = int(getattr(resp, "elapsed_ms", 0) or 0)
                if getattr(resp, "error", None):
                    entry["verdict"] = UNUSABLE
                    entry["reason"] = str(resp.error)[:200]
                    audit["error_kind"] = str(resp.error).split(":", 1)[0]
                else:
                    entry["verdict"], entry["reason"] = _verdict(entry["status"])

        counts[entry["verdict"]] += 1
        results.append(entry)

    summary = {
        "usable": counts[USABLE],
        "unusable": counts[UNUSABLE],
        "skipped": counts[SKIPPED],
        "probed": counts[USABLE] + counts[UNUSABLE],
        "requests": used,
        "max_requests": roe.max_requests,
        "budget_used_pct": round(used / roe.max_requests * 100.0, 1) if roe.max_requests else 0.0,
    }
    return {
        "version": VERIFY_VERSION,
        "generated_by": "reconone.verify (one GET per endpoint, scope-bound, no AI)",
        "enabled": roe.enabled,
        "roe": roe.as_dict(),
        "summary": summary,
        "results": results,
        "by_path": {entry["path"]: entry["verdict"] for entry in results},
    }


def annotate(endpoints: list[dict], verification: dict) -> None:
    """Stamp `verified` onto endpoints so every consumer (report, console) shares one field."""
    by_path = (verification or {}).get("by_path") or {}
    for endpoint in endpoints or []:
        verdict = by_path.get(endpoint.get("path") or "")
        if verdict:
            endpoint["verified"] = verdict
