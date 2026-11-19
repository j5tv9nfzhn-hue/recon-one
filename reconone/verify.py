"""Verification: turn claims into evidence, and evidence into a bet.

Two questions, deliberately separated
-------------------------------------
1. **Does this path exist?** A status class answers it. In single-identity mode one `HEAD` per
   endpoint is enough — cheaper than a `GET`, no body, no side effect on a well-behaved app.
   A server that refuses `HEAD` (405/501) is asked with `GET` instead, once.
2. **Is it open without credentials?** A status class alone cannot answer it: the same 200 can
   mean "public page" or "our session is valid". So when an identity was injected, the engine
   sends the request **twice** — once with the injected session, once with a clean one — and
   records both statuses plus a body comparison. That pair is what makes a bet possible.

Everything stays bounded: `RoE.max_requests` counts *every* request (HEAD, GET, both identities),
the scope guard is checked before each one, and destructive-looking paths are skipped rather than
"just checked" — the verb list is now word-boundary matched, so `/applications` is not confused
with `/apply`.

No AI, no body heuristics beyond length/title: the verdict is a table you can read.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

VERIFY_VERSION = "2"

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

#: GET/HEAD can still have side effects. These are skipped, never "just checked".
EXCLUDED_WORDS = (
    "logout", "signout", "sign-out", "logoff", "delete", "remove", "destroy", "purge",
    "reset", "revoke", "unsubscribe", "shutdown", "disable", "deactivate", "cancel",
    # A GET on these does something irreversible on a surprising number of sites.
    "close", "void", "apply", "submit", "confirm", "approve", "reject", "suspend",
    "terminate", "wipe", "truncate", "drop", "rollback", "restore", "transfer",
    "withdraw", "refund", "charge", "publish", "archive", "merge", "finalize",
)

#: Word-boundary match: `/applications` must not be excluded by the word `apply`.
_EXCLUDE_RE = re.compile(
    r"(?:^|[/_\-.])(?:" + "|".join(re.escape(word) for word in EXCLUDED_WORDS) + r")(?:$|[/_\-.]|\?|#)")


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
    #: `HEAD` when there is one identity (cheap existence check), two `GET`s when there are two.
    identity_model: str = "single"

    def method_allowed(self, method: str) -> bool:
        return str(method or "").upper() in self.allowed_methods

    def path_excluded(self, path: str) -> bool:
        low = str(path or "").lower()
        if any(word in low for word in self.excluded):
            # Keep the cheap check, then require a word boundary for the new verbs so that
            # `/applications` (contains `apply`) is not silently dropped from the scan.
            return bool(_EXCLUDE_RE.search(low))
        return False

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
            "identity_model": self.identity_model,
            "note": ("每次验证请求都要同时通过作用域守卫与 RoE；被拦下的请求不发送，"
                     "但会连同原因写进 audit。单身份用 HEAD 判存在，双身份用两次 GET 判授权差。"),
        }


def build_roe(domain: str, allow_external: bool = False, max_requests: int = DEFAULT_MAX_REQUESTS,
              enabled: bool = True, source: str = "cli:--verify",
              identity_model: str = "single") -> RoE:
    return RoE(scope_domain=str(domain or "").lower(), allow_external=bool(allow_external),
               max_requests=max(0, int(max_requests)), enabled=bool(enabled), source=source,
               identity_model=identity_model)


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


def _open(status: int) -> bool:
    """Reachable *without* credentials: a redirect or a 2xx, not a 401/403/429."""
    return 200 <= int(status or 0) < 400


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _title(body: bytes) -> str:
    try:
        text = body.decode("utf-8", "replace")
    except Exception:                       # noqa: BLE001 - a body is never worth raising for
        return ""
    found = _TITLE_RE.search(text[:200_000])
    return " ".join(found.group(1).split())[:120] if found else ""


def _authz(anon, authed) -> dict:
    """Compare the anonymous and authenticated answers for one endpoint.

    `label` is the machine-readable conclusion the bet sheet reads:
    `anonymous_open` (no credentials needed), `gated` (existence proven, credentials required),
    `same`, `divergent` (both open but the bodies differ) or `unknown`.
    """
    anon_status = int(getattr(anon, "status", 0) or 0)
    authed_status = int(getattr(authed, "status", 0) or 0)
    anon_body = getattr(anon, "body", b"") or b""
    authed_body = getattr(authed, "body", b"") or b""
    anon_len, authed_len = len(anon_body), len(authed_body)
    longer = max(anon_len, authed_len, 1)
    block = {
        "anon_status": anon_status,
        "authed_status": authed_status,
        "anon_open": _open(anon_status),
        "gated": anon_status in (401, 403) and _open(authed_status),
        "same_status": anon_status == authed_status,
        "body": {"anon_len": anon_len, "authed_len": authed_len,
                 "delta_pct": round(abs(anon_len - authed_len) / longer * 100.0, 1),
                 "same_title": _title(anon_body) == _title(authed_body)},
    }
    if block["gated"]:
        block["label"] = "gated"
    elif block["anon_open"]:
        block["label"] = ("anonymous_open" if (block["body"]["delta_pct"] > 10.0
                                              or not block["body"]["same_title"])
                          else "same")
    elif anon_status and authed_status:
        block["label"] = "same" if block["same_status"] else "unknown"
    else:
        block["label"] = "unknown"
    return block


def _probe(session, url: str, method: str, audit: dict, budget: int) -> tuple[object | None, int]:
    """Send one request if the budget allows. Returns (response, requests_used)."""
    if budget <= 0:
        return None, 0
    return session.request(url, method=method, max_bytes=64_000), 1


def run(session, base_url: str, endpoints: list[dict], roe: RoE, anon_session=None) -> dict:
    """Probe each endpoint, bound by RoE and the scope guard.

    `anon_session` is a second, credential-free session. When it is given the engine sends two
    requests per endpoint and fills `results[].authz`; when it is `None` it sends one `HEAD`
    and reports `authz` as `null` — "open anonymously" is then unproven, not assumed.
    """
    base = str(base_url or "").rstrip("/")
    dual = anon_session is not None and roe.identity_model != "single"
    results: list[dict] = []
    used = 0
    counts = {USABLE: 0, UNUSABLE: 0, SKIPPED: 0}
    labels = {"anonymous_open": 0, "gated": 0, "same": 0, "divergent": 0, "unknown": 0}
    methods_used = {"HEAD": 0, "GET": 0}

    for endpoint in endpoints or []:
        path = str(endpoint.get("path") or "")
        method = "GET" if dual else "HEAD"
        audit = {
            "in_scope": None,
            "method_allowed": roe.method_allowed(method),
            "excluded": roe.path_excluded(path),
            "budget_left": max(0, roe.max_requests - used),
            "requests_used": 0,
        }
        entry = {"path": path, "method": method, "status": 0, "ms": 0, "verdict": SKIPPED,
                 "reason": "", "authz": None, "checked_with": method, "audit": audit}

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
            elif dual:
                authed, n1 = _probe(session, url, "GET", audit, roe.max_requests - used)
                used += n1
                methods_used["GET"] += n1
                anon, n2 = _probe(anon_session, url, "GET", audit, roe.max_requests - used)
                used += n2
                methods_used["GET"] += n2
                audit["requests_used"] = n1 + n2
                audit["budget_left"] = max(0, roe.max_requests - used)
                if authed is not None:
                    entry["status"] = int(getattr(authed, "status", 0) or 0)
                    entry["ms"] = int(getattr(authed, "elapsed_ms", 0) or 0)
                if authed is None:
                    entry["reason"] = "budget: no request left（未发送）"
                elif getattr(authed, "error", None):
                    entry["verdict"] = UNUSABLE
                    entry["reason"] = str(authed.error)[:200]
                    audit["error_kind"] = str(authed.error).split(":", 1)[0]
                else:
                    entry["verdict"], entry["reason"] = _verdict(entry["status"])
                if anon is not None and not getattr(anon, "error", None) and \
                        not getattr(authed, "error", None) and authed is not None:
                    entry["authz"] = _authz(anon, authed)
                    labels[entry["authz"]["label"]] = labels.get(entry["authz"]["label"], 0) + 1
            else:
                resp, n1 = _probe(session, url, "HEAD", audit, roe.max_requests - used)
                used += n1
                methods_used["HEAD"] += n1
                status = int(getattr(resp, "status", 0) or 0) if resp is not None else 0
                if resp is not None and not getattr(resp, "error", None) and status in (405, 501):
                    # Server refuses HEAD: ask once with GET, as the protocol intends.
                    entry["checked_with"] = "GET"
                    resp, n2 = _probe(session, url, "GET", audit, roe.max_requests - used)
                    used += n2
                    methods_used["GET"] += n2
                    n1 += n2
                    status = int(getattr(resp, "status", 0) or 0) if resp is not None else 0
                audit["requests_used"] = n1
                audit["budget_left"] = max(0, roe.max_requests - used)
                entry["status"] = status
                entry["ms"] = int(getattr(resp, "elapsed_ms", 0) or 0) if resp is not None else 0
                if resp is None:
                    entry["reason"] = "budget: no request left（未发送）"
                elif getattr(resp, "error", None):
                    entry["verdict"] = UNUSABLE
                    entry["reason"] = str(resp.error)[:200]
                    audit["error_kind"] = str(resp.error).split(":", 1)[0]
                else:
                    entry["verdict"], entry["reason"] = _verdict(status)

        counts[entry["verdict"]] += 1
        results.append(entry)

    probed = counts[USABLE] + counts[UNUSABLE]
    summary = {
        "usable": counts[USABLE],
        "unusable": counts[UNUSABLE],
        "skipped": counts[SKIPPED],
        "probed": probed,
        "requests": used,
        "max_requests": roe.max_requests,
        "budget_used_pct": round(used / roe.max_requests * 100.0, 1) if roe.max_requests else 0.0,
        "identity_model": "dual" if dual else "single",
        "methods": methods_used,
        "authz": labels if dual else {},
        "anonymous_open": labels.get("anonymous_open", 0) if dual else 0,
        "gated": labels.get("gated", 0) if dual else 0,
    }
    return {
        "version": VERIFY_VERSION,
        "generated_by": "reconone.verify (HEAD for existence, two GETs for authz, scope-bound, no AI)",
        "enabled": roe.enabled,
        "roe": roe.as_dict(),
        "summary": summary,
        "results": results,
        "by_path": {entry["path"]: entry["verdict"] for entry in results},
        "authz_by_path": {entry["path"]: entry["authz"] for entry in results
                          if entry.get("authz")},
    }


def annotate(endpoints: list[dict], verification: dict) -> None:
    """Stamp `verified` and `authz_open` so every consumer shares one meaning.

    `verified` answers "does the path exist?" — 401/403 is still evidence of existence.
    `authz_open` answers a different question: "is it reachable *without* credentials?"
    It is only stamped when that question has an answer:

    * single identity — the scan itself was anonymous, so a 2xx/3xx status is open and
      401/403/405/429 is not. "usable" alone must never be read as "open";
    * dual identity — only `label == "anonymous_open"` counts. `same` (identical answers
      with and without the credential) and `gated` do not; an unclassified pair stays
      undecided instead of being assumed open.
    """
    verification = verification or {}
    by_path = verification.get("by_path") or {}
    authz = verification.get("authz_by_path") or {}
    dual = str((verification.get("summary") or {}).get("identity_model") or "single") == "dual"
    results = {str(entry.get("path") or ""): entry
               for entry in verification.get("results") or []}
    for endpoint in endpoints or []:
        path = endpoint.get("path") or ""
        verdict = by_path.get(path)
        if verdict:
            endpoint["verified"] = verdict
        if dual:
            block = authz.get(path)
            if block:
                label = str(block.get("label") or "")
                if label in ("anonymous_open", "gated", "same"):
                    endpoint["authz_open"] = label == "anonymous_open"
            continue
        entry = results.get(path)
        if entry is not None:
            status = int(entry.get("status") or 0)
            if status > 0:
                endpoint["authz_open"] = 200 <= status < 400
