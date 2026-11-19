"""Subdomain liveness: turn certificate names into observed hosts.

Criterion 2 of the bet sheet ("a live subdomain exposing a non-public face") needs an
observation, not a certificate. This module makes the cheapest useful observation per host —
one `GET /` — and records what came back.

Why one GET and not DNS + HEAD + GET
------------------------------------
A `GET /` answers three questions at once: does the name resolve, is anything listening, and what
does it serve. `HEAD` would answer the first two but not the third, and the third is the whole
point ("exposes a non-public face"). The body is read with a small cap: we need the title and a
keyword sample, never a page.

Scope rules (non-negotiable)
----------------------------
Only names under the scanned target are touched (`host == domain` or `host.endswith("." + domain)`).
A certificate can legitimately list names for other domains — probing those would silently widen
the engagement to hosts nobody authorised. Out-of-scope names are recorded as `skipped`, never
requested.

Classification is a table, not a model
--------------------------------------
`gated` (401/403, or a login wall in the body) → a non-public surface exists and asks for credentials.
`exposed` (2xx/3xx whose host name or title looks internal) → a non-public surface is reachable.
`public` and `dead` are not evidence of a non-public face. The keyword list is data
(`INTERNAL_HINTS`) so it can be argued with instead of guessed at.
"""
from __future__ import annotations

import re

#: Hard cap on hosts probed by one scan. Each host costs one request (two only when HTTPS fails
#: at the transport level and HTTP is worth a try).
DEFAULT_MAX_HOSTS = 20

#: Name/title fragments that mean "this is not the marketing site". Deliberately short: every
#: entry here can promote a target to `worth`, so the list is a policy, not a dump.
INTERNAL_HINTS = (
    "admin", "internal", "intranet", "corp", "vpn", "sso", "auth", "idp", "portal",
    "jenkins", "gitlab", "gitea", "bitbucket", "jira", "confluence", "nexus", "harbor",
    "grafana", "kibana", "prometheus", "metrics", "sonar", "portainer", "traefik",
    "phpmyadmin", "adminer", "vault", "consul", "rabbit", "kafka",
    "swagger", "api-docs", "openapi", "docs", "dev", "stage", "staging", "preprod", "uat",
    "qa", "test", "demo", "sandbox", "beta",
)

#: Host labels that mean "this host is an authentication endpoint". Deliberately host-only:
#: a "Login" link in a marketing page's navigation is not a login wall, and matching that
#: text classified nearly every public site as gated (which promoted it to `worth`).
LOGIN_HOST_HINTS = ("login", "signin", "sign-in", "logon")
#: A page whose *title* is a sign-in prompt is a login wall even on a public-looking host.
_LOGIN_TITLE = re.compile(
    r"(?i)^\s*(?:sign\s+in|log\s+in|login|logon|please\s+authenticate)\b")
#: This phrase is specific enough to trust in a body, unlike the word "login".
_LOGIN_MARKER = "please authenticate"

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GATED_STATUS = (401, 403)
#: Transport failures that say nothing about the *name*: a second request over plain HTTP is
#: worth it because internal hosts are often HTTP-only.
_RETRY_KINDS = ("tls", "refused", "connect-timeout", "reset", "proxy-error", "http")

def in_scope(host: str, domain: str) -> bool:
    # A target may be given as `host:port` (the CLI and the console both accept that), and the
    # scope is always the host part — same rule as `util.in_scope`, kept here so a probe cannot
    # silently skip every candidate when the operator typed a port.
    host = str(host or "").strip().lower().rstrip(".").split(":")[0]
    domain = str(domain or "").strip().lower().rstrip(".").split(":")[0]
    if not host or not domain:
        return False
    return host == domain or host.endswith("." + domain)

def _title(body: bytes) -> str:
    try:
        text = body.decode("utf-8", "replace")
    except Exception:                       # noqa: BLE001 - a title is never worth raising for
        return ""
    found = _TITLE.search(text[:200_000])
    return " ".join(found.group(1).split())[:160] if found else ""


def classify(status: int, host: str, title: str, body: bytes = b"") -> tuple[str, bool]:
    """Return (label, non_public). Pure table lookup — same input, same answer."""
    status = int(status or 0)
    if status == 0:
        return "dead", False
    if status in _GATED_STATUS:
        return "gated", True
    if 200 <= status < 400:
        haystack = f"{host} {title}".lower()
        if any(hint in haystack for hint in INTERNAL_HINTS):
            return "exposed", True
        # Structural signals only. A nav link containing "Login" is content, not a wall;
        # matching it made every marketing subdomain a non-public face and flipped the bet.
        if (any(hint in host.lower() for hint in LOGIN_HOST_HINTS)
                or _LOGIN_TITLE.match(title)):
            return "gated", True
        snippet = body[:8000].decode("utf-8", "replace").lower()
        if _LOGIN_MARKER in snippet:
            return "gated", True
        return "public", False
    if status == 404:
        return "dead", False
    return "error", False


def _attempt(session, scheme: str, host: str, port: int | None = None) -> dict:
    netloc = f"{host}:{port}" if port else host
    url = f"{scheme}://{netloc}/"
    resp = session.request(url, method="GET", max_bytes=32_000)
    status = int(getattr(resp, "status", 0) or 0)
    error = str(getattr(resp, "error", "") or "")
    body = getattr(resp, "body", b"") or b""
    return {"url": url, "status": status, "error": error, "body": body,
            "kind": error.split(":", 1)[0] if error else ""}


def _row(host: str, *, url: str = "", probed: bool = False, status: int = 0,
         title: str = "", label: str = "dead", non_public: bool = False,
         error: str = "", skipped: str = "") -> dict:
    row = {"host": host, "url": url or f"https://{host}/", "probed": probed,
           "status": status, "title": title, "label": label, "non_public": non_public,
           "error": error, "source": "active"}
    if skipped:
        row["skipped"] = skipped
    return row


def probe(session, hosts, domain: str, max_hosts: int = DEFAULT_MAX_HOSTS,
          port: int | None = None) -> list[dict]:
    """Probe up to *max_hosts* in-scope hosts once each and return one row per host.

    `port` exists for non-standard web ports (8080/8443 on internal hosts) and for tests; the
    default `None` means the scheme's standard port.
    """
    rows: list[dict] = []
    seen: set[str] = set()
    limit = max(0, int(max_hosts))
    probed_count = 0
    for raw in hosts or []:
        host = str(raw or "").strip().lower().rstrip(".")
        if not host or host in seen:
            continue
        seen.add(host)
        if not in_scope(host, domain):
            rows.append(_row(host, skipped="out_of_scope", label="skipped"))
            continue
        if probed_count >= limit:
            rows.append(_row(host, skipped="max_hosts", label="skipped"))
            continue
        probed_count += 1
        result = _attempt(session, "https", host, port)
        if result["status"] == 0 and result["kind"] in _RETRY_KINDS:
            fallback = _attempt(session, "http", host, port)
            if fallback["status"]:
                result = dict(fallback, kind=result["kind"])
        title = _title(result["body"]) if result["body"] else ""
        label, non_public = classify(result["status"], host, title, result["body"])
        rows.append(_row(host, url=result["url"], probed=result["status"] > 0,
                         status=result["status"], title=title, label=label,
                         non_public=non_public, error=result["error"][:200]))
    return rows


def stats(rows) -> dict:
    """Counts for `meta.subdomains`; names only, never bodies."""
    rows = list(rows or [])
    probed = [row for row in rows if row.get("probed")]
    labels: dict[str, int] = {}
    for row in rows:
        key = str(row.get("label") or "unknown")
        labels[key] = labels.get(key, 0) + 1
    return {
        "candidates": len(rows),
        "probed": len(probed),
        "live": sum(1 for row in probed if 200 <= int(row.get("status") or 0) < 400),
        "non_public": sum(1 for row in probed if row.get("non_public")),
        "gated": labels.get("gated", 0),
        "exposed": labels.get("exposed", 0),
        "skipped": labels.get("skipped", 0),
        "labels": labels,
    }
