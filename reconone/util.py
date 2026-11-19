"""Shared helpers: hashing, redaction, URL normalisation, deterministic JSON, JS prettifier."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

_ID_SEG = re.compile(r"^(?:\d{1,10}|[0-9a-fA-F]{16,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
_TMPL = re.compile(r"\$\{[^}]*\}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return os.path.abspath(path)


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def redact(secret: str) -> dict:
    """Never put a live secret in the machine report: only a masked form + verifiable hash."""
    if len(secret) <= 8:
        masked = "*" * len(secret)
    else:
        keep = 4 if len(secret) >= 16 else 2
        masked = f"{secret[:keep]}{'*' * (len(secret) - keep * 2)}{secret[-keep:]}"
    return {
        "masked": masked,
        "sha256_12": sha256_text(secret)[:12],
        "length": len(secret),
    }


# Response headers whose value is a credential, a session or a person. The *name* stays in
# the report (its presence is a finding); the value must never leave the process.
SENSITIVE_HEADERS = (
    "set-cookie", "cookie", "authorization", "proxy-authorization",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "x-session-id", "x-amz-security-token",
    "x-goog-api-key", "authentication-info", "www-authenticate",
)

# Query parameters whose value is a credential rather than a filter. Kept narrow on purpose:
# `id`, `page`, `q` are not secrets, and masking them would destroy the endpoint map.
SENSITIVE_PARAMS = (
    "token", "access_token", "id_token", "refresh_token", "api_key", "apikey",
    "key", "secret", "client_secret", "password", "passwd", "pwd", "sig",
    "signature", "auth", "session", "sessionid", "sid", "ticket", "jwt",
    "bearer", "credential", "sas", "code",
)

# Cookie attributes carry the analysis (HttpOnly / Secure / SameSite / lifetime). Only the
# value half of `name=value` is a secret, so the attributes survive redaction.
_COOKIE_ATTRS = ("expires", "max-age", "path", "domain", "secure", "httponly",
                 "samesite", "priority", "partitioned")


def redacted_marker(value: str) -> str:
    """A self-describing placeholder: no character of the original, but still checkable.

    `masked` in `redact()` keeps the first and last characters because a human needs to
    recognise the key they pasted. A session cookie has no such need: keeping any of it
    would let the value be confirmed by a third party. Length plus hash is enough to prove
    "this is the same value I saw" without enabling reuse.
    """
    return f"[redacted:{sha256_text(value)[:12]}:len={len(value)}]"


def redact_cookie_header(value: str) -> str:
    """Mask every cookie value, keep every attribute and every cookie name."""
    parts = []
    for chunk in str(value or "").split(";"):
        piece = chunk.strip()
        if not piece:
            continue
        name, sep, raw = piece.partition("=")
        low = name.strip().lower()
        if sep and low not in _COOKIE_ATTRS:
            parts.append(f"{name.strip()}={redacted_marker(raw)}")
        else:
            parts.append(piece)
    return "; ".join(parts)


def redact_header(name: str, value: str) -> str:
    """One header, redacted if its value is a credential. Non-sensitive headers pass through."""
    low = str(name or "").strip().lower()
    text = "" if value is None else str(value)
    if not text:
        return text
    if low in ("set-cookie", "cookie"):
        return redact_cookie_header(text)
    if low in SENSITIVE_HEADERS:
        return redacted_marker(text)
    return text


def scrub_headers(headers: dict | None) -> dict:
    """Header map with every credential value replaced. Key order and names are preserved."""
    return {k: redact_header(k, v) for k, v in (headers or {}).items()}


def redact_url(url: str) -> str:
    """Drop userinfo and mask sensitive query values, keeping scheme/host/path intact.

    The path stays: it is the finding. Only the parts that authenticate a request go.
    """
    text = str(url or "")
    if not text:
        return text
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    netloc = parts.netloc
    if "@" in netloc:
        host = netloc.rsplit("@", 1)[1]
        netloc = f"[redacted]@{host}"
    query = parts.query
    if query:
        pairs = []
        for name, value in parse_qsl(query, keep_blank_values=True):
            if name.lower() in SENSITIVE_PARAMS and value:
                pairs.append((name, redacted_marker(value)))
            else:
                pairs.append((name, value))
        query = urlencode(pairs, safe="[]:,=")
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def scrub_header_block(text: str) -> str:
    """Redact a raw header dump ("name: value" per line), as used in evidence snippets.

    `derive_findings()` stores the whole response header block as the snippet behind every
    header claim — which is right (the evidence has to be checkable) and wrong (it carried
    `authorization:` and `set-cookie:` verbatim). This keeps the block readable while making
    the credential lines unreadable.
    """
    out = []
    for line in str(text or "").splitlines():
        name, sep, value = line.partition(":")
        low = name.strip().lower()
        if sep and (low in SENSITIVE_HEADERS or low in ("set-cookie", "cookie")):
            out.append(f"{name}: {redact_header(name.strip(), value.strip())}")
        else:
            out.append(line)
    return "\n".join(out)


def scrub_urls(value, depth: int = 0):
    """Walk a report fragment and redact every URL-shaped string it contains."""
    if depth > 6:
        return value
    if isinstance(value, str):
        return redact_url(value) if "://" in value else value
    if isinstance(value, list):
        return [scrub_urls(item, depth + 1) for item in value]
    if isinstance(value, dict):
        return {k: scrub_urls(v, depth + 1) for k, v in value.items()}
    return value


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def origin_of(url: str) -> str:
    try:
        p = urlsplit(url)
    except ValueError:
        return ""
    if not p.scheme or not p.hostname:
        return ""
    netloc = p.hostname if not p.port else f"{p.hostname}:{p.port}"
    return f"{p.scheme}://{netloc}"


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without the public-suffix list (handles common two-label suffixes)."""
    host = (host or "").lower().strip(".")
    if not host or host.replace(".", "").isdigit():
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "mil", "sch"}
    if labels[-2] in two and len(labels[-1]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_part(value: str) -> str:
    """Host part of a target that may be `host:port`, `[v6]:port`, or a bare literal.

    One definition for scope checks, cookie scopes and "is this an IP" decisions. Splitting
    on `:` alone was wrong for `[::1]:8443`; treating any `:` as "IP" was wrong for
    `example.com:8443` (a host name with a port is not an address).
    """
    text = str(value or "").strip().lstrip(".").lower()
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def is_ip_literal(value: str) -> bool:
    """True only for an actual IP address, never for `example.com:8443`."""
    import ipaddress

    try:
        ipaddress.ip_address(host_part(value))
        return True
    except ValueError:
        return False


def in_scope(host: str, domain: str) -> bool:
    # a target may be given as host:port; scope is always compared on the host part
    host = host_part(host)
    domain = host_part(domain)
    return bool(host and domain) and (host == domain or host.endswith("." + domain))


def norm_endpoint(path: str) -> str:
    """Collapse variable path segments so 'same endpoint, different object' merges into one row."""
    path = path.strip()
    path = _TMPL.sub("{param}", path)
    base, sep, query = path.partition("?")
    segs = []
    for seg in base.split("/"):
        if not seg:
            segs.append(seg)
        elif _ID_SEG.match(seg):
            segs.append("{id}")
        elif re.fullmatch(r"[0-9a-fA-F]{8,}", seg):
            segs.append("{id}")
        else:
            segs.append(seg)
    out = "/".join(segs)
    if sep:
        pairs = sorted(parse_qsl(query, keep_blank_values=True))
        out += "?" + urlencode([(k, v) for k, v in pairs])
    return out


_STRONG = re.compile(r"(?i)(?:api|v[0-9]+|rest|graphql|gql|rpc|internal|admin|service|backend|internalapi)")


def looks_like_endpoint(value: str) -> bool:
    if not value or len(value) < 3 or len(value) > 400:
        return False
    if any(c in value for c in " \t\n\r\"'<>"):
        return False
    if value.startswith(("//", "data:", "mailto:", "tel:", "javascript:", "#", "blob:")):
        return False
    if value.startswith("/"):
        return len(value) > 1
    if value.startswith(("http://", "https://")):
        return True
    return bool(_STRONG.search(value)) and "/" in value


def pretty_minified(text: str, max_chars: int = 6_000_000, max_line: int = 200) -> str:
    """Insert newlines into a minified bundle without touching string literals.

    This is not a real parser: it only tracks quote state and escapes, which is enough to keep
    string contents intact while making offsets readable for a human or an LLM.
    """
    if len(text) > max_chars:
        return text
    nl = 0
    if text.count("\n") < 5 and len(text) > 20_000:
        pass
    out = []
    quote = None
    escaped = False
    line_len = 0
    for ch in text:
        out.append(ch)
        line_len += 1
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
        elif ch in (";", "{", "}"):
            if line_len > 0:
                out.append("\n")
                line_len = 0
                nl += 1
        elif ch == "," and line_len > max_line:
            out.append("\n")
            line_len = 0
            nl += 1
    return "".join(out)


def clip(text: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def dedupe(items, key=None):
    seen, out = set(), []
    for item in items:
        k = key(item) if key else item
        if k in seen:
            continue
        seen.add(k)
        out.append(item)
    return out


def safe_name(value: str, limit: int = 60) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return (cleaned or "x")[:limit]


# Response metadata the server regenerates on every request. It has no audit value that
# the rest of the header block does not already carry, but it breaks any digest or
# evidence comparison that includes it. Kept here so score.py and report.py cannot drift
# apart on the definition.
VOLATILE_HEADERS = ("date",)
