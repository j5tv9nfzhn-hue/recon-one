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


def in_scope(host: str, domain: str) -> bool:
    # a target may be given as host:port; scope is always compared on the host part
    host = (host or "").lower().split(":")[0]
    domain = (domain or "").lower().split(":")[0]
    return host == domain or host.endswith("." + domain)


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
