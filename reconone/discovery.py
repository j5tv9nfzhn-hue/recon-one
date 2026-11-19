"""Targeted content discovery: a small candidate set, checked against a 404 baseline.

What this is
------------
The next question after "which endpoints does the front end call?" is "which paths exist
that it never linked?". A full directory wordlist is both noisy and outside this tool's
posture, so this module builds a **bounded, explainable** candidate set from evidence the
scan already has:

* directory prefixes of JS/spec endpoints (`/api/v1/users/{id}` → `/api/`, `/api/v1/`);
* a short, versioned table of paths for detected technologies (`rules/discovery.json`);
* a small common list of API/ops/documentation roots.

Every candidate is then **observed**, not assumed: one GET each, compared with a request to
a deterministic non-existent path. Without that baseline an SPA that answers 200 to every
path makes every wordlist entry look "found"; with it, a candidate that merely repeats the
404 shell is recorded as `absent (soft-404)`.

Boundaries
----------
* GET only, no request body, no brute force; the candidate cap is explicit and comes from
  the profile (`discovery_max`) or `--discovery-max`.
* Every request goes through `Session` (scope guard, limiter, egress, injection, cookie
  jar) and goes into `requests.jsonl`.
* Destructive-looking paths are skipped with the same word-boundary rule as verification.
* A baseline that is itself 401/403/429/5xx means the site cannot answer this question
  anonymously; the module returns `baseline-blocked` and probes nothing.
"""
from __future__ import annotations

import re
import time

from .config import load_rule
from .util import clip, norm_endpoint, sha256_text
from .verify import build_roe

VERSION = "1"
DEFAULT_MAX_CANDIDATES = 80
BASELINE_BYTES = 16_000
CANDIDATE_BYTES = 16_000
SOFT_404_TOLERANCE = 0.05
#: Root + a handful of directory baselines. A single root baseline cannot see an API
#: router that answers 200 to every path under `/api/`.
MAX_BASELINES = 12

STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".rar", ".pdf", ".css", ".js",
    ".map", ".exe", ".dmg", ".iso", ".bin",
)

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _clean_path(value: str) -> str:
    """One site-absolute path; absolute URLs are rejected, not rewritten.

    A candidate must be a path on the scanned target. Turning `https://other.example/x`
    into `/x` would silently probe the wrong host's path; the caller's endpoint list is
    already same-origin, and this guard keeps it that way.
    """
    text = str(value or "").strip()
    if "://" in text or text.startswith("//"):
        return ""
    text = text.split("?", 1)[0].split("#", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    if len(text) > 200 or ".." in text.split("/"):
        return ""
    if any(ch in text for ch in "\\\"'<> \t\r\n"):
        return ""
    return text


def _is_static(path: str) -> bool:
    return path.split("?", 1)[0].lower().endswith(STATIC_EXT)


def _prefixes(endpoint_paths) -> list[str]:
    """Directory prefixes of observed endpoints; stops before a variable segment."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in endpoint_paths or []:
        path = _clean_path(raw)
        segments = [s for s in path.split("/") if s]
        for depth in range(1, min(3, len(segments)) + 1):
            head = segments[:depth]
            if any(s.startswith(("{", "$", ":", "*")) for s in head):
                break
            prefix = "/" + "/".join(head) + "/"
            if prefix not in seen:
                seen.add(prefix)
                out.append(prefix)
    return out


def candidates(endpoint_paths, tech_names, domain: str = "", rules: dict | None = None,
               max_candidates: int = 0) -> tuple[list[dict], int]:
    """Return (selected candidates, number dropped by the cap).

    Order is deliberate: technology-specific paths first, then the small common list, then
    prefixes derived from the target's own JS/spec. A target with hundreds of JS endpoints
    therefore cannot crowd out `/actuator` on a Spring site.
    """
    rules = rules or load_rule("discovery", default={}) or {}
    cap = int(max_candidates or rules.get("max_candidates") or DEFAULT_MAX_CANDIDATES)
    cap = max(0, cap)
    if cap == 0:
        return [], 0

    existing_raw = {_clean_path(p) for p in endpoint_paths or [] if _clean_path(p)}
    existing_norm = {norm_endpoint(p) for p in existing_raw}
    ordered: list[tuple[str, str]] = []
    tech_blob = " ".join(str(name).lower() for name in (tech_names or []))
    for key, paths in sorted((rules.get("tech") or {}).items()):
        if str(key).lower() in tech_blob:
            ordered.extend((path, f"tech:{key}") for path in paths or [])
    ordered.extend((path, "common") for path in rules.get("common") or [])
    ordered.extend((path, "prefix") for path in _prefixes(endpoint_paths))

    roe = build_roe(domain, max_requests=cap)
    out: list[dict] = []
    seen: set[str] = set()
    eligible = 0
    for raw, source in ordered:
        path = _clean_path(raw)
        if not path or path == "/" or path in seen:
            continue
        norm = norm_endpoint(path)
        if path in existing_raw or norm in existing_norm:
            continue
        if _is_static(path) or roe.path_excluded(path):
            continue
        seen.add(path)
        eligible += 1
        if len(out) < cap:
            out.append({"path": path, "norm": norm, "source": source})
    return out, max(0, eligible - len(out))


def baseline_path(domain: str) -> str:
    """Deterministic improbable path: same target → same baseline, reproducible packages.

    No leading dot: many servers return 403 for dotfiles (`.env`, `.git` rules), which would
    turn a perfectly healthy target into `baseline-blocked` and skip discovery entirely.
    """
    token = sha256_text(str(domain or "target"))[:10]
    return f"/reconone-{token}-not-found"


def _prefix_for(path: str) -> str:
    """The directory a candidate belongs to; `/api/v1/x/` → `/api/v1/`."""
    clean = (path or "/").rstrip("/")
    if not clean:
        return "/"
    parent = clean.rsplit("/", 1)[0]
    return "/" if not parent else parent.rstrip("/") + "/"


def _baseline_prefixes(selected: list[dict]) -> list[str]:
    """Root first, then the most-used parent directories (bounded, deterministic)."""
    counts: dict[str, int] = {}
    for item in selected:
        prefix = _prefix_for(item["path"])
        counts[prefix] = counts.get(prefix, 0) + 1
    others = sorted((p for p in counts if p != "/"), key=lambda p: (-counts[p], p))
    return ["/"] + others[: max(0, MAX_BASELINES - 1)]


def _title(body: bytes) -> str:
    try:
        text = body.decode("utf-8", "replace")
    except Exception:                       # noqa: BLE001 - a title is never worth raising for
        return ""
    found = _TITLE.search(text[:200_000])
    return " ".join(found.group(1).split())[:120] if found else ""


def _shape(body: bytes, path: str) -> str:
    """Body hash with the candidate path removed, so an echoed 404 path compares equal."""
    text = body[:8000].decode("utf-8", "replace").replace(path, "")
    return sha256_text(text)


def _soft_404(status: int, body: bytes, path: str, baseline: dict,
              baseline_shape: str) -> bool:
    if not baseline.get("soft_404"):
        return False
    if int(status or 0) != int(baseline.get("status") or 0):
        return False
    if _title(body) != baseline.get("title"):
        return False
    if _shape(body, path) == baseline_shape:
        return True
    a, b = len(body), int(baseline.get("bytes") or 0)
    longer = max(a, b, 1)
    return abs(a - b) / longer <= SOFT_404_TOLERANCE


def _covering_baseline(path: str, baselines: dict) -> dict:
    """Nearest fetched directory baseline; root is always the final fallback."""
    prefix = _prefix_for(path)
    while True:
        if prefix in baselines:
            return baselines[prefix]
        if prefix == "/":
            return baselines.get("/") or {}
        prefix = _prefix_for(prefix)


def classify(status: int, body: bytes, path: str, baseline: dict,
             baseline_shape: str = "") -> tuple[str, str]:
    """Return (label, reason). `present`/`gated` are the only positives."""
    status = int(status or 0)
    if status in (401, 403):
        return "gated", f"status {status}（存在但受保护）"
    if 200 <= status < 400:
        if _soft_404(status, body, path, baseline, baseline_shape):
            return "absent", "soft-404（与基线响应相同）"
        return "present", ""
    if status in (404, 410):
        return "absent", f"status {status}"
    if status == 405:
        return "present", "405：GET 不被允许，但路径存在"
    if status == 429:
        return "error", "429：被限流，未取得可用答案"
    if status >= 500:
        return "error", f"status {status}"
    return "absent", f"status {status}"


def run(session, base_url: str, endpoint_paths, tech_names, domain: str,
        max_candidates: int = 0, rules: dict | None = None) -> dict:
    """Build the bounded candidate set, probe it once, and return a reproducible block."""
    rules = rules or load_rule("discovery", default={}) or {}
    selected, dropped = candidates(endpoint_paths, tech_names, domain, rules, max_candidates)
    block = {
        "version": VERSION,
        "enabled": True,
        "status": "empty",
        "policy": {
            "methods": ["GET"],
            "max_candidates": int(max_candidates or rules.get("max_candidates")
                                  or DEFAULT_MAX_CANDIDATES),
            "max_requests": MAX_BASELINES + len(selected),
            "baseline_bytes": BASELINE_BYTES,
            "candidate_bytes": CANDIDATE_BYTES,
            "note": "只发 GET；候选来自已观测端点前缀 + 技术栈表 + 小规模公共路径；不是字典。",
        },
        "baseline": {},
        "baselines": [],
        "stats": {
            "candidates": len(selected),
            "dropped_by_cap": dropped,
            "probed": 0,
            "present": 0,
            "gated": 0,
            "absent": 0,
            "error": 0,
            "skipped_by_baseline": 0,
            "truncated": False,
            "requests": 0,
        },
        "sources": {},
        "rows": [],
    }
    for item in selected:
        block["sources"][item["source"]] = block["sources"].get(item["source"], 0) + 1
    if not selected:
        return block

    base = str(base_url or "").rstrip("/")
    root_probe = baseline_path(domain)
    prefixes = _baseline_prefixes(selected)
    baselines: dict[str, dict] = {}
    shapes: dict[str, str] = {}
    for prefix in prefixes:
        probe_path = root_probe if prefix == "/" else prefix + root_probe.lstrip("/")
        resp = session.request(base + probe_path, method="GET",
                               max_bytes=BASELINE_BYTES)
        body = getattr(resp, "body", b"") or b""
        baseline = {
            "prefix": prefix,
            "path": probe_path,
            "url": base + probe_path,
            "status": int(getattr(resp, "status", 0) or 0),
            "bytes": len(body),
            "title": _title(body),
            "soft_404": False,
            "blocked": False,
            "error": str(getattr(resp, "error", "") or "")[:200],
        }
        block["stats"]["requests"] += 1
        if baseline["error"] or baseline["status"] in (401, 403, 429) or baseline["status"] >= 500:
            baseline["blocked"] = True
        else:
            baseline["soft_404"] = 200 <= baseline["status"] < 400
        baselines[prefix] = baseline
        shapes[prefix] = _shape(body, probe_path)
        if prefix == "/":
            block["baseline"] = baseline
            if baseline["blocked"]:
                block["status"] = "baseline-blocked"
                block["reason"] = (
                    f"根基线返回 {baseline['status'] or 'error'}，无法把“存在”与“被拦截/错误页”"
                    "分开；未探测候选")
                block["baselines"] = [baseline]
                return block
    block["baselines"] = [baselines[p] for p in prefixes]

    for item in selected:
        if getattr(session, "exhausted", False):
            block["stats"]["truncated"] = True
            break
        deadline = getattr(session, "deadline", None)
        if deadline and time.time() > deadline:
            block["stats"]["truncated"] = True
            break
        cover = _covering_baseline(item["path"], baselines)
        if cover.get("blocked"):
            block["stats"]["skipped_by_baseline"] += 1
            label, reason = ("error",
                             f"前缀基线 {cover.get('prefix', '/')} 返回 "
                             f"{cover.get('status') or 'error'}；无法区分存在与被拦截，未探测")
            resp = None
            body, error = b"", ""
        else:
            resp = session.request(base + item["path"], method="GET",
                                   max_bytes=CANDIDATE_BYTES)
            block["stats"]["probed"] += 1
            block["stats"]["requests"] += 1
            body = getattr(resp, "body", b"") or b""
            error = str(getattr(resp, "error", "") or "")
            if error:
                label, reason = "error", clip(error, 160)
            else:
                label, reason = classify(int(getattr(resp, "status", 0) or 0), body,
                                         item["path"], cover,
                                         shapes.get(cover.get("prefix", "/"), ""))
        block["stats"][label] = block["stats"].get(label, 0) + 1
        block["rows"].append({
            "path": item["path"],
            "source": item["source"],
            "url": base + item["path"],
            "status": int(getattr(resp, "status", 0) or 0),
            "bytes": len(body),
            "title": _title(body),
            "label": label,
            "reason": reason,
            "soft_404": label == "absent" and "soft-404" in reason,
            "error": error[:200],
        })

    if block["stats"]["truncated"]:
        block["status"] = "truncated"
    elif block["stats"]["probed"] or block["rows"]:
        # A blocked prefix produces an error row without a probe; the stage still ran.
        block["status"] = "ok"
    return block


def endpoints(block: dict) -> list[dict]:
    """Positive discovery rows as endpoint entries (no anonymous-access claim)."""
    out: list[dict] = []
    for row in (block or {}).get("rows") or []:
        if row.get("label") not in ("present", "gated"):
            continue
        status = int(row.get("status") or 0)
        out.append({
            "path": norm_endpoint(row.get("path") or "/"),
            "raw": row.get("path") or "/",
            "methods": ["GET"],
            "params": [],
            "confidence": "low",
            "sources": ["content-discovery"],
            "evidence": [{"file": "live-http", "offset": 0,
                          "snippet": f"GET {row.get('path')} -> {status}"}],
            "verified": "usable" if status in (200, 201, 202, 203, 204, 205, 206,
                                               300, 301, 302, 303, 304, 307, 308,
                                               401, 403, 405, 429) else None,
            "discovered": True,
            "discovery_label": row.get("label"),
        })
    return out
