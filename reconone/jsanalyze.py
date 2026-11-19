"""Front-end JavaScript analysis: endpoints, parameters, secrets, hosts, source maps.

Everything here is offline static analysis of already-public assets; no exploitation happens.
Each hit keeps a file + byte offset + snippet so the report is verifiable, not a bare string list.
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urljoin, urlsplit

from .config import load_rule
from .util import (clip, dedupe, host_of, in_scope, looks_like_endpoint, norm_endpoint,
                   pretty_minified, redact, safe_name, sha256_bytes)

STATIC_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf",
              ".eot", ".css", ".js", ".mjs", ".map", ".mp4", ".mp3", ".webmanifest")

RE_ABS = re.compile(r"""["'`](https?://[^"'`\s\\<>{}\[\]]{4,300})["'`]""")
RE_PATH = re.compile(r"""["'`](/(?:[A-Za-z0-9_\-${}.~/]|%[0-9A-Fa-f]{2}){2,300})["'`]""")
RE_CALL = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head))?|\$\.(?:ajax|get|post)|\.open)"""
    r"""\s*\(\s*["'`]([^"'`]{2,300})["'`]""")
RE_CFG = re.compile(r"""(?:baseURL|baseUrl|apiUrl|apiURL|API_URL|API_BASE|apiBase|endpoint|API_ENDPOINT)"""
                    r"""\s*[:=]\s*["'`]([^"'`]{2,300})["'`]""")
RE_METHOD = re.compile(r"""method\s*:\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]""", re.I)
RE_SOURCEMAP = re.compile(r"""[#@]\s*sourceMappingURL=([^\s'"]+)""")
RE_GRAPHQL = re.compile(r"""["'`]([^"'`\s]{0,60}graphql[^"'`\s]{0,40})["'`]""", re.I)
RE_JSCHUNK = re.compile(r"""["'`]([^"'`\s]{1,200}?\.js)["'`]""")

# --- request bodies -------------------------------------------------------------------
# The point of front-end reverse engineering is to learn what a write endpoint expects
# *before* touching it. Extracting only query strings leaves every POST looking opaque.
# All three patterns capture the literal object/array text; keys are pulled out of it.
# Anchored on the `body:` property, optionally wrapping JSON.stringify(). Anchoring matters:
# a bare object literal also matches every header map, which made `Content-Type` show up as
# a request parameter.
RE_BODY_JSON = re.compile(
    r"""body\s*[:=]\s*(?:JSON\.stringify\s*\(\s*)?\{([^{}]{2,4000})\}\s*\)?""")
RE_BODY_KV = re.compile(
    r"""(?:^|[,{\s])(?:params|payload)\s*[:=]\s*\{([^{}]{2,2000})\}""")
# axios.put("/x/", {a:1}) puts the body in the second positional argument.
RE_BODY_POS = re.compile(
    r"""\.(?:post|put|patch)\s*\(\s*[`"'][^`"']{1,300}[`"']\s*,\s*\{([^{}]{2,3000})\}""")
RE_BODY_FORMDATA = re.compile(r"""\.append\s*\(\s*["'`]([A-Za-z_][\w.\[\]-]{1,50})["'`]""")
RE_KEY = re.compile(r"""(?:^|[,{])\s*["'`]?([A-Za-z_$][\w$.-]{1,50})["'`]?\s*:""")

# Keys that appear in every bundle and mean nothing as a parameter name.
BODY_KEY_DENY = {
    "data", "result", "error", "errors", "status", "success", "message", "code", "type",
    "id", "name", "value", "key", "items", "list", "count", "total", "page", "content",
    "children", "props", "style", "className", "toString", "length", "map", "filter",
}

RISK_PATTERNS = [
    ("dangerously_set_inner_html", r"dangerouslySetInnerHTML", "medium"),
    ("inner_html_sink", r"\.innerHTML\s*=", "low"),
    ("eval_sink", r"\beval\s*\(", "medium"),
    ("post_message", r"postMessage\s*\(", "low"),
    ("document_domain", r"document\.domain\s*=", "medium"),
    ("token_in_storage", r"(?:localStorage|sessionStorage)\.setItem\(\s*['\"][^'\"]*(?:token|jwt|auth)", "medium"),
    ("debug_flag", r"(?:debug|verbose)\s*[:=]\s*true", "low"),
    ("basic_auth_in_url", r"https?://[^/\s:@]{1,40}:[^/\s@]{1,40}@", "high"),
]


# Counting stops here; the number is reported so a caller can tell 3 sinks from 300.
HINT_COUNT_CAP = 500

INTERNAL_TLDS = (".internal", ".local", ".corp", ".lan", ".intranet", ".home", ".intra",
                 ".svc", ".cluster.local", ".ad", ".test", ".example")

# Coverage matters here: cloud and k8s environments leak 100.64/10 and *.svc far more often
# than they leak 10/8.
INTERNAL_HOST_RE = re.compile(
    r"^(?:localhost"
    r"|127\."
    r"|10\."
    r"|192\.168\."
    r"|169\.254\."
    r"|172\.(?:1[6-9]|2\d|3[01])\."
    r"|100\.(?:6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\."
    r"|::1$"
    r"|\[::1\]$)")


LOOPBACK_RE = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+|\[::1\]|::1)$", re.I)


def _method_at(text: str, pos: int) -> str:
    window = text[max(0, pos - 160):pos + 160]
    m = RE_METHOD.search(window)
    return m.group(1).upper() if m else ""


def _classify_url(value: str, domain: str) -> tuple[str, str]:
    """Return (kind, normalised_path) where kind is same_host|external|internal|path."""
    if value.startswith(("http://", "https://")):
        host = host_of(value)
        try:
            parts = urlsplit(value)
        except ValueError:
            return "external", value
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if host and in_scope(host, domain):
            return "same_host", path
        if LOOPBACK_RE.match(host or ""):
            # localhost/127.x in a bundle means "the machine running the browser", not a
            # reachable internal service. Classifying it as internal produces a false
            # positive on nearly every SPA, so it gets its own kind.
            return "reference", f"http://{host}{path}"
        if INTERNAL_HOST_RE.match(host) or host.endswith(INTERNAL_TLDS):
            return "internal", f"http://{host}{path}"
        return "external", f"https://{host}{path}"
    return "path", value


_GQL_PATH = re.compile(r"^/(?:[A-Za-z0-9_.-]+/){0,3}(?:graphql|gql|query)/?$", re.I)


def _looks_like_gql_path(path: str) -> bool:
    return bool(path and _GQL_PATH.match(path))


def _is_static(path: str) -> bool:
    return path.split("?")[0].lower().endswith(STATIC_EXT)


def extract(text: str, domain: str, source: str) -> dict:
    endpoints: dict[str, dict] = {}
    hosts: dict[str, dict] = {}
    params: dict[str, dict] = {}
    secrets: list[dict] = []
    hints: list[dict] = []
    chunks: set[str] = set()
    graphql: set[str] = set()

    def add_endpoint(raw_url: str, pos: int, confidence: str, via: str):
        kind, path = _classify_url(raw_url, domain)
        if kind in ("external", "internal", "reference"):
            hosts.setdefault(path, {"url": path, "kind": kind, "source": source,
                                    "offset": pos, "snippet": clip(text[pos:pos + 120])})
            return
        if not looks_like_endpoint(path) or _is_static(path):
            return
        norm = norm_endpoint(path)
        entry = endpoints.setdefault(norm, {
            "path": norm, "raw": path, "methods": set(), "sources": set(),
            "confidence": confidence, "evidence": [], "params": set(),
        })
        rank = {"high": 3, "medium": 2, "low": 1}
        if rank.get(confidence, 0) > rank.get(entry["confidence"], 0):
            entry["confidence"] = confidence
            entry["raw"] = path
        entry["sources"].add(via)
        method = _method_at(text, pos)
        if method:
            entry["methods"].add(method)
        if len(entry["evidence"]) < 3:
            entry["evidence"].append({"file": source, "offset": pos,
                                      "snippet": clip(text[max(0, pos - 40):pos + 100])})
        query = path.partition("?")[2]
        for name in re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_]{1,40})=", "?" + query):
            entry["params"].add(name)
            params.setdefault(name, {"name": name, "in": "query", "endpoints": set(),
                                     "source": source})
            params[name]["endpoints"].add(norm)

    for rx, conf, via in ((RE_CALL, "high", "js-call"), (RE_CFG, "high", "js-config"),
                          (RE_ABS, "medium", "js-literal"), (RE_PATH, "low", "js-string")):
        for m in rx.finditer(text):
            add_endpoint(m.group(1), m.start(1), conf, via)

    for m in RE_GRAPHQL.finditer(text):
        value = m.group(1)
        # Only plausible API paths: '/graphql', '/api/graphql', '/gql', '/query'... Anything else
        # (graphql-ws, GraphQLPlayground, use-graphql-hook) would otherwise become a bogus
        # candidate that probe_graphql then POSTs 8 times.
        if value.startswith("/") and _looks_like_gql_path(value):
            graphql.add(norm_endpoint(value))
        elif "graphql" in value and value.startswith(("http://", "https://")):
            host = host_of(value)
            if host and in_scope(host, domain) and _looks_like_gql_path(urlsplit(value).path if "/" in value else ""):
                try:
                    graphql.add(norm_endpoint(urlsplit(value).path))
                except ValueError:
                    pass

    for m in RE_JSCHUNK.finditer(text):
        value = m.group(1)
        if value.endswith(".js") and not value.startswith(("http", "//")):
            chunks.add(value)

    for rule in load_rule("secrets", {"patterns": []}).get("patterns", []):
        try:
            rx = re.compile(rule["regex"])
        except (re.error, KeyError):
            continue
        for m in rx.finditer(text):
            value = m.group(rule.get("group", 0))
            if len(value) < int(rule.get("min_len", 8)):
                continue
            secrets.append({
                "type": rule["name"], "severity": rule.get("severity", "medium"),
                "_raw": value,
                **redact(value),
                "evidence": {"file": source, "offset": m.start(),
                             "snippet": clip(text[max(0, m.start() - 30):m.start() + 60])},
            })

    for name, pattern, severity in RISK_PATTERNS:
        count = 0
        first = None
        for m in re.finditer(pattern, text):
            count += 1
            if first is None:
                first = m.start()
            if count >= HINT_COUNT_CAP:
                break
        if first is None:
            continue
        # One hint per (kind, file) carrying the occurrence count, not one hint per match.
        # .innerHTML= appears hundreds of times in any real bundle; the useful signal is
        # "this file sinks to innerHTML, N times", not N near-identical rows.
        hints.append({"kind": name, "severity": severity, "file": source, "occurrences": count,
                      "offset": first,
                      "snippet": clip(text[max(0, first - 40):first + 80])})

    # Body fields are attributed to the bundle, not to one endpoint: minified code rarely
    # keeps the literal next to the call, and guessing a link would manufacture evidence.
    bodies = _extract_bodies(text, source)
    for b in bodies:
        name = b["name"]
        if name not in params:
            params[name] = {"name": name, "in": b["in"], "endpoints": set(),
                            "source": source, "evidence": b}

    return {"endpoints": endpoints, "hosts": hosts, "params": params, "secrets": secrets,
            "hints": hints, "chunks": chunks, "graphql": graphql, "body_fields": bodies}


def _extract_bodies(text: str, source: str) -> list[dict]:
    """Pull request-body field names out of a bundle.

    Deliberately conservative: we return field *names* with a byte offset, never values.
    A body literal only counts when it sits near a network call, otherwise every React
    prop object in the bundle would be reported as an API payload.
    """
    calls = [m.start() for m in re.finditer(
        r"(?:fetch|axios(?:\.[a-z]+)?|XMLHttpRequest|\.open)\s*\(", text)]
    import bisect

    found: list[dict] = []

    def near_call(pos: int, window: int = 600) -> bool:
        i = bisect.bisect_left(calls, pos)
        for j in (i - 1, i):
            if 0 <= j < len(calls) and abs(calls[j] - pos) <= window:
                return True
        return False

    seen: set[str] = set()
    # RE_BODY_POS already requires `.post(`/`.put(`/`.patch(` immediately before the literal,
    # so it is self-anchored; only the generic object patterns need the proximity test.
    for rx, anchored in ((RE_BODY_JSON, False), (RE_BODY_KV, False), (RE_BODY_POS, True)):
        for m in rx.finditer(text):
            if not anchored and not near_call(m.start()):
                continue
            keys = [k for k in RE_KEY.findall(m.group(1))
                    if k.lower() not in BODY_KEY_DENY and not k.startswith(("aria", "data-"))]
            if not keys:
                continue
            for key in dict.fromkeys(keys):
                if key in seen:
                    continue
                seen.add(key)
                found.append({"name": key, "in": "body", "source": source,
                              "offset": m.start(),
                              "snippet": clip(text[m.start():m.start() + 120])})
    for m in RE_BODY_FORMDATA.finditer(text):
        key = m.group(1)
        if key in seen:
            continue
        seen.add(key)
        found.append({"name": key, "in": "form", "source": source, "offset": m.start(),
                      "snippet": clip(text[max(0, m.start() - 40):m.start() + 80])})
    return found


def _fetch_sourcemap(session, map_url: str, out_dir: str) -> dict:
    resp = session.request(map_url, max_bytes=8_000_000)
    if resp.error or resp.status >= 400:
        return {"url": map_url, "error": resp.error or f"status {resp.status}"}
    try:
        data = json.loads(resp.text())
    except ValueError:
        return {"url": map_url, "error": "not json"}
    sources = data.get("sources") or []
    has_content = bool(data.get("sourcesContent"))
    name = f"{safe_name(sha256_bytes(resp.body)[:16])}.map"
    path = os.path.join(out_dir, "raw", "maps", name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(resp.body)
    return {
        "url": map_url, "sources": sources[:300], "source_count": len(sources),
        "sources_content": has_content,
        "leaks_original_source": has_content,
        "artifact": os.path.relpath(path, out_dir).replace("\\", "/"),
        "bytes": len(resp.body),
    }


# Confidence per provenance. Anything that came from a third-party index or a plain link is
# "low": it proves the path exists somewhere, not that it is an API endpoint today.
SOURCE_CONFIDENCE = {
    "js-call": "high", "js-config": "high", "openapi-spec": "high",
    "js-literal": "medium", "html-link": "medium", "html-form": "medium",
    "robots": "low", "sitemap": "low", "wayback": "low",
}


def from_paths(items, domain: str, source: str, confidence: str = "") -> list[dict]:
    """Endpoints from *non-JS* sources: crawl links, form actions, robots, sitemap, archive.

    This exists so the pipeline can produce an API map without downloading a single bundle:
    the same normalisation and filtering as `extract()`, but the input is a plain path list.
    """
    conf = confidence or SOURCE_CONFIDENCE.get(source, "low")
    found: dict[str, dict] = {}
    for raw in items or []:
        value = str(raw or "").strip()
        if not value:
            continue
        if value.startswith(("http://", "https://")):
            kind, path = _classify_url(value, domain)
            if kind != "same_host":
                continue
        else:
            path = value if value.startswith("/") else "/" + value
        path = path.split("#", 1)[0]
        if not looks_like_endpoint(path) or _is_static(path):
            continue
        norm = norm_endpoint(path)
        entry = found.setdefault(norm, {
            "path": norm, "raw": path, "methods": ["GET?"], "confidence": conf,
            "sources": [source], "params": [], "evidence": [], "in_scope": True,
        })
        query = path.partition("?")[2]
        for name in re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_]{1,40})=", "?" + query):
            if name not in entry["params"]:
                entry["params"].append(name)
        if len(entry["evidence"]) < 2:
            entry["evidence"].append({"file": source, "offset": 0, "snippet": clip(path, 120)})
    return sorted(found.values(), key=lambda e: e["path"])


def merge_endpoints(base: list[dict], extra: list[dict]) -> list[dict]:
    """Union endpoint lists by normalised path, keeping the stronger confidence."""
    rank = {"high": 3, "medium": 2, "low": 1}
    merged = {e["path"]: dict(e) for e in (base or [])}
    for entry in extra or []:
        cur = merged.get(entry["path"])
        if cur is None:
            merged[entry["path"]] = dict(entry)
            continue
        cur["sources"] = sorted(set(cur.get("sources") or []) | set(entry.get("sources") or []))
        if rank.get(entry.get("confidence", "low"), 1) > rank.get(cur.get("confidence", "low"), 1):
            cur["confidence"] = entry["confidence"]
            cur["raw"] = entry.get("raw", cur.get("raw"))
        for key in ("methods", "params"):
            cur[key] = sorted(set(cur.get(key) or []) | set(entry.get(key) or []))
        if len(cur.get("evidence") or []) < 3:
            cur["evidence"] = (cur.get("evidence") or []) + (entry.get("evidence") or [])[:1]
    return sorted(merged.values(), key=lambda e: e["path"])


def analyze(session, script_urls: list[str], inline_scripts: list[str], domain: str,
            out_dir: str, max_scripts: int = 60, max_js_bytes: int = 1_500_000,
            max_total_js_bytes: int = 12_000_000) -> dict:
    os.makedirs(os.path.join(out_dir, "raw", "js"), exist_ok=True)
    scripts: list[dict] = []
    merged = {"endpoints": {}, "hosts": {}, "params": {}, "secrets": [], "hints": [], "chunks": set(),
              "graphql": set()}

    # Two URLs can serve byte-identical bundles; the artifact name is the content hash, so
    # both land on the same file and every hint/secret is produced twice. Findings are
    # keyed by (kind, file, offset) so the report counts one occurrence, not two rows that
    # look like two separate problems.
    hint_keys: set[tuple] = set()
    secret_keys: set[tuple] = set()

    def merge(result, source_name):
        for norm, entry in result["endpoints"].items():
            if norm in merged["endpoints"]:
                tgt = merged["endpoints"][norm]
                for key in ("methods", "sources", "params"):
                    tgt[key] |= entry[key]
                tgt["evidence"].extend(e for e in entry["evidence"] if e not in tgt["evidence"])
            else:
                merged["endpoints"][norm] = entry
        for url, entry in result["hosts"].items():
            merged["hosts"].setdefault(url, entry)
        for name, entry in result["params"].items():
            if name in merged["params"]:
                merged["params"][name]["endpoints"] |= entry["endpoints"]
                if not merged["params"][name].get("evidence") and entry.get("evidence"):
                    merged["params"][name]["evidence"] = entry["evidence"]
            else:
                merged["params"][name] = dict(entry)
        for secret in result["secrets"]:
            key = (secret.get("type"), secret.get("sha256_12"),
                   (secret.get("evidence") or {}).get("file"),
                   (secret.get("evidence") or {}).get("offset"))
            if key in secret_keys:
                continue
            secret_keys.add(key)
            merged["secrets"].append(secret)
        for hint in result["hints"]:
            key = (hint.get("kind"), hint.get("file"), hint.get("offset"))
            if key in hint_keys:
                continue
            hint_keys.add(key)
            merged["hints"].append(hint)
        merged["chunks"] |= result["chunks"]
        merged["graphql"] |= result["graphql"]

    total = 0
    for index, text in enumerate(inline_scripts):
        merge(extract(text, domain, f"inline:{index}"), f"inline:{index}")

    queue = list(dict.fromkeys(script_urls))[:max_scripts]
    fetched = 0
    failed = 0
    budget_cut = False
    for url in queue:
        if session.exhausted or fetched >= max_scripts or total >= max_total_js_bytes:
            # A budget stop is different from a 404: only the former makes the scan too thin
            # to trust a negative (`coverage.truncated`), the latter is just a missing file.
            budget_cut = True
            break
        resp = session.request(url, max_bytes=max_js_bytes,
                               headers={"Accept": "*/*", "Referer": f"https://{domain}/"})
        if resp.error or resp.status >= 400 or not resp.body:
            failed += 1
            scripts.append({"url": url, "status": resp.status, "error": resp.error or "empty",
                            "bytes": len(resp.body)})
            continue
        fetched += 1
        total += len(resp.body)
        digest = sha256_bytes(resp.body)
        raw_text = resp.text()
        minified = raw_text.count("\n") < 3 and len(raw_text) > 5000
        body = pretty_minified(raw_text) if minified else raw_text
        raw_path = os.path.join(out_dir, "raw", "js", f"{digest[:16]}.js")
        with open(raw_path, "wb") as fh:
            fh.write(resp.body)
        entry = {
            "url": url, "status": resp.status, "bytes": len(resp.body), "sha256": digest,
            "minified": minified, "artifact": os.path.relpath(raw_path, out_dir).replace("\\", "/"),
            "lines": body.count("\n") + 1,
        }
        if minified:
            pretty_path = os.path.join(out_dir, "raw", "js", f"{digest[:16]}.pretty.js")
            with open(pretty_path, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(body)
            entry["pretty_artifact"] = os.path.relpath(pretty_path, out_dir).replace("\\", "/")
        sm = RE_SOURCEMAP.search(raw_text)
        if sm:
            map_url = urljoin(url, sm.group(1))
            entry["sourcemap"] = _fetch_sourcemap(session, map_url, out_dir)
        scripts.append(entry)
        merge(extract(body, domain, entry["artifact"]), entry["artifact"])

    endpoints = []
    for norm, entry in merged["endpoints"].items():
        endpoints.append({
            "path": norm, "raw": entry["raw"],
            "methods": sorted(entry["methods"]) or ["GET?"],
            "confidence": entry["confidence"],
            "sources": sorted(entry["sources"]),
            "params": sorted(entry["params"]),
            "evidence": entry["evidence"][:3],
            "in_scope": True,
        })

    result = {
        "scripts": scripts,
        "endpoints": sorted(endpoints, key=lambda e: (e["path"], e["confidence"])),
        "params": [{"name": v["name"], "in": v["in"], "endpoints": sorted(v["endpoints"]),
                    "source": v["source"],
                    # Body fields have no attributable endpoint (see _extract_bodies), so the
                    # reader gets the literal instead of an invented link.
                    **({"evidence": v["evidence"]} if v.get("evidence") else {})}
                   for v in sorted(merged["params"].values(), key=lambda x: x["name"])],
        "secrets": merged["secrets"],
        "hints": merged["hints"],
        "hosts": sorted(merged["hosts"].values(), key=lambda h: h["url"]),
        "chunks": sorted(merged["chunks"]),
        "graphql": sorted(merged["graphql"]),
        "stats": {"fetched": fetched, "failed": failed, "bytes": total,
                  "requested": len(queue), "budget_cut": budget_cut},
    }
    # Redaction is not enough: a snippet that quotes the secret leaks it just as well.
    # Replace every raw value with its masked form across the whole result before it leaves memory.
    scrub_map: dict[str, str] = {}
    for secret in merged["secrets"]:
        raw = secret.pop("_raw", None)
        if raw:
            scrub_map[raw] = secret["masked"]

    def _scrub(obj):
        if isinstance(obj, str):
            for raw, masked in scrub_map.items():
                if raw in obj:
                    obj = obj.replace(raw, masked)
            return obj
        if isinstance(obj, list):
            return [_scrub(item) for item in obj]
        if isinstance(obj, dict):
            return {key: _scrub(value) for key, value in obj.items()}
        return obj

    return _scrub(result)
