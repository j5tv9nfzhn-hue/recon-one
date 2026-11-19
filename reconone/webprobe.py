"""HTTP surface: root fetch, security headers, cookies, TLS, well-known files, tech, CORS."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .config import load_rule
from .http import probe_tls_certificate

SECURITY_HEADERS = [
    ("content-security-policy", "high", "CSP 缺失：无 XSS 缓解，前端注入类假设代价下降"),
    ("strict-transport-security", "medium", "HSTS 缺失：明文降级与 cookie 劫持窗口仍然开放"),
    ("x-content-type-options", "low", "缺少 nosniff：MIME 嗅探类绕过可用"),
    ("x-frame-options", "medium", "无框架限制：点击劫持面未被关闭"),
    ("referrer-policy", "low", "无 Referrer 策略：URL 中的 token/参数可能外泄"),
    ("permissions-policy", "low", "无 Permissions-Policy：浏览器能力未收紧"),
    ("cross-origin-opener-policy", "low", "无 COOP：跨窗口隔离缺失"),
]

WELL_KNOWN = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt",
    "/.well-known/change-password", "/crossdomain.xml", "/favicon.ico",
]


def _parse_set_cookie(values: list[str]) -> list[dict]:
    cookies = []
    for raw in values:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or not parts[0]:
            continue
        name, _, value = parts[0].partition("=")
        flags = {p.split("=")[0].strip().lower(): p.split("=", 1)[1].strip() if "=" in p else True
                 for p in parts[1:]}
        cookies.append({
            "name": name.strip(),
            "flags": sorted(flags.keys()),
            "secure": "secure" in flags,
            "httponly": "httponly" in flags,
            "samesite": str(flags.get("samesite", "")).lower(),
        })
    return cookies


def fingerprint(html: str, headers: dict, cookies: list[dict], script_urls: list[str]) -> list[dict]:
    techs = load_rule("technologies", {"technologies": []}).get("technologies", [])
    blob = " ".join(script_urls)
    out = []
    for tech in techs:
        hits = []
        for header, pattern in (tech.get("headers") or {}).items():
            if re.search(pattern, headers.get(header, ""), re.I):
                hits.append(f"header:{header}")
        for cookie_name in tech.get("cookies") or []:
            if any(cookie_name.lower() == c["name"].lower() for c in cookies):
                hits.append(f"cookie:{cookie_name}")
        for pattern in tech.get("body") or []:
            if re.search(pattern, html, re.I):
                hits.append("body")
                break
        for pattern in tech.get("scripts") or []:
            if re.search(pattern, blob, re.I):
                hits.append("script-src")
                break
        if hits:
            out.append({"name": tech["name"], "evidence": sorted(set(hits)),
                        "category": tech.get("category", "")})
    return out


# Referrer-Policy values that actually restrict leakage. Anything else is present-but-weak,
# which is a different claim from absent and must not be reported as a pass.
# NOTE: this set is literal on purpose. An earlier version ended with
# `"no-referrer-when-downgrade".upper() and "origin-when-cross-origin"`, which evaluates to
# the *second* string: `no-referrer-when-downgrade` was silently unsafe while the weak
# `origin-when-cross-origin` counted as a pass. Never build a set from expressions.
SAFE_REFERRER = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    # Still leaks to HTTPS destinations, but never on downgrade; accepted as OK by
    # Mozilla Observatory and kept for backward compatibility with the original intent.
    "no-referrer-when-downgrade",
}
SAFE_COOP = {"same-origin", "same-origin-allow-popups", "same-origin-plus-coep"}
SAFE_XFO = {"deny", "sameorigin"}
HSTS_MIN_MAX_AGE = 15768000          # six months, per Mozilla Observatory


def _directive_values(csp: str, directive: str) -> list[str]:
    """Return the source list for one CSP directive, following default-src fallback."""
    found = {}
    for part in csp.split(";"):
        tokens = part.strip().split()
        if tokens:
            found[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    if directive in found:
        return found[directive]
    return found.get("default-src", [])


def evaluate_header(name: str, value: str) -> tuple:
    """Judge a security header by its *value*. Returns (verdict, note).

    verdict is one of ok / weak / invalid. Absence is handled by the caller. Every branch
    here reads only what the header literally says — no inference about the site's intent,
    which is what turns header graders into false-positive factories.
    """
    v = (value or "").strip()
    low = v.lower()
    if not v:
        return "invalid", "头存在但值为空"

    if name == "content-security-policy":
        if "'unsafe-inline'" in low:
            where = "script-src" if "'unsafe-inline'" in " ".join(_directive_values(v, "script-src")) else "策略中"
            return "weak", f"含 'unsafe-inline'（{where}），内联脚本未被禁止"
        if "'unsafe-eval'" in low:
            return "weak", "含 'unsafe-eval'，允许动态求值"
        if "default-src *" in low or "script-src *" in low:
            return "weak", "含通配源 *，等同于不限制"
        if _directive_values(v, "script-src") == ["'none'"] or "default-src 'none'" in low:
            return "ok", "default-src 'none' 且无 unsafe"
        return "ok", "已配置且未检出已知弱指令"

    if name == "strict-transport-security":
        m = re.search(r"max-age\s*=\s*(\d+)", low)
        if not m:
            return "invalid", "缺少 max-age 指令，浏览器将忽略"
        age = int(m.group(1))
        if age < HSTS_MIN_MAX_AGE:
            return "weak", f"max-age={age} 小于六个月（{HSTS_MIN_MAX_AGE}），覆盖窗口不足"
        return "ok", f"max-age={age}" + ("，含 includeSubDomains" if "includesubdomains" in low else "")

    if name == "x-frame-options":
        if low in SAFE_XFO:
            return "ok", v
        return "weak", f"值为 {v}，非 DENY/SAMEORIGIN，点击劫持面未关闭"

    if name == "x-content-type-options":
        return ("ok", "nosniff") if low == "nosniff" else ("weak", f"值为 {v}，应为 nosniff")

    if name == "referrer-policy":
        if low in SAFE_REFERRER:
            return "ok", v
        return "weak", f"值为 {v}，跨源仍可能泄露完整 URL"

    if name == "cross-origin-opener-policy":
        if low in SAFE_COOP:
            return "ok", v
        return "weak", f"值为 {v}，未隔离浏览上下文"

    return "ok", v[:200]


def analyze_headers(headers: dict) -> dict:
    """Per-header verdicts with the actual value retained for audit.

    The previous version used `if headers.get(name)`, which attributes a pass to any
    non-empty value: `X-Frame-Options: ALLOWALL` and `CSP: default-src *` both counted as
    "configured". Every claim now carries the observed value so a reader can check it.
    """
    results, present, missing = [], {}, []
    for name, level, reason in SECURITY_HEADERS:
        value = headers.get(name, "")
        if not value:
            missing.append({"header": name, "severity": level, "reason": reason})
            results.append({"header": name, "verdict": "absent", "value": "",
                            "note": reason, "severity": level})
            continue
        verdict, note = evaluate_header(name, value)
        present[name] = value[:300]
        results.append({"header": name, "verdict": verdict, "value": value[:300],
                        "note": note, "severity": level})
    ok = sum(1 for r in results if r["verdict"] == "ok")
    weak = sum(1 for r in results if r["verdict"] == "weak")
    absent = sum(1 for r in results if r["verdict"] == "absent")
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    return {"present": present, "missing": missing, "results": results,
            "server": server, "powered_by": powered,
            "counts": {"ok": ok, "weak": weak, "absent": absent},
            # Ratio of strict passes. Present-but-weak deliberately does not count.
            "score": round(ok / len(SECURITY_HEADERS), 3)}


def probe_web(session, domain: str, scheme: str = "https") -> dict:
    root = session.request(f"{scheme}://{domain}/")
    result: dict = {"root_url": f"{scheme}://{domain}/", "reachable": False}
    if root.error:
        result["error"] = root.error
        if scheme == "https":
            fallback = session.request(f"http://{domain}/")
            if not fallback.error:
                result.update({"root_url": f"http://{domain}/", "reachable": True,
                               "https_available": False})
                root = fallback
                scheme = "http"
            else:
                return result
        else:
            return result
    else:
        result["reachable"] = True
        result["https_available"] = scheme == "https"

    html = root.text() if "html" in root.header("content-type", "").lower() or not root.header("content-type") else ""
    # Every Set-Cookie header, in wire order: the dict view keeps only the last one.
    cookie_values = root.header_values("set-cookie")
    cookies = _parse_set_cookie(cookie_values) if cookie_values else []
    script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)
    result.update({
        "status": root.status,
        "final_url": root.url,
        "redirect_chain": root.redirect_chain,
        "headers": root.headers,
        "security": analyze_headers(root.headers),
        "cookies": cookies,
        "title": (re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I).group(1).strip()[:200]
                  if re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I) else ""),
        "tech": fingerprint(html, root.headers, cookies, script_urls),
        "well_known": {},
    })

    if result.get("https_available"):
        result["tls"] = probe_tls_certificate(domain.split(":")[0], verify=session.verify_tls,
                                              egress=getattr(session, "egress", None))

    for path in WELL_KNOWN:
        resp = session.request(f"{scheme}://{domain}{path}", max_bytes=256_000)
        if resp.error or resp.status >= 400:
            continue
        entry = {"status": resp.status, "bytes": len(resp.body)}
        if path == "/robots.txt":
            entry["disallow"] = re.findall(r"(?im)^\s*Disallow:\s*(\S*)", resp.text())[:50]
        elif path == "/sitemap.xml":
            entry["locations"] = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", resp.text())[:100]
        elif "security.txt" in path:
            entry["contacts"] = re.findall(r"(?im)^Contact:\s*(\S+)", resp.text())[:10]
        result["well_known"][path] = entry
    return result


def probe_cors(session, origin_url: str, sample_paths: list[str] | None = None) -> dict:
    """Reflect a foreign Origin and record the policy. One request per candidate path."""
    evil = "https://recon-one-cors-check.invalid"
    targets = [origin_url] + [origin_url.rstrip("/") + p for p in (sample_paths or [])]
    findings = []
    for url in targets[:6]:
        resp = session.request(url, headers={"Origin": evil}, max_bytes=64_000)
        if resp.error:
            continue
        acao = resp.header("access-control-allow-origin")
        acac = resp.header("access-control-allow-credentials").lower()
        if not acao:
            continue
        reflected = acao.strip() == evil
        wildcard = acao.strip() == "*"
        findings.append({
            "url": url,
            "allow_origin": acao,
            "allow_credentials": acac == "true",
            "reflected": reflected,
            "wildcard": wildcard,
            "risk": "high" if (reflected and acac == "true") else
                    ("medium" if wildcard and acac == "true" else "info"),
        })
    return {"probes": findings}
