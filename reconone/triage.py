"""Target profile: is this worth attacking, how hard is it, how good are the odds?

Everything here is a rule table over values the run already observed. There is no model, no
LLM, no learning: given the same report the same numbers come out, and every number names
the checks (and their evidence) that produced it.

Three questions, three answers, never collapsed into one:

* ``worth``    — is there anything here to test? (business/attack surface, disclosure path)
* ``hardness`` — how much work stands between an outsider and that surface?
* ``success``  — a *banded index* derived from the two above, explicitly not a probability
                 of finding a vulnerability. It is withheld when coverage is too low.

Every check carries ``mode``: ``passive`` (data came from a third-party index, no packet
reached the target) or ``active`` (the scanner talked to the target itself). That split is
what lets an operator run the whole thing without touching the target.
"""
from __future__ import annotations

from .util import is_ip_literal

PASS, WARN, FAIL, UNKNOWN = "pass", "warn", "fail", "unknown"
PASSIVE, ACTIVE = "passive", "active"

MIN_COVERAGE = 60.0

# A perimeter signal is "strong" when the target advertises one of these.
WAF_HEADERS = ("cf-ray", "cf-cache-status", "x-akamai", "x-sucuri", "x-cdn",
               "x-azure-ref", "x-amz-cf-id", "server-timing", "x-fastly-request-id")
WAF_SERVER = ("cloudflare", "akamai", "imperva", "incapsula", "sucuri", "fastly",
              "cloudfront", "azure front door", "f5", "barracuda", "fortiweb")
LEGACY_TECH = ("php", "jquery", "wordpress", "drupal", "joomla", "asp.net", "tomcat",
               "iis", "apache", "nginx", "openssl")
SENSITIVE_PATH_WORDS = ("admin", "internal", "debug", "actuator", "manage", "backup",
                        "staging", "test", "console", "upload")


def _check(cid: str, axis: str, weight: float, status: str, title: str, detail: str,
           mode: str = ACTIVE, evidence=None, source: str = "") -> dict:
    return {
        "id": cid, "axis": axis, "weight": float(weight), "status": status,
        "title": title, "detail": detail, "mode": mode, "evidence": evidence or [],
        "source": source, "evaluated": status in (PASS, WARN, FAIL),
        "earned": float(weight) if status == PASS else (float(weight) * .5 if status == WARN else 0.0),
    }


def _axis(checks: list[dict], axis: str) -> dict:
    rel = [c for c in checks if c["axis"] == axis]
    ev = [c for c in rel if c["evaluated"]]
    total_w = sum(c["weight"] for c in rel)
    eval_w = sum(c["weight"] for c in ev)
    earned = sum(c["earned"] for c in ev)
    pct = round(earned / eval_w * 100.0, 1) if eval_w else None
    return {"score": pct, "earned_weight": round(earned, 1), "evaluated_weight": round(eval_w, 1),
            "total_weight": round(total_w, 1),
            "coverage_pct": round(eval_w / total_w * 100.0, 1) if total_w else 0.0,
            "checks_total": len(rel), "checks_evaluated": len(ev),
            "checks_unknown": len(rel) - len(ev)}


# --------------------------------------------------------------------------- helpers
def _intel_status(intel: dict, key: str) -> tuple[dict, bool]:
    node = (intel or {}).get(key) or {}
    return node, node.get("status") == "ok"


def _hygiene(report: dict) -> float | None:
    axes = ((report.get("score") or {}).get("axes") or {})
    value = (axes.get("hygiene") or {}).get("score")
    return float(value) if isinstance(value, (int, float)) else None


# --------------------------------------------------------------------------- worth
def _worth_checks(report: dict, intel: dict) -> list[dict]:
    out: list[dict] = []
    counts = ((report.get("coverage") or {}).get("counts") or {})
    endpoints = report.get("endpoints") or []

    write = int(counts.get("endpoints_write") or 0)
    out.append(_check(
        "worth.write_endpoints", "worth", 18,
        PASS if write >= 10 else (WARN if write >= 3 else FAIL),
        "写方法端点", f"{write} 个 POST/PUT/PATCH/DELETE 端点",
        ACTIVE, [{"kind": "count", "value": write}], "observed in this run"))

    specs = report.get("specs") or []
    out.append(_check(
        "worth.api_spec", "worth", 12, PASS if specs else FAIL,
        "公开 API 规范", f"{len(specs)} 份 OpenAPI/Swagger",
        ACTIVE, [{"kind": "spec", "count": len(specs)}], "observed in this run"))

    gql = report.get("graphql") or []
    out.append(_check(
        "worth.graphql", "worth", 10, PASS if gql else FAIL,
        "GraphQL introspection", f"{len(gql)} 个可 introspection 的端点",
        ACTIVE, [{"kind": "graphql", "count": len(gql)}], "observed in this run"))

    named = [p for p in report.get("parameters") or [] if p.get("name")]
    out.append(_check(
        "worth.parameters", "worth", 10,
        PASS if len(named) >= 8 else (WARN if named else FAIL),
        "可变异参数", f"{len(named)} 个具名参数（查询串/请求体/规范）",
        ACTIVE, [{"kind": "param", "count": len(named)}], "observed in this run"))

    api_like = [e for e in endpoints
                # Discovered prefixes are observations but still guesses about *intent*;
                # they must not inflate the value score the way JS/spec endpoints do.
                if not e.get("discovered") and (
                    "/api/" in (e.get("path") or "").lower()
                    or (e.get("path") or "").startswith(("/v1", "/v2", "/v3", "/rest", "/graphql")))]
    out.append(_check(
        "worth.api_surface", "worth", 10,
        PASS if len(api_like) >= 10 else (WARN if api_like else FAIL),
        "API 面规模", f"{len(api_like)} 个端点落在 API/REST/GraphQL 路径下",
        ACTIVE, [{"kind": "endpoint", "count": len(api_like)}], "observed in this run"))

    ct, ct_ok = _intel_status(intel, "ct")
    subs = ct.get("subdomains") or []
    out.append(_check(
        "worth.subdomains", "worth", 14,
        UNKNOWN if not ct_ok else (PASS if len(subs) >= 8 else (WARN if len(subs) >= 2 else FAIL)),
        "子域规模（CT 日志）",
        (f"{len(subs)} 个子域，时间跨度 {ct.get('first_cert', '?')} → {ct.get('last_cert', '?')}"
         if ct_ok else f"未取得：{ct.get('reason') or ct.get('status')}"),
        PASSIVE, [{"kind": "subdomains", "count": len(subs), "samples": subs[:8]}],
        f"certificate transparency ({ct.get('source', '?')})"))

    arch, arch_ok = _intel_status(intel, "archive")
    sensitive = arch.get("sensitive_paths") or []
    out.append(_check(
        "worth.archive_sensitive", "worth", 10,
        UNKNOWN if not arch_ok else
        (PASS if len(sensitive) >= 5 else (WARN if sensitive else FAIL)),
        "历史存档中的敏感路径",
        (f"{arch.get('snapshots', 0)} 条快照，{len(sensitive)} 个敏感路径"
         if arch_ok else f"未取得：{arch.get('reason') or arch.get('status')}"),
        PASSIVE, [{"kind": "archive", "snapshots": arch.get("snapshots", 0),
                   "paths": sensitive[:8]}],
        f"wayback cdx ({arch.get('source', '?')})"))

    well_known = ((report.get("assets") or {}).get("well_known") or {})
    st = well_known.get("/.well-known/security.txt") or well_known.get("/security.txt") or {}
    out.append(_check(
        "worth.disclosure", "worth", 8, PASS if st.get("status") == 200 else FAIL,
        "漏洞披露渠道", "存在 security.txt" if st else "未发现 security.txt",
        ACTIVE, [{"kind": "well-known", "status": st.get("status", 0)}], "observed in this run"))

    forms = (report.get("assets") or {}).get("forms") or []
    auth_forms = [f for f in forms if "password" in str(f.get("inputs", "")).lower()]
    out.append(_check(
        "worth.auth_surface", "worth", 8, PASS if auth_forms else FAIL,
        "认证入口", f"{len(auth_forms)} 个含密码字段的表单",
        ACTIVE, [{"kind": "form", "count": len(auth_forms)}], "observed in this run"))
    # ---- what the target itself answered (the light active side) ----------------------
    # Only endpoints this run actually reached are counted here: a path from a bundle that
    # was never returned is a claim, a path the server answered is evidence. The check is
    # `unknown` when neither crawl nor JS ran, so a skipped stage cannot read as "nothing".
    probes = ((report.get("coverage") or {}).get("probes") or {})
    crawl_state = str(probes.get("crawl", ""))
    js_state = str(probes.get("js", ""))
    observed = crawl_state == "ok" or js_state == "ok"
    live = [e for e in endpoints
            if any(s in ("js-call", "js-config", "openapi-spec", "html-form", "html-link")
                   for s in (e.get("sources") or []))]
    out.append(_check(
        "worth.live_surface", "worth", 8,
        UNKNOWN if not observed else
        (PASS if len(live) >= 8 else (WARN if len(live) >= 2 else FAIL)),
        "实测可达端点",
        (f"{len(live)} 个端点由本次主动抓取/爬取直接得到（crawl={crawl_state}，js={js_state}）"
         if observed else f"未执行主动抓取（crawl={crawl_state}，js={js_state}）"),
        ACTIVE, [{"kind": "endpoint", "count": len(live),
                  "samples": [e.get("path") for e in live[:6]]}],
        "observed in this run (crawl + js + crawl-derived endpoints)"))

    return out


# --------------------------------------------------------------------------- hardness
def _hardness_checks(report: dict, intel: dict) -> list[dict]:
    out: list[dict] = []
    http = ((report.get("assets") or {}).get("http") or {})
    headers = {str(k).lower(): str(v) for k, v in (http.get("headers") or {}).items()}

    waf_hits = [h for h in WAF_HEADERS if h in headers]
    server = headers.get("server", "").lower()
    waf_hits += [name for name in WAF_SERVER if name in server]
    out.append(_check(
        "hard.waf", "hardness", 16,
        PASS if waf_hits else FAIL,
        "WAF / CDN 遮挡", ("命中：" + ", ".join(sorted(set(waf_hits))[:5])) if waf_hits
        else "未发现常见 WAF/CDN 响应头",
        ACTIVE, [{"kind": "header", "hits": sorted(set(waf_hits))}], "observed in this run"))

    # Active-side hardness: a target that answers with 403/429 is harder than one that
    # answers everything. This is a ratio over requests we already sent, so it costs nothing
    # extra and cannot be mistaken for a load test.
    stats = ((report.get("meta") or {}).get("probe_stats") or {})
    sent = int(stats.get("requests") or 0)
    blocked = int(stats.get("blocked") or 0)
    pct = float(stats.get("blocked_pct") or 0.0)
    out.append(_check(
        "hard.active_blocking", "hardness", 6,
        UNKNOWN if sent < 5 else (PASS if pct >= 20 else (WARN if blocked else FAIL)),
        "主动请求被拦截比例",
        (f"{blocked}/{sent} 次请求得到 401/403/405/406/429/503（{pct}%）；"
         f"429 限流 {int(stats.get('throttled') or 0)} 次" if sent >= 5
         else f"仅 {sent} 次请求，不足以判断拦截强度"),
        ACTIVE, [{"kind": "probe", "requests": sent, "blocked": blocked,
                  "throttled": int(stats.get("throttled") or 0), "pct": pct}],
        "session.log status codes"))

    hyg = _hygiene(report)
    out.append(_check(
        "hard.hygiene", "hardness", 14,
        UNKNOWN if hyg is None else (PASS if hyg >= 70 else (WARN if hyg >= 50 else FAIL)),
        "外围加固程度",
        "无评分：报告缺少 hygiene 轴" if hyg is None else f"hygiene {hyg:.0f}/100",
        ACTIVE, [{"kind": "score", "hygiene": hyg}], "score.axes.hygiene"))

    tls = http.get("tls") or {}
    version = str(tls.get("tls_version") or "").upper()
    out.append(_check(
        "hard.tls", "hardness", 10,
        UNKNOWN if not version else (PASS if version in ("TLSV1.3", "TLSV1.2") else FAIL),
        "TLS 版本", version or "未取得证书信息",
        ACTIVE, [{"kind": "tls", "version": version}], "observed in this run"))

    exposed = [h for h in ("server", "x-powered-by", "x-aspnet-version") if
               any(ch.isdigit() for ch in headers.get(h, ""))]
    out.append(_check(
        "hard.version_hidden", "hardness", 10,
        FAIL if exposed else PASS,
        "版本号暴露", ("暴露：" + ", ".join(exposed)) if exposed else "响应头未带版本号",
        ACTIVE, [{"kind": "header", "values": {h: headers.get(h, "") for h in exposed}}],
        "observed in this run"))

    legacy = [t.get("name", "") for t in ((report.get("assets") or {}).get("technology") or [])
              if any(word in str(t.get("name", "")).lower() for word in LEGACY_TECH)]
    out.append(_check(
        "hard.stack_age", "hardness", 12,
        UNKNOWN if not (report.get("assets") or {}).get("technology") else
        (FAIL if legacy else PASS),
        "技术栈年龄", ("命中传统栈：" + ", ".join(legacy[:5])) if legacy else "未见传统栈指纹",
        ACTIVE, [{"kind": "tech", "hits": legacy}], "observed in this run"))

    ct, ct_ok = _intel_status(intel, "ct")
    subs = ct.get("subdomains") or []
    out.append(_check(
        "hard.subdomain_sprawl", "hardness", 10,
        UNKNOWN if not ct_ok else (FAIL if len(subs) >= 15 else (WARN if len(subs) >= 5 else PASS)),
        "子域暴露面", f"{len(subs)} 个子域（面越大越难一次摸清）" if ct_ok else "未取得子域",
        PASSIVE, [{"kind": "subdomains", "count": len(subs)}],
        f"certificate transparency ({ct.get('source', '?')})"))

    # Honest unknowns: these cannot be observed statically, so they are not scored.
    out.append(_check(
        "hard.rate_limit", "hardness", 8, UNKNOWN,
        "限流 / 账号锁定", "静态探测无法判定，需要主动发包并观察 429/423", ACTIVE, [],
        "not observable without active testing"))
    out.append(_check(
        "hard.mfa", "hardness", 10, UNKNOWN,
        "多因素认证", "未持有账号，无法判定登录是否强制 MFA", ACTIVE, [],
        "requires an authenticated session"))
    return out


# --------------------------------------------------------------------------- success
def _band(index: float | None) -> dict:
    if index is None:
        return {"band": "unknown", "label": "证据不足，不给结论", "range": None}
    if index >= 70:
        return {"band": "high", "label": "机会窗口大（外围阻力低、可测面明确）", "range": [70, 85]}
    if index >= 50:
        return {"band": "elevated", "label": "机会窗口较大", "range": [50, 70]}
    if index >= 30:
        return {"band": "moderate", "label": "机会窗口一般", "range": [30, 50]}
    return {"band": "low", "label": "机会窗口小（阻挡强或可测面窄）", "range": [10, 30]}


ASSUMPTIONS = [
    "worth 与 hardness 都只覆盖未认证时可观测的外围信号，不覆盖业务逻辑与权限模型。",
    "success 是由 worth 与 hardness 线性合成的**机会指数**，不是漏洞存在概率，也不预测单次尝试的成败。",
    "限流、账号锁定、MFA 无法通过静态探测判定，因此不参与打分，并在 checks 中显式标为 unknown。",
    "CVE 查询只回答“这些版本文本是否被分配过 CVE”，命中不代表目标可利用，未命中不代表安全。",
    "主动探测只复用轻量预算：首页、同源爬取、脚本下载、spec/GraphQL 探测、CORS 反射，"
    "外加一次归档索引查询；不做目录爆破、参数模糊测试或载荷注入 —— 那属于渗透执行，"
    "不在本工具范围内，因此主动项只提高评分准确度，不改变探测深度。",
]



def build(report: dict, intel: dict | None = None) -> dict:
    """Assemble the profile block. Pure function: same input → same output."""
    intel = intel or {}
    checks = _worth_checks(report, intel) + _hardness_checks(report, intel)
    worth = _axis(checks, "worth")
    hardness = _axis(checks, "hardness")
    coverage = min(worth["coverage_pct"], hardness["coverage_pct"])

    index = None
    if coverage >= MIN_COVERAGE and worth["score"] is not None and hardness["score"] is not None:
        ease = 100.0 - hardness["score"]
        index = round(max(5.0, min(95.0, 0.55 * worth["score"] + 0.45 * ease)), 0)
    band = _band(index)

    assets = report.get("assets") or {}
    ct, ct_ok = _intel_status(intel, "ct")
    arch, arch_ok = _intel_status(intel, "archive")
    geo, _geo_ok = _intel_status(intel, "geo")
    cves, _cve_ok = _intel_status(intel, "cve")
    dns = (assets.get("dns") or {})
    records = dns.get("records") or {}
    site_type = intel.get("site_type") or {}
    paths = [e.get("path") or "" for e in (report.get("endpoints") or [])]

    # Weight accounting is part of the answer, not decoration: a score that rests mostly on
    # third-party indexes deserves a different reading from one that rests on requests the
    # target actually answered. Both numbers are emitted so a reader can check the mix.
    active_all = [c for c in checks if c["mode"] == ACTIVE]
    passive_all = [c for c in checks if c["mode"] == PASSIVE]
    active_w = round(sum(c["weight"] for c in active_all), 1)
    passive_w = round(sum(c["weight"] for c in passive_all), 1)
    total_w = active_w + passive_w
    active_eval_w = round(sum(c["weight"] for c in active_all if c["evaluated"]), 1)
    eval_w = round(sum(c["weight"] for c in checks if c["evaluated"]), 1)

    return {
        "version": "1",
        "generated_by": "reconone.triage (deterministic rule table, no AI)",
        "mode_split": {
            "passive": [c["id"] for c in passive_all],
            "active": [c["id"] for c in active_all],
        },
        "weights": {
            "active": active_w, "passive": passive_w, "total": round(total_w, 1),
            "active_share_pct": round(active_w / total_w * 100.0, 1) if total_w else 0.0,
            "evaluated_active": active_eval_w, "evaluated_total": eval_w,
            # Share of the *scored* weight that came from talking to the target. This is the
            # number to look at before trusting an index: it says how much was measured.
            "observed_share_pct": round(active_eval_w / eval_w * 100.0, 1) if eval_w else 0.0,
        },
        "axes": {"worth": worth, "hardness": hardness},
        "success": {"index": index, "band": band["band"], "label": band["label"],
                    "range": band["range"], "is_probability": False},
        "dimensions": {
            "site_type": site_type or {"primary": "unknown", "status": "unavailable"},
            "geo": {"status": geo.get("status", "unavailable"),
                    "country": geo.get("country", ""), "city": geo.get("city", ""),
                    "isp": geo.get("isp", ""), "asn": geo.get("asn", ""),
                    "source": geo.get("source", ""), "reason": geo.get("reason", "")},
            "subdomains": {"status": ct.get("status", "unavailable"),
                           "count": len(ct.get("subdomains") or []),
                           "samples": (ct.get("subdomains") or [])[:20],
                           "source": ct.get("source", ""), "reason": ct.get("reason", "")},
            "history": {"status": arch.get("status", "unavailable"),
                        "snapshots": arch.get("snapshots", 0),
                        "first": arch.get("first", ""), "last": arch.get("last", ""),
                        "sensitive_paths": (arch.get("sensitive_paths") or [])[:20],
                        "source": arch.get("source", ""), "reason": arch.get("reason", "")},
            "cve_hints": {"status": cves.get("status", "unavailable"),
                          "hits": cves.get("hits") or [], "checked": cves.get("checked") or [],
                          "source": cves.get("source", ""), "reason": cves.get("reason", "")},
            "dns": {"records": {k: len(v or []) for k, v in records.items()},
                    "spf": len(dns.get("spf") or []), "dmarc": len(dns.get("dmarc") or []),
                    "resolvers": (dns.get("resolvers") or [])[:3]},
            "infra": {"server": headers_value(assets, "server"),
                      "powered_by": headers_value(assets, "x-powered-by"),
                      "tls_version": ((assets.get("http") or {}).get("tls") or {}).get("tls_version", ""),
                      "waf": sorted({h for h in WAF_HEADERS if h in headers_lower(assets)}
                                    | {n for n in WAF_SERVER
                                       if n in headers_value(assets, "server").lower()})},
            "surface": {"endpoints": len(paths),
                        "sensitive_paths": [p for p in paths
                                            if any(w in p.lower() for w in SENSITIVE_PATH_WORDS)][:15],
                        "historic_paths": (arch.get("paths") or [])[:15] if arch_ok else []},
        },
        "checks": checks,
        "coverage": {"worth_pct": worth["coverage_pct"], "hardness_pct": hardness["coverage_pct"],
                     "combined_pct": coverage, "min_required": MIN_COVERAGE,
                     "unknown": [c["id"] for c in checks if c["status"] == UNKNOWN]},
        "assumptions": ASSUMPTIONS,
        "disclaimer": ("这是可解释的机会评估，不是漏洞预测。分数只由这里列出的检查项产生，"
                       "每一项都能回溯到观测值；未采集项标 unknown，既不计分也不视为通过。"),
    }


def headers_value(assets: dict, name: str) -> str:
    headers = ((assets.get("http") or {}).get("headers") or {})
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value)[:120]
    return ""


def headers_lower(assets: dict) -> set[str]:
    return {str(k).lower() for k in ((assets.get("http") or {}).get("headers") or {})}


#: The bet threshold this build implements. Named so a future threshold cannot silently
#: change what an old report meant.
BET_THRESHOLD = "A"

BET_DEFINITION = ("A：至少 1 个**匿名可访问且带参数**的端点，或 1 个**存活子域暴露非公开面**。"
                  "“匿名可访问”必须由观测证明：单身份只有 2xx/3xx 算，双身份只有匿名侧 2xx "
                  "且内容与认证态不同算；401/403/405/429 只证明端点存在。"
                  "判据一是唯一能否决的判据：它明确未命中且扫描够厚 → not_worth；"
                  "判据二只能把判决升级为 worth，缺它不会把 not_worth 变成 withheld。")


def _param_names(endpoint: dict) -> list[str]:
    names = []
    for param in endpoint.get("params") or []:
        name = str(param.get("name") if isinstance(param, dict) else param or "").strip()
        if name:
            names.append(name)
    return names


def _is_ip(text: str) -> bool:
    """`example.com:8443` is a name with a port, not an IP literal."""
    return is_ip_literal(text)


def bet(report: dict) -> dict:
    """Turn evidence into the one thing a decision needs: worth it or not.

    Threshold A, deliberately narrow: a *parameterised* endpoint that answers **without**
    credentials is the cheapest signal that there is real surface behind the login wall and that
    it accepts input. A live subdomain exposing a non-public face counts as well.

    **Criterion 2 may only promote, never veto.** An earlier version reported the subdomain half
    as `unknown` whenever it had not been probed — which made `not_worth` unreachable: criterion 1
    could be a decisive miss and the verdict still came out `withheld` forever. A judgement that
    can only ever say "worth" (or "can't tell") is not a judgement. So: a decisive miss on
    criterion 1, backed by adequate coverage, is `not_worth`; the unprobed subdomain half is
    recorded in `unknowns` as something that could *upgrade* the verdict later.

    `withheld` therefore means one specific thing: we could not judge criterion 1 (verification
    off, parameterised endpoints unverified) or the scan was too thin to trust a negative.
    """
    report = report or {}
    meta = report.get("meta") or {}
    target = report.get("target") or {}
    coverage = report.get("coverage") or {}
    ver = report.get("verification") or {}
    summary = ver.get("summary") or {}
    endpoints = report.get("endpoints") or []
    injected = bool((meta.get("session") or {}).get("enabled"))
    dual = str(summary.get("identity_model") or "single") == "dual"
    verify_on = bool(ver.get("enabled", False))

    with_params = [ep for ep in endpoints if _param_names(ep)]
    usable_p = [ep for ep in with_params if ep.get("verified") == "usable"]
    skipped_p = [ep for ep in with_params if ep.get("verified") == "skipped"]

    # `authz_open` is only ever stamped when the answer is known: single-identity runs derive
    # it from the observed status (2xx/3xx = open, 401/403/405/429 = not open), dual-identity
    # runs derive it from the authz label (`anonymous_open` only). "usable" alone means the
    # path exists, not that it is reachable without credentials — conflating the two was how
    # a 401-protected endpoint became a `worth` verdict.
    opened, not_open, undecided = [], [], []
    for endpoint in usable_p:
        flag = endpoint.get("authz_open")
        if flag is True:
            opened.append(endpoint)
        elif flag is False:
            not_open.append(endpoint)
        else:
            undecided.append(endpoint)

    if opened:
        first, detail = "hit", f"{len(opened)} 个带参数端点无需凭据即可访问"
    elif undecided:
        first, detail = "unknown", f"{len(undecided)} 个带参数端点缺少匿名访问判定"
    elif not verify_on:
        first, detail = "unknown", "验证未启用，无法判定匿名可访问"
    elif skipped_p:
        # A skipped parameterised endpoint is still a possible hit. A negative verdict is
        # only allowed after every parameterised endpoint has an answer, so this must be
        # checked *before* the decisive-miss branch.
        first, detail = "unknown", f"{len(skipped_p)} 个带参数端点未验证（预算/作用域/排除）"
    elif usable_p:
        first, detail = ("miss", f"{len(not_open)} 个可用的带参数端点均未证明匿名可访问"
                                  "（401/403/405/429 或双身份内容相同）")
    elif with_params:
        first, detail = "miss", f"{len(with_params)} 个带参数端点全部不可用（404/5xx/连不上）"
    else:
        first, detail = "miss", "没有带参数的端点"

    subs = (report.get("assets") or {}).get("subdomains") or []
    probed_subs = [sub for sub in subs if sub.get("probed")]
    ct = ((report.get("intel") or {}).get("ct")) or {}
    ct_status = str(ct.get("status") or "")
    # Observation outranks the structural default: if we actually probed hosts, that is the
    # answer even when the target itself is an IP (a name can point at anything).
    if probed_subs:
        exposed = sum(1 for sub in probed_subs if sub.get("non_public"))
        second = "hit" if exposed else "miss"
        # `probed` means "the host answered", not "the host is live": a 404 is still an
        # answer. Say what was probed, and separately how many exposed a non-public face.
        second_detail = (f"{len(probed_subs)} 个已探子域中 {exposed} 个暴露非公开面")
    elif _is_ip(target.get("domain")):
        second, second_detail = "miss", "IP 目标：没有子域维度"
    elif subs:
        second = "unknown"
        second_detail = f"{len(subs)} 个 CT 子域尚未探测（probed:false）"
    elif ct_status == "ok":
        second, second_detail = "miss", "CT 已查且未发现子域"
    else:
        second = "unknown"
        second_detail = f"子域面未评估（CT 状态：{ct_status or 'n/a'}）"

    truncated = bool(coverage.get("truncated"))
    probed = int(summary.get("probed") or 0)
    adequate = verify_on and (probed > 0 or not endpoints) and not truncated

    if first == "hit" or second == "hit":
        verdict = "worth"
    elif first == "unknown" or not adequate:
        verdict = "withheld"
    else:
        verdict = "not_worth"

    if verdict == "worth":
        confidence = "high" if len(opened) >= 2 else "medium"
    elif verdict == "withheld":
        confidence = "low"
    else:
        confidence = "medium" if adequate else "low"

    unknowns = []
    if undecided:
        unknowns.append(f"{len(undecided)} 个带参数端点缺匿名访问判定")
    if skipped_p:
        unknowns.append(f"{len(skipped_p)} 个带参数端点未验证")
    if second == "unknown":
        unknowns.append("子域面未评估（可作为改判为 worth 的证据）")
    if truncated:
        unknowns.append("扫描被截断（页面/脚本/字节预算）")
    if verify_on and not probed and endpoints:
        unknowns.append("验证没有实际探测任何端点")

    evidence = [{"path": ep.get("path"), "params": _param_names(ep),
                 "anon_status": (ep.get("authz") or {}).get("anon_status"),
                 "why": ("匿名即可访问（双身份对比）" if dual else "本次扫描本身即匿名")}
                for ep in opened[:10]]
    writes = [ep for ep in opened
              if any(str(m).upper() in ("POST", "PUT", "PATCH", "DELETE")
                     for m in (ep.get("methods") or []))]

    return {
        "threshold": BET_THRESHOLD,
        "definition": BET_DEFINITION,
        "verdict": verdict,
        "confidence": confidence,
        "identity": "dual" if dual else ("injected-unverified" if injected else "anonymous"),
        "criteria": [
            {"rule": "anonymous_parameterized", "status": first, "detail": detail,
             "endpoints": [ep.get("path") for ep in opened[:10]]},
            {"rule": "live_subdomain_nonpublic", "status": second, "detail": second_detail,
             "count": len(probed_subs)},
        ],
        "counts": {"parameterised": len(with_params),
                   "parameterised_usable": len(usable_p),
                   "parameterised_unverified": len(skipped_p),
                   "anonymous_open": len(opened), "not_open": len(not_open),
                   "undecided": len(undecided),
                   "anonymous_open_write": len(writes)},
        "evidence": evidence,
        "kill_criteria": [
            "命中的写端点若全部需要 CSRF token / 二次确认 → 降为「需凭据才能利用」",
            "带参数端点改为返回 401/403（例如上线了 WAF 规则）→ 判决转 withheld",
            "判据二探到存活子域且暴露非公开面 → 由 not_worth/withheld 改判 worth",
        ],
        "unknowns": unknowns,
        "note": ("三态判决：worth / not_worth / withheld。判据二只能升级、不能否决——"
                 "否则 not_worth 永远不可达。withheld 只表示判据一判不了，或扫描太薄不信负数。"),
    }
