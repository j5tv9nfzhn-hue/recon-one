"""Evidence-gated scoring: turn observed facts into numbers without inventing any.

Design contract
---------------
Every point awarded or deducted must come from a *check* that either:

* fired on a value the scanner literally observed (a header string, a cookie attribute,
  a certificate field), or
* was explicitly marked `insufficient-data` because the observation is absent.

The second case is the important one. Commercial security rating products are widely
criticised for exactly one failure mode: they emit a confident score from partial data and
the customer cannot audit where the number came from. This module refuses to do that.

Rules enforced here
-------------------
1. **No observation, no claim.** If a probe did not run or its result was not captured, the
   check is `unknown`, contributes 0 to both numerator and denominator, and the report says
   how much of the total weight was therefore unevaluated.
2. **Absence is not proof.** A missing header is only scored if we captured the header block.
   Otherwise the check is unknown.
3. **Value beats presence.** A header that is present but weak scores as weak; it never
   silently passes (that was the pre-existing bug this module replaces).
4. **Weights are data.** They live in rules/score.json with a published source and are
   versioned, so a score is reproducible and its basis can be argued with.
5. **Two separate numbers.** "Hygiene" (how well maintained) and "Opportunity" (how much
   room an assessment has) are different questions. Collapsing them into one score is what
   makes vendor ratings misleading, so they are reported side by side and never summed.
"""
from __future__ import annotations

import os
import re

from .config import load_rule
from .util import VOLATILE_HEADERS

SCORE_RULE_FILE = "score"

# Verdicts a check may produce. UNKNOWN is deliberately distinct from FAIL.
PASS, FAIL, WARN, UNKNOWN = "pass", "fail", "warn", "unknown"


def _rule() -> dict:
    return load_rule(SCORE_RULE_FILE, default={})


def _get(path: str, default=None):
    node = _rule()
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _check(cid: str, axis: str, dimension: str, status: str, weight: float,
           title: str, detail: str, evidence=None, source: str = "") -> dict:
    """One atomic, auditable assertion. This is the only unit that moves a score."""
    return {
        "id": cid,
        "axis": axis,                       # hygiene | opportunity
        "dimension": dimension,
        "status": status,                   # pass | fail | warn | unknown
        "weight": float(weight),
        "title": title,
        "detail": detail,
        "evidence": evidence or [],
        "source": source,
        # Points only exist for evaluated checks; unknown contributes nothing anywhere.
        "earned": float(weight) if status == PASS else (float(weight) * 0.5 if status == WARN else 0.0),
        "evaluated": status in (PASS, FAIL, WARN),
    }


# ---------------------------------------------------------------------------
# Individual check families
# ---------------------------------------------------------------------------

def _header_checks(web: dict, weights: dict) -> list[dict]:
    """Security headers, judged by value and gated on having captured the header block."""
    http = web.get("http") or {}
    headers = http.get("headers") or {}
    root_url = http.get("root_url") or web.get("root_url", "")
    results = ((http.get("security") or {}).get("results")) or []
    out = []

    if not headers:
        out.append(_check(
            "hdr.unavailable", "hygiene", "headers", UNKNOWN, weights.get("headers", 0),
            "响应头未捕获",
            "本次运行未保存响应头，因此所有响应头相关项均无法判定（不计分，不视为通过）",
            [], "recon-one internal"))
        return out

    # One aggregated check per header group would hide which header drove the score; the
    # whole point is that a reader can trace the number to a specific observed value.
    per_header = weights.get("per_header", {})
    # "Absent" is only provable by showing what *was* returned. Without the observed block
    # a reader has to trust the scanner's word, which is exactly the opacity that makes
    # commercial ratings unappealable.
    # `date` is regenerated per response and would otherwise make every score-dependent
    # artefact differ between two scans of an unchanged target (see util.VOLATILE_HEADERS).
    observed_block = {k: v[:200] for k, v in sorted(headers.items())
                      if k.lower() not in VOLATILE_HEADERS}
    for r in results:
        name = r.get("header", "")
        w = per_header.get(name, weights.get("default_header", 1))
        verdict = r.get("verdict")
        status = PASS if verdict == "ok" else (WARN if verdict == "weak" else FAIL)
        evidence = {"kind": "header", "name": name, "value": r.get("value", ""), "url": root_url}
        if status == FAIL:
            # Shown so the absence can be confirmed against the real response.
            evidence["observed_headers"] = observed_block
        out.append(_check(
            f"hdr.{name}", "hygiene", "headers", status, w,
            f"{name} {'已正确配置' if status == PASS else ('配置不足' if status == WARN else '缺失')}",
            r.get("note") or (r.get("value") or "响应头中不存在该项"),
            [evidence],
            "Mozilla HTTP Observatory scoring modifiers"))
    return out


def _cookie_checks(web: dict, weights: dict) -> list[dict]:
    """Cookie attributes. Each cookie is judged on its own flags, nothing inferred."""
    http = web.get("http") or {}
    cookies = http.get("cookies")
    root_url = http.get("root_url") or web.get("root_url", "")
    w = weights.get("cookie", 4)
    if cookies is None:
        return [_check("cookie.unavailable", "hygiene", "cookies", UNKNOWN, w,
                       "Cookie 未采集", "本次运行未采集 Cookie，无法判定属性",
                       [], "recon-one internal")]
    if not cookies:
        return [_check("cookie.none", "hygiene", "cookies", PASS, w,
                       "根页面未下发 Cookie", "根响应无 Set-Cookie，无 Cookie 属性可削弱",
                       [{"kind": "cookie", "count": 0}], "Mozilla HTTP Observatory")]

    out = []
    for c in cookies:
        name = c.get("name", "?")
        problems = []
        if not c.get("secure"):
            problems.append("缺少 Secure")
        if not c.get("httponly"):
            problems.append("缺少 HttpOnly")
        if (c.get("samesite") or "") in ("", "none"):
            problems.append("SameSite 缺失或为 None")
        status = FAIL if problems else PASS
        out.append(_check(
            f"cookie.{name}", "hygiene", "cookies", status, w,
            f"Cookie `{name}` {'属性完整' if status == PASS else '属性不足'}",
            "、".join(problems) if problems else "Secure + HttpOnly + SameSite 均存在",
            [{"kind": "cookie", "name": name, "secure": c.get("secure"),
              "httponly": c.get("httponly"), "samesite": c.get("samesite"), "url": root_url}],
            "Mozilla HTTP Observatory cookie modifiers"))
    return out


def _tls_checks(web: dict, weights: dict) -> list[dict]:
    tls = (web.get("http") or {}).get("tls") or web.get("tls") or {}
    w = weights.get("tls", 6)
    if not tls:
        return [_check("tls.unavailable", "hygiene", "tls", UNKNOWN, w,
                       "TLS 未探测", "未取得证书信息（站点可能不支持 HTTPS 或探测失败）",
                       [], "recon-one internal")]
    version = (tls.get("tls_version") or "").upper()
    if not version:
        return [_check("tls.version", "hygiene", "tls", UNKNOWN, w,
                       "TLS 版本未知", "证书可取但未记录协商版本",
                       [{"kind": "tls", "value": tls}], "recon-one internal")]
    status = PASS if version in ("TLSV1.2", "TLSV1.3") else FAIL
    note = f"协商版本 {version}"
    if tls.get("cipher"):
        note += f"，套件 {tls['cipher']}"
    if version in ("TLSV1", "TLSV1.0", "TLSV1.1"):
        note += "（已废弃版本，存在已知降级攻击面）"
    return [_check("tls.version", "hygiene", "tls", status, w,
                   f"TLS 协商版本 {version}", note,
                   [{"kind": "tls", "version": version, "cipher": tls.get("cipher"),
                     "not_after": tls.get("not_after"), "issuer": (tls.get("issuer") or {})}],
                   "RFC 8996 / Mozilla TLS guidelines")]


def _dns_checks(web: dict, dns: dict, weights: dict) -> list[dict]:
    w = weights.get("dns", 4)
    records = (dns or {}).get("records") or {}
    if not dns or not records:
        return [_check("dns.unavailable", "hygiene", "dns", UNKNOWN, w,
                       "DNS 未探测", "本次运行跳过了 DNS（--no-dns 或探测失败）",
                       [], "recon-one internal")]
    out = []
    spf = (dns.get("spf") or [])
    txt = records.get("TXT") or []
    if spf:
        joined = " ".join(spf).lower()
        if "-all" in joined:
            out.append(_check("dns.spf", "hygiene", "dns", PASS, w,
                              "SPF 存在且为硬失败", "SPF 使用 -all，未授权发信方被拒",
                              [{"kind": "dns", "type": "TXT", "value": spf[0][:200]}], "RFC 7208"))
        elif "~all" in joined:
            out.append(_check("dns.spf", "hygiene", "dns", WARN, w,
                              "SPF 为软失败", "SPF 使用 ~all，未授权邮件仅被标记而非拒绝",
                              [{"kind": "dns", "type": "TXT", "value": spf[0][:200]}], "RFC 7208"))
        else:
            out.append(_check("dns.spf", "hygiene", "dns", FAIL, w,
                              "SPF 无 all 限定", "SPF 未声明 all，任意主机可声称代发",
                              [{"kind": "dns", "type": "TXT", "value": spf[0][:200]}], "RFC 7208"))
    else:
        out.append(_check("dns.spf", "hygiene", "dns", FAIL, w,
                          "缺少 SPF 记录", "TXT 中无 v=spf1，邮件伪造门槛低",
                          [{"kind": "dns", "type": "TXT", "values": txt[:5]}], "RFC 7208"))

    dmarc = (dns.get("dmarc") or [])
    if dmarc:
        policy = ""
        for part in dmarc[0].split(";"):
            if part.strip().lower().startswith("p="):
                policy = part.split("=", 1)[1].strip().lower()
        status = PASS if policy in ("reject", "quarantine") else WARN
        out.append(_check("dns.dmarc", "hygiene", "dns", status, w,
                          f"DMARC 策略 p={policy or '缺失'}",
                          {"reject": "不合规邮件被拒", "quarantine": "不合规邮件进隔离",
                           "none": "仅监控不处置"}.get(policy, "策略值缺失或无法解析"),
                          [{"kind": "dns", "type": "TXT", "name": "_dmarc",
                            "value": dmarc[0][:200]}], "RFC 7489"))
    else:
        out.append(_check("dns.dmarc", "hygiene", "dns", FAIL, w,
                          "缺少 DMARC 记录", "_dmarc 无 TXT，收信方无法依据策略处置伪造邮件",
                          [], "RFC 7489"))
    return out


def _opportunity_checks(web: dict, api: dict, js: dict, dns: dict, weights: dict,
                        api_observed: bool = True) -> list[dict]:
    """Signals that raise or lower the expected cost of an assessment.

    These are scored on the *opportunity* axis only: they never improve or damage the
    hygiene score, because "this target is cheap to assess" and "this target is well
    maintained" are independent statements.
    """
    out = []
    w = weights

    # --- Source maps: the single strongest cost reducer, and it is binary. -------------
    scripts = js.get("scripts") or []
    if js.get("scripts") is None:
        out.append(_check("opp.sourcemap", "opportunity", "code-exposure", UNKNOWN,
                          w.get("sourcemap", 10), "Source map 未探测",
                          "本次未抓取脚本，无法判定 source map", [], "recon-one internal"))
    else:
        leaking = [s for s in scripts if (s.get("sourcemap") or {}).get("leaks_original_source")]
        if leaking:
            names = ", ".join(os.path.basename(s.get("artifact") or "") for s in leaking[:3])
            out.append(_check("opp.sourcemap", "opportunity", "code-exposure", PASS,
                              w.get("sourcemap", 10),
                              f"source map 泄露原始源码（{len(leaking)} 处）",
                              f"sourcesContent 可直接还原业务源码，黑盒审计转白盒；样例 {names}",
                              [{"kind": "js", "artifacts": [s.get("artifact") for s in leaking[:5]],
                                "urls": [s.get("url") for s in leaking[:5]]}],
                              "observed in this run"))
        else:
            out.append(_check("opp.sourcemap", "opportunity", "code-exposure", FAIL,
                              w.get("sourcemap", 10), "未发现 source map 泄露",
                              f"已检查 {len(scripts)} 个脚本，无可还原源码的 map",
                              [{"kind": "js", "checked": len(scripts)}], "observed in this run"))

    # --- API specs / GraphQL introspection: schema handed to the tester. --------------
    specs = api.get("specs") or []
    gql = (api.get("graphql") or {}).get("endpoints") or []
    wspec = w.get("api_spec", 8)
    wgql = w.get("graphql", 8)
    if not api_observed:
        out.append(_check("opp.api_spec", "opportunity", "schema-exposure", UNKNOWN, wspec,
                          "API 规范未探测",
                          "本次跳过 API 探测（目标不可达或 --no-graphql），无法判定规范是否公开",
                          [], "recon-one internal"))
        out.append(_check("opp.graphql", "opportunity", "schema-exposure", UNKNOWN, wgql,
                          "GraphQL 未探测",
                          "本次未做 introspection（目标不可达或 --no-graphql），无法判定是否开放",
                          [], "recon-one internal"))
    else:
        if specs:
            out.append(_check("opp.api_spec", "opportunity", "schema-exposure", PASS, wspec,
                              f"公开 API 规范（{len(specs)} 份）",
                              "端点、参数与认证模型已描述，测试矩阵可直接生成",
                              [{"kind": "spec", "urls": [x.get("url") for x in specs[:5]],
                                "endpoints": sum(x.get("endpoint_count", 0) for x in specs)}],
                              "observed in this run"))
        else:
            out.append(_check("opp.api_spec", "opportunity", "schema-exposure", FAIL, wspec,
                              "无公开 API 规范", "未发现 OpenAPI/Swagger 文档",
                              [{"kind": "spec", "checked": len(_spec_paths())}],
                              "observed in this run"))
        if gql:
            out.append(_check("opp.graphql", "opportunity", "schema-exposure", PASS, wgql,
                              f"GraphQL introspection 开放（{len(gql)} 处）",
                              "schema 全暴露，字段级越权测试成本骤降",
                              [{"kind": "graphql", "urls": [x.get("url") for x in gql]}],
                              "observed in this run"))
        else:
            out.append(_check("opp.graphql", "opportunity", "schema-exposure", FAIL, wgql,
                              "GraphQL introspection 未开放",
                              "未发现可 introspection 的端点或 introspection 被关闭",
                              [{"kind": "graphql", "checked": True}], "observed in this run"))

    # --- Secrets: count only confirmed rule hits, never guesses. ----------------------
    secrets = js.get("secrets")
    if secrets is None:
        out.append(_check("opp.secrets", "opportunity", "credentials", UNKNOWN,
                          w.get("secrets", 12), "密钥扫描未运行", "未抓取脚本，无法扫描",
                          [], "recon-one internal"))
    elif secrets:
        by_type = {}
        for sec in secrets:
            by_type[sec.get("type", "?")] = by_type.get(sec.get("type", "?"), 0) + 1
        out.append(_check("opp.secrets", "opportunity", "credentials", PASS,
                          w.get("secrets", 12),
                          f"前端硬编码凭据（{len(secrets)} 处 / {len(by_type)} 类）",
                          "、".join(f"{k}×{v}" for k, v in sorted(by_type.items())),
                          [{"kind": "secret", "masked": [s.get("masked") for s in secrets[:5]],
                            "sha256_12": [s.get("sha256_12") for s in secrets[:5]],
                            "note": "原文仅在报告包 raw/ 内，未写入本表"}],
                          "observed in this run（规则命中，非启发式）"))
    else:
        out.append(_check("opp.secrets", "opportunity", "credentials", FAIL,
                          w.get("secrets", 12), "未发现前端硬编码凭据",
                          f"{_secret_rule_count()} 条规则全部未命中", [{"kind": "secret", "hits": 0}],
                          "observed in this run"))

    # --- Internal hostnames: only real internal TLDs / private ranges. ---------------
    hosts = js.get("hosts")
    if hosts is None:
        out.append(_check("opp.internal", "opportunity", "topology", UNKNOWN,
                          w.get("internal_host", 8), "主机引用未采集",
                          "未抓取脚本，无法判定", [], "recon-one internal"))
    else:
        # Re-check the classification instead of trusting the record: reports produced by
        # older versions labelled localhost/127.x as "internal", and scoring a stale
        # report must not resurrect that false positive.
        def _is_loopback(h: dict) -> bool:
            host = (h.get("url") or "").split("://")[-1].split("/")[0].split(":")[0].lower()
            return host in ("localhost", "::1", "[::1]") or host.startswith("127.")

        internal = [h for h in hosts if h.get("kind") == "internal" and not _is_loopback(h)]
        refs = [h for h in hosts
                if h.get("kind") == "reference" or (h.get("kind") == "internal" and _is_loopback(h))]
        if internal:
            out.append(_check("opp.internal", "opportunity", "topology", PASS,
                              w.get("internal_host", 8),
                              f"前端引用内部命名空间（{len(internal)} 处）",
                              "内网主机名暴露拓扑，可用于横向路径规划；"
                              + "、".join(h.get("url", "") for h in internal[:3]),
                              [{"kind": "host", "urls": [h.get("url") for h in internal[:5]],
                                "sources": [h.get("source") for h in internal[:5]]}],
                              "observed in this run"))
        else:
            note = "未发现 .internal/.corp/私网地址引用"
            if refs:
                note += f"（另有 {len(refs)} 处 localhost/127.x 自引用，已排除，不计为内网）"
            out.append(_check("opp.internal", "opportunity", "topology", FAIL,
                              w.get("internal_host", 8), "未发现内部命名空间", note,
                              [{"kind": "host", "checked": len(hosts)}], "observed in this run"))

    # --- Parameters on endpoints: the difference between inventory and testability. --
    endpoints = api.get("endpoints") or []
    if not endpoints:
        out.append(_check("opp.params", "opportunity", "surface", UNKNOWN,
                          w.get("parameters", 10), "无可评估端点",
                          "本次未发现端点，无法评估可测性", [], "recon-one internal"))
    else:
        with_params = sum(1 for e in endpoints if e.get("params"))
        write = sum(1 for e in endpoints
                    if any(m.upper() in ("POST", "PUT", "PATCH", "DELETE")
                           for m in (e.get("methods") or []) if m))
        body_fields = sum(1 for p in (api.get("parameters") or [])
                          if (p.get("in") or "").lower() in ("body", "form"))
        ratio = with_params / len(endpoints)
        # Only 4% of endpoints exposed a parameter, yet 32 write endpoints exist. The old
        # rule scored on the parameter ratio alone and reported this as a *pass*, which
        # understated how much state-changing surface was present. Write endpoints are
        # independently testable (authz, replay, state machines) even with no visible
        # parameter name, so the two signals are graded separately.
        write_status = PASS if write >= 10 else (WARN if write >= 3 else FAIL)
        # Query strings are one source of parameter names; extracted body fields are the
        # other, and for POST/PUT endpoints they are the only usable one.
        named = with_params + body_fields
        param_status = PASS if named >= 5 else (WARN if named >= 1 else FAIL)
        status = write_status if write >= 10 else (
            WARN if WARN in (write_status, param_status) else FAIL
        )
        out.append(_check("opp.params", "opportunity", "surface", status,
                          w.get("parameters", 10),
                          f"写方法端点 {write} 个；显式参数 {with_params}/{len(endpoints)}"
                          f"（{ratio:.0%}）；请求体字段 {body_fields} 个",
                          f"写方法端点可承载越权/重放/状态机类测试（{write} 个已确认）；"
                          f"显式参数仅 {with_params} 个，说明参数多在请求体内，静态提取不到 —— "
                          "这本身是「需要动态探测」的信号，不是「没有可测面」",
                          [{"kind": "endpoint", "with_params": with_params,
                            "write_methods": write, "total": len(endpoints)}],
                          "observed in this run"))

    # --- Maintenance freshness: only from explicit version evidence in headers. ------
    headers = (web.get("http") or {}).get("headers") or {}
    wfresh = w.get("freshness", 6)
    if not headers:
        out.append(_check("opp.freshness", "opportunity", "maintenance", UNKNOWN, wfresh,
                          "版本信息未采集", "无响应头，无法判断维护新鲜度", [],
                          "recon-one internal"))
    else:
        # Deliberately narrow: a version string in Server/X-Powered-By is evidence of
        # *staleness only when it names a version*, and even then we do not claim a CVE.
        stale = []
        for hname in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            val = headers.get(hname, "")
            if not val:
                continue
            m = re_search_version(val)
            if m:
                stale.append(f"{hname}: {val[:60]}")
        if stale:
            out.append(_check("opp.freshness", "opportunity", "maintenance", PASS, wfresh,
                              "响应头暴露软件版本",
                              "版本号可直接对照 CVE；注意：仅表示可查询，不表示存在已知漏洞",
                              [{"kind": "header", "values": stale}],
                              "observed in this run"))
        else:
            out.append(_check("opp.freshness", "opportunity", "maintenance", FAIL, wfresh,
                              "响应头未暴露版本号",
                              "Server/X-Powered-By 无版本串，CVE 对照需其他来源",
                              [{"kind": "header", "server": headers.get("server", "")}],
                              "observed in this run"))
    return out


_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)*\b")


def re_search_version(value: str):
    """True only when the header carries an explicit dotted version number."""
    return _VERSION_RE.search(value or "")


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _axis_score(checks: list[dict], axis: str) -> dict:
    """Weighted percentage over *evaluated* checks only, with coverage reported."""
    relevant = [c for c in checks if c["axis"] == axis]
    evaluated = [c for c in relevant if c["evaluated"]]
    total_w = sum(c["weight"] for c in relevant)
    eval_w = sum(c["weight"] for c in evaluated)
    earned = sum(c["earned"] for c in evaluated)
    pct = (earned / eval_w * 100.0) if eval_w else None
    return {
        "score": round(pct, 1) if pct is not None else None,
        "earned_weight": round(earned, 1),
        "evaluated_weight": round(eval_w, 1),
        "total_weight": round(total_w, 1),
        # How much of the intended assessment actually produced a verdict.
        "coverage_pct": round(eval_w / total_w * 100.0, 1) if total_w else 0.0,
        "checks_total": len(relevant),
        "checks_evaluated": len(evaluated),
        "checks_unknown": len(relevant) - len(evaluated),
    }


MIN_COVERAGE_FOR_GRADE = 60.0   # below this, no letter grade is issued at all

# What each axis does and does not cover. Printed in reports and shown in the GUI because a
# number without its scope gets over-read — that is how "strong browser headers" became
# "well maintained" in the first place.
AXIS_SCOPE = {
    "hygiene": "仅覆盖浏览器侧配置（响应头、Cookie 属性、TLS 版本、SPF/DMARC）。"
               "不覆盖：服务端代码、鉴权与会话逻辑、容器/沙箱隔离、权限模型、业务逻辑。",
    "opportunity": "仅覆盖本次可观测的「降低评估成本」信号。"
                   "不覆盖：内部人员信息、已泄露凭据库、供应链、历史 CVE。",
}


def _spec_paths() -> list[str]:
    """Candidate spec paths, taken from the probe module so the count cannot drift."""
    from .apiprobe import SPEC_PATHS
    return list(SPEC_PATHS)


def _secret_rule_count() -> int:
    """Number of secret regexes actually shipped, so the wording cannot drift from data."""
    return len((load_rule("secrets", default={"patterns": []}).get("patterns")) or [])


def _js_was_observed(report: dict, asset_scripts) -> bool:
    """True only when the JS stage produced usable data, i.e. "none found" is a finding.

    `assemble()` always writes `assets.scripts = []`, so an empty list cannot tell
    "downloaded the bundles, inspected them, found nothing" apart from "never fetched
    anything" (unreachable target, JS stage failed, or no scripts at all). The stage
    status carries that distinction; reports written before it existed fall back to
    "there is at least one script entry".
    """
    probes = ((report.get("coverage") or {}).get("probes") or {})
    status = probes.get("js")
    if status is not None:
        return str(status) == "ok"
    return bool(asset_scripts)


def _api_was_observed(report: dict) -> bool:
    """False only when the API stage was explicitly skipped (unreachable / --no-graphql).

    Same rule as `_js_was_observed`: a skipped stage cannot support "no public spec" or
    "introspection closed". Unknown statuses from older reports keep the old behaviour so a
    re-score of an archived package does not silently change its verdict.
    """
    probes = ((report.get("coverage") or {}).get("probes") or {})
    status = probes.get("api")
    if status is None:
        return True
    return str(status) != "skipped"


def _grade(pct, chart: list, coverage: float = 100.0) -> str:
    """Letter grade, withheld when the assessment covered too little to justify one.

    A high score over a small slice is the classic rating-product failure: 3 of 5 checks
    passing reads as "A" when 40% of the weight was never evaluated. Withholding the grade
    is the only honest output in that case.
    """
    if coverage < MIN_COVERAGE_FOR_GRADE:
        # Covers both "nothing evaluated" and "too little evaluated": either way a letter
        # grade would misrepresent the evidence, so none is issued.
        return "N/A◇"
    if pct is None:
        return "N/A"
    for floor, letter in chart:
        if pct >= floor:
            return letter
    return chart[-1][1]


def score_report(report: dict) -> dict:
    """Attach a fully traceable score block to a report. Pure function, no I/O."""
    cfg = _rule()
    weights = cfg.get("weights", {})
    hygiene_w = weights.get("hygiene", {})
    opp_w = weights.get("opportunity", {})
    chart = cfg.get("grade_chart", [[90, "A"], [80, "B"], [70, "C"], [60, "D"], [0, "F"]])

    web = {
        "root_url": (report.get("target") or {}).get("root_url", ""),
        **(report.get("assets") or {}),
    }
    api = {
        "specs": report.get("specs") or [],
        "graphql": {"endpoints": report.get("graphql") or []},
        "endpoints": report.get("endpoints") or [],
        "parameters": report.get("parameters") or [],
    }
    assets = report.get("assets") or {}
    asset_scripts = assets.get("scripts")
    js_observed = _js_was_observed(report, asset_scripts)
    js = {
        "scripts": assets.get("script_details"),
        "secrets": report.get("secrets"),
        "hosts": assets.get("hosts"),
    }
    # `assets.scripts` is a list of summary dicts, not the raw jsanalyze structure. Rebuild
    # the shape the checks expect instead of assuming the two are interchangeable — doing
    # the latter silently turned every sourcemap verdict into a false "no leak".
    if js["scripts"] is None and asset_scripts is not None:
        # `scripts[].sourcemap` appears in two shapes: a bool written by assemble(), and a
        # dict written by the raw jsanalyze result. Testing the dict for truthiness is
        # always true, which silently turned every "no leak" into a leak.
        def _leaks(entry: dict) -> bool:
            sm = entry.get("sourcemap")
            if isinstance(sm, dict):
                return bool(sm.get("leaks_original_source"))
            return bool(sm) or bool(entry.get("sourcemap_leaks"))

        js["scripts"] = [
            {"url": s.get("url"), "artifact": s.get("artifact"),
             "sourcemap": {"leaks_original_source": _leaks(s)}}
            for s in asset_scripts
        ]

    # "Not inspected" is not "inspected and clean". `assemble()` always writes an empty
    # list for scripts/secrets/hosts, so without this gate an unreachable target or a run
    # where the JS stage never ran produced confident FAILs ("17 rules, no hits") that the
    # model never had the evidence to make. Empty + no observation => unknown.
    if not js_observed:
        for key in ("scripts", "secrets", "hosts"):
            if not js[key]:
                js[key] = None

    dns = ((report.get("assets") or {}).get("dns")) or {}

    checks: list[dict] = []
    checks += _header_checks(web, hygiene_w)
    checks += _cookie_checks(web, hygiene_w)
    checks += _tls_checks(web, hygiene_w)
    checks += _dns_checks(web, dns, hygiene_w)
    checks += _opportunity_checks(web, api, js, dns, opp_w, api_observed=_api_was_observed(report))

    hygiene = _axis_score(checks, "hygiene")
    opportunity = _axis_score(checks, "opportunity")
    hygiene["grade"] = _grade(hygiene["score"], chart, hygiene["coverage_pct"])
    opportunity["grade"] = None            # an opportunity score is not a quality grade

    block = {
        "version": cfg.get("version", "1"),
        "scoring_method": cfg.get("method_note", ""),
        "weights_source": cfg.get("source", ""),
        "axes": {"hygiene": hygiene, "opportunity": opportunity},
        "checks": checks,
        "summary": _summary_line(hygiene, opportunity),
        "disclaimer": cfg.get("disclaimer", ""),
    }
    block["triage"] = triage({**report, "score": block})
    return block


def _summary_line(hygiene: dict, opportunity: dict) -> str:
    """One line that a human can sanity-check at a glance."""
    h = hygiene["score"]
    o = opportunity["score"]
    parts = []
    if h is None:
        parts.append("维护水平 无法评分")
    elif hygiene["grade"] == "N/A◇":
        parts.append(f"维护水平 暂不评级（覆盖率仅 {hygiene['coverage_pct']:.0f}%，"
                     f"低于 {MIN_COVERAGE_FOR_GRADE:.0f}% 的评级门槛）")
    else:
        parts.append(f"维护水平 {h:.0f}/100（{hygiene['grade']}）")
    parts.append(f"可评估机会 {o:.0f}/100" if o is not None else "可评估机会 无法评分")
    cov = min(hygiene["coverage_pct"], opportunity["coverage_pct"])
    if cov < 100:
        parts.append(f"数据覆盖 {cov:.0f}%，未覆盖项不计分、不视为通过")
    return "；".join(parts)


# ---------------------------------------------------------------------------
# Decision layer: "is this worth doing?"
# ---------------------------------------------------------------------------
# This is deliberately a rule tree over the *already-computed* checks, not a second score.
# Its output names the checks that drove the verdict, so a disagreement can be traced to a
# specific observation rather than argued with as a black box.
def triage(report: dict) -> dict:
    """Return a verdict about assessment cost/value, with the rules that produced it.

    IMPORTANT — what the hygiene score must NOT be used for
    ------------------------------------------------------
    An earlier version branched on `hygiene >= 70` to conclude "well maintained, probably
    not worth it". That inference is invalid, and a real target exposed it: browser headers
    were largely correct (74/100) while container/sandbox isolation and backend
    authorization were broken badly enough that the sandbox was escaped in 15 minutes.

    The reason is structural, not a tuning problem: `hygiene` only reads what is visible
    from outside without authentication — response headers, cookie flags, TLS version,
    SPF/DMARC. Application authorization, tenancy isolation, container boundaries and
    business logic are *invisible to all of those signals*. A site can be perfect on every
    header and still hand out another tenant's data.

    Therefore this function never infers low value from a high hygiene score. Hygiene is
    only allowed to *raise* confidence when it is low (a genuinely neglected perimeter does
    correlate with cheaper assessment), never to rule a target out when it is high.
    """
    block = (report.get("score") if isinstance(report.get("score"), dict) else None) \
        or score_report(report)
    axes = block.get("axes") or {}
    hyg, opp = axes.get("hygiene") or {}, axes.get("opportunity") or {}
    checks = {c["id"]: c for c in block.get("checks") or []}
    well_known = (report.get("assets") or {}).get("well_known") or {}

    coverage = min(hyg.get("coverage_pct") or 0.0, opp.get("coverage_pct") or 0.0)
    unknown = [cid for cid, c in checks.items() if c.get("status") == UNKNOWN]

    # Rule 0 — insufficient evidence outranks every other judgement.
    if coverage < MIN_COVERAGE_FOR_GRADE:
        return {
            "verdict": "insufficient-evidence",
            "label": "证据不足，暂不判断",
            "why": (f"数据覆盖仅 {coverage:.0f}%（门槛 {MIN_COVERAGE_FOR_GRADE:.0f}%）。"
                    "在补齐之前，任何「值得/不值得」的结论都不可信。"),
            "actions": ["补齐未采集项后重跑", "或接受部分结论并明确标注不确定性"],
            "drivers": unknown[:8],
            "blind_spots": list(AXIS_SCOPE.values()),
        }

    st = well_known.get("/.well-known/security.txt") or well_known.get("/security.txt") or {}
    has_channel = st.get("status") == 200

    drivers = []
    # Business-surface signals: these say "there is something here to test", independent of
    # how neat the perimeter looks.
    write_eps = 0
    for e in (report.get("endpoints") or []):
        if any(str(m).upper() in ("POST", "PUT", "PATCH", "DELETE")
               for m in (e.get("methods") or [])):
            write_eps += 1
    if write_eps >= 10:
        drivers.append("surface.write_endpoints")
    if "opp.sourcemap" in checks and checks["opp.sourcemap"].get("status") == PASS:
        drivers.append("opp.sourcemap")
    if "opp.secrets" in checks and checks["opp.secrets"].get("status") == PASS:
        drivers.append("opp.secrets")
    if "opp.api_spec" in checks and checks["opp.api_spec"].get("status") == PASS:
        drivers.append("opp.api_spec")
    if "opp.internal" in checks and checks["opp.internal"].get("status") == PASS:
        drivers.append("opp.internal")
    if has_channel:
        drivers.append("disclosure.available")

    surface = [d for d in drivers if d == "surface.write_endpoints" or d.startswith("opp.")]
    blind = list(AXIS_SCOPE.values())

    # Rule 1 — real business surface is the strongest positive signal we can observe.
    # 32 write endpoints + source map + a disclosure channel is not "low yield" by any
    # reading; the perimeter looking tidy says nothing about authorization inside.
    if write_eps >= 10 or len(surface) >= 3:
        return {
            "verdict": "worthwhile",
            "label": "值得投入（存在实质业务测试面）",
            "why": (f"观测到 {write_eps} 个写方法端点"
                    + ("、source map 可还原源码" if "opp.sourcemap" in drivers else "")
                    + ("、明文凭据" if "opp.secrets" in drivers else "")
                    + ("、公开 API 规范" if "opp.api_spec" in drivers else "")
                    + f"。维护水平 {hyg.get('score', 0):.0f}/100 只反映浏览器侧配置，"
                      "**不能据此推断鉴权、租户隔离或沙箱边界的强度**。"),
            "actions": ["优先测写方法端点的对象级授权（BOLA）",
                        "若有 source map，按还原源码做白盒审计",
                        "容器/沙箱隔离需动态验证，静态信号无法覆盖"],
            "drivers": drivers,
            "blind_spots": blind,
        }

    # Rule 2 — no disclosure channel and no business surface: nothing to deliver.
    if not has_channel and not surface:
        return {
            "verdict": "low-value",
            "label": "不建议投入",
            "why": ("未发现披露渠道（security.txt），且未观测到可承载测试的业务面"
                    "（无写方法端点、无 source map、无公开规范、无明文凭据）。找到了也无处交付。"),
            "actions": ["优先找有 SRC/赏金/披露页的目标", "如仍要做，先设定极短停机预算"],
            "drivers": drivers,
            "blind_spots": blind,
        }

    if not has_channel:
        return {
            "verdict": "no-channel",
            "label": "有技术空间，但无交付出口",
            "why": ("存在可评估的弱点信号，但未发现披露渠道，变现路径不确定。"),
            "actions": ["确认是否有 SRC / 赏金 / 官方联系渠道", "无渠道则仅作自测或放弃"],
            "drivers": drivers,
            "blind_spots": blind,
        }

    # Rule 3 — low hygiene is only ever used as a *positive* hint.
    if (hyg.get("score") or 0) < 50 and (opp.get("score") or 0) >= 40:
        return {
            "verdict": "conditional",
            "label": "外围薄弱，可低成本试探",
            "why": (f"外围配置分仅 {hyg.get('score', 0):.0f}/100，"
                    f"可评估机会 {opp.get('score', 0):.0f}/100：进入成本低，但同样无法据此"
                    "推断业务层强度。"),
            "actions": ["先测外围暴露面，再转向业务端点", "设定停机预算"],
            "drivers": drivers,
            "blind_spots": blind,
        }

    return {
        "verdict": "conditional",
        "label": "有条件可做（外围无结论，需实测业务层）",
        "why": (f"维护水平 {hyg.get('score', 0):.0f}/100 仅代表浏览器侧配置；"
                f"可评估机会 {opp.get('score', 0):.0f}/100。"
                "两者都不能回答「鉴权与隔离是否可靠」——那必须实测。"),
        "actions": ["按报告 §7 假设顺序推进", "优先验证写方法端点的授权边界",
                    "外围配置完善不构成放弃理由"],
        "drivers": drivers,
        "blind_spots": blind,
    }
