"""Unknown surface: what we have not measured, why it matters, and what to do next.

Why this module exists
----------------------
A red-team decision is not "a number says 71". It is "what could change the answer, how
much does it cost to find out, and where is the largest unknown per request". The bet sheet
already says *whether* to bet; this module says *what is still unmeasured* and turns each
gap into a bounded action.

The output is deliberately not probabilistic:

* ``impact`` is an ordinal policy (high / medium / low), not a likelihood;
* ``cost_requests`` is a concrete estimate derived from the scan's own budget and the
  number of unmeasured endpoints/hosts;
* ``could_change_verdict_to`` is a rule ("this unknown can promote/hold the verdict"),
  not a probability of that outcome;
* ``is_probability=False`` is written into the block.

Ordering is ``impact desc → cost_requests asc → id`` so the first action is the cheapest
high-impact unknown, not the longest checklist.
"""
from __future__ import annotations

from .util import is_ip_literal

VERSION = "1"
IMPACT_RANK = {"high": 3, "medium": 2, "low": 1}
MAX_ACTIONS = 5


def _pct(part: int, total: int):
    return round(part / total * 100.0, 1) if total else None


def _stage_incomplete(state) -> bool:
    """`none-found` / `empty` / `no-scripts` are completed observations, not gaps."""
    text = str(state or "")
    if text in ("ok", "empty", "none-found", "no-scripts"):
        return False
    return True


def _samples(items, key: str = "path", limit: int = 5) -> list[str]:
    return sorted({str(item.get(key) or "") for item in items or [] if item.get(key)})[:limit]


def _item(iid: str, title: str, kind: str, impact: str, count: int, cost: int,
          action: str, why: str, affects=(), flips=(), samples=()) -> dict:
    return {
        "id": iid,
        "title": title,
        "kind": kind,
        "impact": impact,
        "count": int(count),
        "cost_requests": int(max(0, cost)),
        "affects": list(affects),
        "could_change_verdict_to": list(flips),
        "action": action,
        "why": why,
        "samples": list(samples),
    }


def _discovery_cost(report: dict) -> int:
    discovery = report.get("discovery") or {}
    policy = discovery.get("policy") or {}
    if policy.get("max_requests"):
        return int(policy["max_requests"])
    limits = (report.get("meta") or {}).get("limits") or {}
    cap = int(limits.get("discovery_max") or 0)
    if not cap:
        cap = int(policy.get("max_candidates") or 80)
    return cap + 4                      # root + a few directory baselines


def build(report: dict, bet: dict | None = None) -> dict:
    """Return the deterministic unknown-surface block for an assembled report."""
    report = report or {}
    bet = bet or report.get("bet") or {}
    verdict = str(bet.get("verdict") or "")
    endpoints = report.get("endpoints") or []
    verification = report.get("verification") or {}
    summary = verification.get("summary") or {}
    identity = str(summary.get("identity_model") or "single")
    dual = identity == "dual"
    per_endpoint = 2 if dual else 1
    verify_on = bool(verification.get("enabled", False))
    coverage = report.get("coverage") or {}
    probes = coverage.get("probes") or {}
    counts = coverage.get("counts") or {}
    assets = report.get("assets") or {}
    intel = report.get("intel") or {}
    target = report.get("target") or {}
    http_headers = ((report.get("assets") or {}).get("http") or {}).get("headers") or {}
    if not int(target.get("status") or 0) and not endpoints and not http_headers:
        return {
            "version": VERSION,
            "generated_by": "reconone.uncertainty (target unreachable; no inventory)",
            "is_probability": False,
            "verdict": verdict,
            "confidence": bet.get("confidence", ""),
            "facts": {"endpoints_total": len(endpoints), "parameterised_total": 0,
                      "parameterised_answered": 0, "parameterised_unanswered": 0,
                      "parameterised_checked_pct": None, "subdomains_total": 0,
                      "subdomains_probed": 0, "subdomains_checked_pct": None,
                      "verification_enabled": verify_on, "identity_model": identity,
                      "js_observed": False, "discovery_status": "absent",
                      "truncated": False, "stages_incomplete": []},
            "unknowns": [],
            "next_actions": [],
            "verdict_flips": [],
            "notes": ["目标不可达；未知面无法评估。先恢复可达性，再谈是否值得打。"],
        }

    with_params = [e for e in endpoints if e.get("params")]
    answered = [e for e in with_params if e.get("verified") in ("usable", "unusable")]
    answered_paths = {e.get("path") for e in answered}
    unverified = [e for e in with_params if e.get("path") not in answered_paths]
    undecided = [e for e in answered if e.get("authz_open") is None]

    subs = assets.get("subdomains") or []
    probed_subs = [s for s in subs if s.get("probed")]
    unprobed_subs = [s for s in subs
                     if not s.get("probed") and s.get("skipped") != "out_of_scope"]
    ct = intel.get("ct") or {}
    archive = intel.get("archive") or {}
    discovery = report.get("discovery") or {}
    dstats = discovery.get("stats") or {}
    ip_target = is_ip_literal(target.get("domain"))

    items: list[dict] = []

    # ------------------------------------------------------------------ verification
    if not verify_on and with_params:
        items.append(_item(
            "verification.disabled", "验证阶段未启用", "verification", "high",
            len(with_params), per_endpoint * len(with_params),
            "启用验证（去掉 --no-verify）；优先验带参数端点",
            "没有验证就无法区分“路径存在”与“匿名可访问”，判据一只能 withheld。",
            affects=["anonymous_parameterized"], flips=["worth", "not_worth"],
            samples=_samples(with_params)))
    elif unverified:
        items.append(_item(
            "verification.parameterised_unverified", "带参数端点未验证", "verification",
            "high" if verdict in ("withheld", "not_worth") else "medium",
            len(unverified), per_endpoint * len(unverified),
            "提高 --verify-max 后重跑验证；预算/作用域/排除导致的跳过要分别处理",
            "每个未验证的带参端点都可能匿名开放；它是判据一唯一能把判决抬到 worth 的缺口。",
            affects=["anonymous_parameterized"], flips=["worth"],
            samples=_samples(unverified)))
    if verify_on and undecided:
        items.append(_item(
            "verification.authz_undecided", "匿名访问判定缺失", "verification", "high",
            len(undecided), per_endpoint * len(undecided),
            "补一次匿名访问判定：单身份看状态码，双身份做认证 / 无凭据两次 GET",
            "端点可用不等于匿名开放；缺少 anonymous_open 判定时判据一无法下结论。",
            affects=["anonymous_parameterized"], flips=["worth"],
            samples=_samples(undecided)))

    # ------------------------------------------------------------------ subdomains
    if unprobed_subs:
        items.append(_item(
            "subdomains.unprobed", "CT 子域未探活", "subdomains", "high",
            len(unprobed_subs), len(unprobed_subs),
            "对未探子域逐个 GET /（--subdomain-max 提高上限）",
            "判据二只能被观测抬高；没敲门就记 unknown，不能把未知说成不存在。",
            affects=["live_subdomain_nonpublic"], flips=["worth"],
            samples=_samples(unprobed_subs, "host")))
    if not ip_target and ct.get("status") not in ("ok", "empty", "disabled"):
        items.append(_item(
            "intel.ct_unavailable", "CT 子域来源不可用", "intel", "medium",
            0, 2,
            "重试 CT（CertSpotter 主 / crt.sh 回退），或换网络出口",
            "没有 CT 就没有子域候选；判据二仍是 unknown，而不是 miss。",
            affects=["live_subdomain_nonpublic"], flips=["worth"]))
    if archive.get("status") not in ("ok", "empty", "disabled"):
        items.append(_item(
            "intel.archive_unavailable", "历史存档不可用", "intel", "low",
            0, 2,
            "重试 Wayback CDX；失败时保留 unknown，不要当成“没有历史路径”",
            "历史路径是低成本的非 JS 端点来源；不可用只降低召回，不改变判据。"))

    # ------------------------------------------------------------------ JS / crawl / discovery
    js_state = str(probes.get("js", ""))
    if js_state == "skipped":
        items.append(_item(
            "js.skipped", "前端 bundle 未分析", "js", "high",
            int(counts.get("scripts") or 0), 12,
            "去掉 --no-js 重跑；这是端点、参数与请求体字段的主来源",
            "跳过 JS 等于放弃最便宜的前端逆向；报告会少掉接口与请求体字段。"))
    if int(counts.get("scripts_failed") or 0) > 0:
        items.append(_item(
            "js.fetch_failed", "部分脚本下载失败", "js", "medium",
            int(counts["scripts_failed"]), int(counts["scripts_failed"]),
            "检查失败脚本的状态码并重试；不要把它当成“没有端点”",
            "下载失败的 bundle 里可能有接口与密钥线索。",
            samples=[]))
    if coverage.get("truncated"):
        items.append(_item(
            "coverage.truncated", "扫描被预算截断", "coverage", "medium", 0, 0,
            "提高时间/字节预算或关闭非核心阶段后重跑",
            "截断意味着后面的阶段没有完整执行；负数结论不可信。",
            affects=["anonymous_parameterized", "live_subdomain_nonpublic"],
            flips=["worth", "not_worth"]))

    if not discovery.get("enabled"):
        items.append(_item(
            "discovery.skipped", "定向内容发现未运行", "discovery", "medium",
            0, _discovery_cost(report),
            "开启定向内容发现后重跑（有界候选 + 同前缀基线）",
            "它不直接改变判据，但会补充未在前端出现的路径与面。"))
    elif discovery.get("status") in ("baseline-blocked", "error"):
        items.append(_item(
            "discovery.baseline_blocked", "内容发现基线被拦截", "discovery", "medium",
            0, _discovery_cost(report),
            "换出口或稍后重试；基线被拦截时不要断言候选不存在",
            "无法区分“路径存在”与“被拦截/错误页”，继续探测只会制造误报。"))
    elif discovery.get("status") == "truncated":
        remaining = max(1, int(dstats.get("candidates") or 0) - int(dstats.get("probed") or 0))
        items.append(_item(
            "discovery.truncated", "内容发现预算截断", "discovery", "medium",
            remaining, remaining,
            "放宽 --discovery-max 或时间预算后重跑",
            "未探测的候选不是“不存在”；它们只是没有轮到。"))
    elif int(dstats.get("dropped_by_cap") or 0) > 0:
        items.append(_item(
            "discovery.cap", "内容发现候选被上限丢弃", "discovery", "low",
            int(dstats["dropped_by_cap"]), int(dstats["dropped_by_cap"]),
            "提高 --discovery-max 后重跑",
            "被上限丢弃的候选没有任何观测，不能当成不存在。"))

    # ------------------------------------------------------------------ endpoint quality
    unknown_method = [e for e in endpoints if "GET?" in (e.get("methods") or [])]
    if unknown_method:
        items.append(_item(
            "endpoints.unknown_method", "端点方法未确认", "endpoints", "medium",
            len(unknown_method), len(unknown_method),
            "从 bundle/规范复核方法，或只对 GET 做安全探测",
            "方法未知会隐藏写端点；写端点是价值判断里权重最高的一项。",
            samples=_samples(unknown_method)))
    low_confidence = [e for e in endpoints
                      if e.get("confidence") == "low" and not e.get("discovered")]
    if low_confidence:
        items.append(_item(
            "endpoints.low_confidence", "低置信端点未复核", "endpoints", "low",
            len(low_confidence), len(low_confidence),
            "按 file+offset 回到 bundle 原文复核，或抽样验证",
            "低置信路径可能是字符串噪声；不复核会污染可测面判断。",
            samples=_samples(low_confidence)))

    # ------------------------------------------------------------------ confirm a positive
    if verdict == "worth":
        opened = [e for e in endpoints if e.get("authz_open") is True and e.get("params")]
        hit_subs = [s for s in probed_subs if s.get("non_public")]
        samples = _samples(opened) or _samples(hit_subs, "host")
        count = max(len(opened), len(hit_subs), 1)
        items.append(_item(
            "confirm.hit", "确认命中的匿名面仍可交付", "confirm", "high",
            count, min(count, 4),
            "抽查命中路径的匿名状态、内容差异与写端点前置条件（CSRF/二次确认）",
            "worth 不是终点；kill_criteria 任意一条成立都要降级。",
            affects=["anonymous_parameterized", "live_subdomain_nonpublic"],
            flips=["not_worth"], samples=samples))

    items.sort(key=lambda item: (-IMPACT_RANK.get(item["impact"], 0),
                                 item["cost_requests"], item["id"]))
    for rank, item in enumerate(items, 1):
        item["rank"] = rank

    upgrade = [item for item in items if "worth" in item["could_change_verdict_to"]]
    downgrade = [item for item in items if "not_worth" in item["could_change_verdict_to"]]
    flips: list[dict] = []
    if verdict in ("withheld", "not_worth") and upgrade:
        flips.append({
            "from": verdict,
            "to": "worth",
            "condition": ("任一未验证带参端点被证明匿名开放，或未探子域暴露非公开面"
                          if verdict == "not_worth" else
                          "补齐判据一/二缺失的观测后，任一条命中"),
            "unknowns": [item["id"] for item in upgrade],
            "cost_requests": min(item["cost_requests"] for item in upgrade),
        })
    if verdict == "withheld":
        closing = [item for item in items
                   if item["id"].startswith("verification.")
                   or item["id"].startswith("subdomains.")
                   or item["id"] == "coverage.truncated"]
        if closing:
            flips.append({
                "from": "withheld",
                "to": "not_worth",
                "condition": "带参端点全部验证为不可用或被 401/403 拦住，且子域未暴露",
                "unknowns": [item["id"] for item in closing],
                "cost_requests": sum(item["cost_requests"] for item in closing),
            })
    if verdict == "worth" and downgrade:
        flips.append({
            "from": "worth",
            "to": "not_worth",
            "condition": "kill_criteria 任一成立：命中写端点需要 CSRF/二次确认，或路径改为 401/403",
            "unknowns": [item["id"] for item in downgrade],
            "cost_requests": min(item["cost_requests"] for item in downgrade),
        })

    facts = {
        "endpoints_total": len(endpoints),
        "parameterised_total": len(with_params),
        "parameterised_answered": len(answered),
        "parameterised_unanswered": len(with_params) - len(answered),
        "parameterised_checked_pct": _pct(len(answered), len(with_params)),
        "subdomains_total": len(subs),
        "subdomains_probed": len(probed_subs),
        "subdomains_checked_pct": _pct(len(probed_subs), len(subs)),
        "verification_enabled": verify_on,
        "identity_model": identity,
        "js_observed": js_state == "ok",
        "discovery_status": str(discovery.get("status") or "absent"),
        "truncated": bool(coverage.get("truncated")),
        "stages_incomplete": sorted(
            name for name, state in probes.items()
            if _stage_incomplete(state) and not (name == "intel" and ip_target)),
    }
    notes = ["这是操作覆盖与影响排序，不是漏洞概率；cost_requests 是按本次预算与端点数的估算。"]
    if verdict == "not_worth" and not upgrade:
        notes.append("没有发现可升级为 worth 的未闭合项；not_worth 仍是当前最强的结论。")
    if not items:
        notes.append("没有发现会改变判决的未闭合项；维持当前判决。")
    return {
        "version": VERSION,
        "generated_by": "reconone.uncertainty (deterministic inventory, no AI, no probabilities)",
        "is_probability": False,
        "verdict": verdict,
        "confidence": bet.get("confidence", ""),
        "facts": facts,
        "unknowns": items,
        "next_actions": items[:MAX_ACTIONS],
        "verdict_flips": flips,
        "notes": notes,
    }
