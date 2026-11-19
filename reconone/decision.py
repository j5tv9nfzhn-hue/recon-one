"""One decision, several evidence layers.

Before this module the report had four blocks that could all look like a conclusion:

* ``profile`` — peripheral value/hardness;
* ``bet`` — anonymous parameterised surface;
* ``uncertainty`` — what is still unmeasured;
* ``score.triage`` — a deliverability/maintenance tree that also said "不建议投入".

They were not wrong individually, but a reader could not tell which one was *the* answer.
``decision`` is the canonical block; the other four become evidence:

* the surface verdict comes from ``bet`` (worth / not_worth / withheld);
* business value is a **proxy** from ``profile`` (write endpoints, specs, parameters);
* resistance is ``profile.hardness`` plus explicitly unobservable controls;
* unknownness and next actions come from ``uncertainty``;
* deliverability is whether a disclosure channel was actually observed (security.txt),
  never inferred from the absence of one.

It is deliberately non-probabilistic: statuses are ``supports`` / ``opposes`` / ``uncertain``
/ ``neutral``; confidence is an ordinal high/medium/low that only goes *down* when a
high-impact unknown exists.
"""
from __future__ import annotations

VERSION = "1"
CONFIDENCE_ORDER = {"high": 2, "medium": 1, "low": 0}
CONFIDENCE_LABEL = {2: "high", 1: "medium", 0: "low"}


def _lower(confidence: str) -> str:
    rank = CONFIDENCE_ORDER.get(confidence, 0)
    return CONFIDENCE_LABEL.get(max(0, rank - 1), "low")


def _criterion_status(value: str) -> str:
    return {"hit": "supports", "miss": "opposes", "unknown": "uncertain"}.get(
        str(value or ""), "uncertain")


def _factor(fid: str, label: str, status: str, value: str, detail: str,
            mode: str = "active") -> dict:
    return {"id": fid, "label": label, "status": status, "value": value,
            "detail": detail, "mode": mode}


def _value_text(axis: dict) -> str:
    score = axis.get("score")
    coverage = axis.get("coverage_pct")
    if score is None:
        return "未评估"
    cover = "—" if coverage is None else f"{coverage:.0f}%"
    return f"{score:.0f}/100（覆盖 {cover}）"


def build(report: dict) -> dict:
    """Compose the one canonical decision block from the evidence layers."""
    report = report or {}
    bet = report.get("bet") or {}
    profile = report.get("profile") or {}
    uncertainty = report.get("uncertainty") or {}
    assets = report.get("assets") or {}
    facts = uncertainty.get("facts") or {}
    unknowns = uncertainty.get("unknowns") or []
    next_actions = uncertainty.get("next_actions") or []
    flips = uncertainty.get("verdict_flips") or []

    criteria = bet.get("criteria") or []
    criterion1 = next((c for c in criteria if c.get("rule") == "anonymous_parameterized"), {})
    criterion2 = next((c for c in criteria if c.get("rule") == "live_subdomain_nonpublic"), {})
    surface_verdict = str(bet.get("verdict") or "")
    surface_confidence = str(bet.get("confidence") or "low")

    well_known = assets.get("well_known") or {}
    security_txt = (well_known.get("/.well-known/security.txt")
                    or well_known.get("/security.txt") or {})
    channel = int(security_txt.get("status") or 0) == 200

    worth_axis = (profile.get("axes") or {}).get("worth") or {}
    hard_axis = (profile.get("axes") or {}).get("hardness") or {}
    worth_status = ("unknown" if worth_axis.get("score") is None else
                    "supports" if (worth_axis.get("score") or 0) >= 50 else
                    "opposes" if (worth_axis.get("score") or 0) < 30 else "neutral")
    hard_status = ("unknown" if hard_axis.get("score") is None else
                   "opposes" if (hard_axis.get("score") or 0) >= 60 else
                   "supports" if (hard_axis.get("score") or 0) < 40 else "neutral")

    high_open = [item for item in unknowns
                 if item.get("impact") == "high" and item.get("kind") != "confirm"
                 and int(item.get("count") or 0) > 0]
    confidence = surface_confidence
    if high_open:
        confidence = _lower(confidence)
    coverage = (profile.get("coverage") or {}).get("combined_pct")
    if coverage is not None and float(coverage) < 60.0:
        confidence = _lower(confidence)

    if surface_verdict == "worth":
        if channel:
            code, label = "worth", "值得打（存在匿名可测面，且观察到披露渠道）"
        else:
            code, label = "worth_no_channel", "有技术面，但交付出口未确认"
    elif surface_verdict == "not_worth":
        upgrades = [item for item in unknowns
                    if "worth" in (item.get("could_change_verdict_to") or [])
                    and item.get("kind") != "confirm"]
        if upgrades:
            code, label = "not_worth_open", "当前证据不支持投入，但仍有可升级项"
        else:
            code, label = "not_worth", "不值（当前证据）"
    elif surface_verdict == "withheld":
        code, label = "collect", "先补证据（当前判不了）"
    else:
        code, label = "unknown", "未评估"

    top_cost = sum(int(item.get("cost_requests") or 0) for item in next_actions[:3])
    unknown_value = (f"{len(unknowns)} 项未闭合（高影响 {len(high_open)}），"
                     f"前 3 项约 {top_cost} 次请求")

    factors = [
        _factor("anonymous_parameterized", "匿名可访问的带参端点",
                _criterion_status(criterion1.get("status")),
                f"{bet.get('counts', {}).get('anonymous_open', 0)} 个命中",
                str(criterion1.get("detail") or "判据一未给出判定")),
        _factor("live_subdomain_nonpublic", "存活子域暴露非公开面",
                _criterion_status(criterion2.get("status")),
                f"{int(criterion2.get('count') or 0)} 个已探子域",
                str(criterion2.get("detail") or "判据二未给出判定")),
        _factor("business_value_proxy", "业务价值代理", worth_status,
                _value_text(worth_axis),
                "写端点/规范/参数/子域等代理信号；不等于真实业务价值，后者必须人工确认",
                "active"),
        _factor("resistance", "外围阻力（难度）", hard_status,
                _value_text(hard_axis),
                "WAF/拦截/TLS/版本/栈龄；限流、账号锁定与 MFA 无法静态判定",
                "active"),
        _factor("unknown_surface", "未知面", "uncertain", unknown_value,
                "未验证端点、未探子域、未逆向 bundle、发现被拦截/截断；补齐前置信度受限",
                "active"),
        _factor("deliverability", "交付出口", "supports" if channel else "unknown",
                "已观察到 security.txt" if channel else "未发现 security.txt",
                "缺失不等于没有交付渠道；需人工确认授权、SRC/赏金或客户通道",
                "active"),
    ]

    why_parts = [
        f"匿名面：{criterion1.get('detail') or '未判定'}；{criterion2.get('detail') or '未判定'}",
        f"阻力：{_value_text(hard_axis)}",
        f"未知：{unknown_value}",
        ("交付：已观察到披露渠道" if channel else "交付：未观察到披露渠道（需人工确认）"),
    ]
    return {
        "version": VERSION,
        "generated_by": "reconone.decision (canonical composition; no AI, no probabilities)",
        "is_probability": False,
        "verdict": surface_verdict,
        "confidence": confidence,
        "headline": {"code": code, "label": label,
                     "surface_verdict": surface_verdict,
                     "confidence": confidence},
        "why": "；".join(why_parts),
        "factors": factors,
        "facts": {
            "surface_verdict": surface_verdict,
            "confidence": confidence,
            "deliverability": "present" if channel else "absent",
            "unknowns": len(unknowns),
            "high_impact_unknowns": len(high_open),
            "cost_top3_requests": top_cost,
            "business_value_proxy": worth_axis.get("score"),
            "resistance": hard_axis.get("score"),
        },
        "next_actions": next_actions,
        "verdict_flips": flips,
        "evidence_layers": ["bet", "profile", "uncertainty", "assets.well_known"],
        "note": ("decision 是唯一结论；bet/profile/uncertainty 是证据层。"
                 "score.triage 只保留为交付/维护信号，不再作为结论。"),
    }
