"""Report assembly, JSON schema, validation and the AI hand-off package."""
from __future__ import annotations

import json
import os
import time
from . import doctor as doctormod
from . import http as httpmod
from . import score as scoremod
from . import redact as redactmod
from . import triage as triagemod
from .config import (AUTHORIZED_USE, AUTHORIZED_USE_PREMISES, AUTHORIZED_USE_SHORT,
                     AUTHORIZED_USE_VERSION, SCHEMA_ID, VERSION)
from .util import (VOLATILE_HEADERS, canonical_json, now_iso, redact_header, scrub_header_block,
                   scrub_headers, scrub_urls, sha256_text)

SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": SCHEMA_ID,
    "type": "object",
    "required": ["schema", "meta", "target", "coverage", "assets", "endpoints", "findings",
                 "hypotheses", "errors"],
    "properties": {
        "schema": {"type": "string", "const": SCHEMA_ID},
        "meta": {"type": "object", "required": ["tool_version", "generated_at", "profile", "limits"]},
        "target": {"type": "object", "required": ["domain", "root_url"]},
        "coverage": {"type": "object", "required": ["probes", "counts", "complete"]},
        "assets": {"type": "object", "required": ["technology", "scripts", "hosts", "forms"]},
        "endpoints": {"type": "array"},
        "findings": {"type": "array"},
        "hypotheses": {"type": "array"},
        "errors": {"type": "array"},
    },
}

_TYPES = {"object": dict, "array": list, "string": str, "number": (int, float),
          "integer": int, "boolean": bool}


def validate(report: dict, schema: dict | None = None, path: str = "$") -> list[str]:
    """Small JSON-Schema subset: type, required, const. Enough to guard the contract."""
    schema = schema or SCHEMA
    errors: list[str] = []
    expected = schema.get("type")
    if expected and not isinstance(report, _TYPES[expected]) or \
            (expected == "boolean" and isinstance(report, int) and not isinstance(report, bool)):
        errors.append(f"{path}: expected {expected}, got {type(report).__name__}")
        return errors
    if "const" in schema and report != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}")
    for key in schema.get("required", []):
        if not isinstance(report, dict) or key not in report:
            errors.append(f"{path}: missing required '{key}'")
    for key, subschema in (schema.get("properties") or {}).items():
        if isinstance(report, dict) and key in report:
            errors.extend(validate(report[key], subschema, f"{path}.{key}"))
    return errors


def _finding(fid: str, category: str, severity: str, title: str, detail: str,
             evidence: list[dict] | None = None, confidence: str = "medium") -> dict:
    return {"id": fid, "category": category, "severity": severity, "title": title,
            "detail": detail, "evidence": evidence or [], "confidence": confidence}


def derive_findings(web: dict, js: dict, api: dict, dns: dict) -> list[dict]:
    out: list[dict] = []
    n = 0

    def add(*args, **kwargs):
        nonlocal n
        n += 1
        out.append(_finding(f"F-{n:03d}", *args, **kwargs))

    root_url = web.get("root_url", "")
    all_headers = web.get("headers") or {}
    # `date` is re-generated on every response, so quoting it verbatim makes the evidence
    # snippet — and therefore the report's deterministic digest — differ between two scans
    # of an unchanged target. It carries no audit value that the other headers do not, so
    # it is excluded from the quoted block only; the header itself stays in assets.http.
    stable_headers = {k: v for k, v in all_headers.items() if k.lower() != "date"}
    for missing in (web.get("security") or {}).get("missing", []):
        # Evidence must be the actual observed header block, not the string "response
        # headers". "Header absent" is only provable by showing the full set that *was*
        # returned, so the reader can confirm it is not in there under another name.
        observed = "\n".join(f"{k}: {v}" for k, v in sorted(stable_headers.items()))[:1200]
        add("headers", missing["severity"], f"缺少安全响应头 {missing['header']}",
            missing["reason"], [{"file": root_url, "offset": 0, "snippet": observed}], "high")
    for weak in (web.get("security") or {}).get("results", []):
        if weak.get("verdict") != "weak":
            continue
        add("headers", weak["severity"], f"安全响应头配置不足：{weak['header']}",
            weak["note"], [{"file": root_url, "offset": 0,
                            "snippet": f"{weak['header']}: {weak['value']}"}], "high")
    for cookie in web.get("cookies") or []:
        problems = []
        if not cookie["secure"]:
            problems.append("无 Secure")
        if not cookie["httponly"]:
            problems.append("无 HttpOnly")
        if cookie["samesite"] in ("", "none"):
            problems.append("SameSite 缺失/None")
        if problems:
            add("cookie", "medium", f"Cookie {cookie['name']} 属性不完整",
                "、".join(problems), [{"file": web.get("root_url", ""), "offset": 0,
                                       "snippet": cookie["name"]}], "high")
    for probe in (web.get("cors") or {}).get("probes", []):
        add("cors", probe["risk"], "CORS 策略可被外部 Origin 利用",
            f"{probe['url']} → ACAO={probe['allow_origin']} ACAC={probe['allow_credentials']}",
            [{"file": probe["url"], "offset": 0, "snippet": f"Origin probe: {probe['allow_origin']}"}],
            "high")
    for secret in js.get("secrets", []):
        add("secret", secret["severity"], f"前端硬编码凭据：{secret['type']}",
            f"{secret['masked']}（sha256:{secret['sha256_12']}，{secret['length']} 字符）",
            [secret["evidence"]], "medium")
    for script in js.get("scripts", []):
        sm = script.get("sourcemap") or {}
        if sm.get("leaks_original_source"):
            add("sourcemap", "high", "source map 内含 sourcesContent",
                f"{sm['url']} 暴露 {sm.get('source_count', 0)} 个源文件",
                [{"file": script.get("artifact", ""), "offset": 0, "snippet": "//# sourceMappingURL"}],
                "high")
    for spec in api.get("specs", []):
        add("api", "medium", f"API 规范公开：{spec.get('title') or spec['kind']}",
            f"{spec['url']} 含 {spec['endpoint_count']} 个端点",
            [{"file": spec["url"], "offset": 0, "snippet": f"{spec['kind']} spec"}], "high")
    for gql in (api.get("graphql") or {}).get("endpoints", []):
        add("graphql", "medium", "GraphQL introspection 未关闭",
            f"{gql['url']} 返回 {gql['type_count']} 个对象类型",
            [{"file": gql["url"], "offset": 0, "snippet": "__schema introspection"}], "high")
    for host in js.get("hosts", []):
        if host.get("kind") == "internal":
            add("exposure", "low", "前端引用内部主机",
                host["url"], [{"file": host["source"], "offset": host.get("offset", 0),
                               "snippet": host.get("snippet", "")}], "medium")
    for hint in js.get("hints", []):
        occurrences = hint.get("occurrences", 1)
        detail = hint["snippet"]
        if occurrences > 1:
            detail = f"出现 {occurrences} 次 · {detail}"
        add("js-hint", hint["severity"], f"前端风险模式：{hint['kind']}",
            detail, [{"file": hint["file"], "offset": hint["offset"],
                      "snippet": hint["snippet"]}], "low")
    for path in (dns.get("records", {}).get("TXT") or []):
        low = path.lower()
        if low.startswith("v=spf1") and "all" not in low:
            add("dns", "low", "SPF 记录缺少 all 限定", path[:160], [], "medium")
    if dns.get("records") and not dns.get("dmarc"):
        add("dns", "low", "缺少 DMARC 记录", f"_dmarc.{dns.get('domain')} 无 TXT", [], "medium")
    out.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}.get(f["severity"], 3), f["id"]))
    return [dict(f, id=f"F-{i:03d}") for i, f in enumerate(out, 1)]


def _testability(endpoint: dict) -> tuple:
    """Sort key that puts *useful* endpoints first.

    Raw discovery order is useless to a reader: a 125-row table of mostly parameterless
    GET routes buries the handful of POST/write endpoints that actually determine whether
    the target is interesting. Rank by how much an attacker can vary first, then confidence.
    """
    methods = [m.upper() for m in (endpoint.get("methods") or []) if m]
    params = endpoint.get("params") or []
    confidence = {"high": 0, "medium": 1, "low": 2}.get(endpoint.get("confidence", "low"), 2)
    write = 1 if any(m in ("POST", "PUT", "PATCH", "DELETE") for m in methods) else 0
    return (0 if params else 1, 0 if write else 1, confidence, endpoint.get("path", ""))


def _score_endpoints(endpoints: list[dict]) -> list[dict]:
    """Attach a coarse priority label so the report can be read without a sort step."""
    out = []
    for e in endpoints:
        params = e.get("params") or []
        methods = [m.upper() for m in (e.get("methods") or [])]
        write = any(m in ("POST", "PUT", "PATCH", "DELETE") for m in methods)
        if params and write:
            priority = "primary"        # has a body/query to fuzz and mutates state
        elif params:
            priority = "secondary"      # parameterised read
        elif write:
            priority = "secondary"
        else:
            priority = "inventory"      # enumerable, but nothing to vary
        out.append(dict(e, priority=priority))
    return sorted(out, key=_testability)


def _subdomain_assets(intel: dict | None) -> list[dict]:
    """CT-discovered hosts as first-class assets, with `probed: false` on every entry.

    They are deliberately *not* scanned: the tool's contract is one host per run, and
    probing every certificate name would turn a recon pass into a list-wide scan. Listing
    them means an operator sees the real surface and can decide, instead of the subdomain
    count being a number with no source behind it.
    """
    ct = ((intel or {}).get("ct") or {})
    if ct.get("status") != "ok":
        return []
    source = ct.get("source", "ct")
    out = []
    for host in ct.get("subdomains") or []:
        host = str(host or "").strip()
        if not host:
            continue
        out.append({"host": host, "url": f"https://{host}/", "source": source,
                    "passive": True, "probed": False,
                    "first_cert": ct.get("first_cert", ""), "last_cert": ct.get("last_cert", "")})
    return out


def _probe_stats(session, js: dict | None = None) -> dict:
    """What the *active* side actually did: per-status counts, blocks, errors.

    The profile scores "how hard is this" partly on evidence the target produced in reply
    (a 403 challenge, a 429 throttle). That evidence is only trustworthy if the number of
    requests is visible next to it, so both travel together here.
    """
    by_status: dict[str, int] = {}
    for entry in (getattr(session, "log", None) or []):
        key = str(entry.get("status", 0))
        by_status[key] = by_status.get(key, 0) + 1
    ordered = dict(sorted(by_status.items(), key=lambda kv: (-kv[1], kv[0])))
    blocked = sum(n for code, n in by_status.items()
                  if code in ("401", "403", "405", "406", "429", "503"))
    throttled = by_status.get("429", 0)
    requests = int(getattr(session, "requests", 0) or 0)
    stats = js or {}
    return {
        "requests": requests,
        "by_status": ordered,
        "blocked": blocked,
        "throttled": throttled,
        "blocked_pct": round(blocked / requests * 100.0, 1) if requests else 0.0,
        "errors": len(getattr(session, "errors", None) or []),
        "scope_blocks": len(getattr(session, "off_scope_attempts", None) or []),
        "bytes": int(getattr(session, "bytes_total", 0) or 0),
        "js_fetched": int((stats.get("stats") or {}).get("fetched", 0) or 0),
    }

def _scrub_findings(items: list[dict]) -> list[dict]:
    """Findings carry a raw header block as their evidence snippet; redact it in place.

    The snippet is the *reason* a reader can check a header claim offline, so it has to stay.
    What it must not carry is the credential lines inside it — `authorization:` and
    `set-cookie:` used to arrive verbatim through this path even after the header map itself
    was scrubbed.
    """
    out = []
    for item in items or []:
        finding = dict(item)
        finding["detail"] = scrub_header_block(finding.get("detail", ""))
        evidence = []
        for ev in finding.get("evidence") or []:
            entry = dict(ev)
            if isinstance(entry.get("snippet"), str):
                entry["snippet"] = scrub_header_block(entry["snippet"])
            if isinstance(entry.get("value"), str):
                entry["value"] = redact_header(str(entry.get("name", "")), entry["value"])
            evidence.append(entry)
        finding["evidence"] = evidence
        out.append(finding)
    return scrub_urls(out)


def _scrub_hypothesis(item: dict) -> dict:
    """Hypotheses quote findings; the quote must not reintroduce a credential."""
    out = dict(item)
    for key in ("detail", "success_signal", "precondition"):
        if isinstance(out.get(key), str):
            out[key] = scrub_header_block(out[key])
    return scrub_urls(out)


def assemble(*, domain, root_url, profile_name, limits, web, dns, crawl_result, js, api,
             findings, hyp, session, started_at, elapsed, probe_status,
             intel: dict | None = None, authorized_by: str = "") -> dict:
    sourcemaps = [s["sourcemap"] for s in js.get("scripts", []) if s.get("sourcemap")]
    # Passive assets and active-probe telemetry are computed once, here, so every consumer
    # (markdown, brief, console, compare view) reads the same numbers.
    subdomains = _subdomain_assets(intel)
    probe_stats = _probe_stats(session, js)
    deps = doctormod.versions()
    assets = {
        "technology": web.get("tech", []),
        # Raw response headers are the evidence base for every header claim. Keeping them
        # makes each finding auditable offline instead of pointing at "response headers".
        #
        # They are also the one place a live session credential used to reach the report:
        # `Set-Cookie` arrived verbatim. Names stay (their presence *is* the finding), values
        # are replaced with `[redacted:<sha12>:len=n]` — enough to prove identity, useless
        # for replay. Cookie attributes survive so `HttpOnly`/`Secure` analysis still works.
        "http": {
            "root_url": scrub_urls(web.get("root_url", "")),
            "status": web.get("status", 0),
            "final_url": scrub_urls(web.get("final_url", "")),
            "redirect_chain": scrub_urls(web.get("redirect_chain", [])),
            "headers": scrub_headers(web.get("headers", {})),
            "security": web.get("security", {}),
            "cookies": web.get("cookies", []),
            "tls": web.get("tls", {}),
        },
        "scripts": [{"url": scrub_urls(s["url"]), "bytes": s.get("bytes", 0),
                     "sha256": s.get("sha256", ""),
                     "status": s.get("status"),
                     # A script that failed to download must say why; `bytes: 0` alone reads
                     # as "empty file" and hides a 403 or a scope refusal.
                     "error": s.get("error", ""),
                     "sourcemap_leaks": bool((s.get("sourcemap") or {}).get("leaks_original_source")),
                     "minified": s.get("minified", False), "artifact": s.get("artifact", ""),
                     "pretty_artifact": s.get("pretty_artifact", ""),
                     "sourcemap": bool(s.get("sourcemap"))} for s in js.get("scripts", [])],
        "hosts": js.get("hosts", []),
        "subdomains": subdomains,
        "forms": crawl_result.get("forms", []),
        "pages": [{"url": scrub_urls(p["url"]), "status": p["status"], "title": p["title"],
                   "depth": p["depth"]} for p in crawl_result.get("pages", [])],
        "cookies": web.get("cookies", []),
        "tls": web.get("tls", {}),
        "dns": dns,
        "well_known": web.get("well_known", {}),
        "chunks": js.get("chunks", []),
    }
    # Everything that quotes the response is scrubbed here, once, before it enters the report.
    findings = _scrub_findings(findings)
    hyp = [_scrub_hypothesis(item) for item in (hyp or [])]
    endpoints = js.get("endpoints", [])
    for spec in api.get("specs", []):
        endpoints.extend(spec["endpoints"])
    endpoints.sort(key=lambda e: (e["path"], e.get("confidence", "")))
    for i, endpoint in enumerate(endpoints, 1):
        endpoint["id"] = f"E-{i:04d}"

    report = {
        "schema": SCHEMA_ID,
        "meta": {
            "tool": "recon-one", "tool_version": VERSION, "generated_at": now_iso(),
            "started_at": started_at, "profile": profile_name, "limits": limits,
            "elapsed_seconds": round(elapsed, 1),
            "requests": session.requests, "bytes": session.bytes_total,
            "scope_blocks": len(session.off_scope_attempts),
            "deps": deps,
            "probe_stats": probe_stats,
            "redaction": redactmod.scope_note(),
            "egress": httpmod.egress_view(session),
            # The premises this run rested on, recorded rather than assumed. `authorized_by`
            # is free text (ticket id, contract reference, pentest window) so an auditor can
            # tie the package to the paper that allowed it.
            "authorization": {
                "notice_version": AUTHORIZED_USE_VERSION,
                "notice": AUTHORIZED_USE,
                "summary": AUTHORIZED_USE_SHORT,
                "premises": list(AUTHORIZED_USE_PREMISES),
                "authorized_by": (authorized_by or "").strip()[:200],
                "declared": bool((authorized_by or "").strip()),
            },
        },
        "target": {"domain": domain, "root_url": root_url,
                   "https": web.get("https_available", False),
                   "status": web.get("status", 0), "title": web.get("title", "")},
        "coverage": {
            "probes": probe_status,
            "counts": {
                "pages": len(assets["pages"]), "scripts": len(assets["scripts"]),
                "endpoints": len(endpoints), "parameters": len(api.get("parameters", [])),
                "secrets": len(js.get("secrets", [])), "findings": len(findings),
                "hypotheses": len(hyp), "sourcemaps": len(sourcemaps),
                "specs": len(api.get("specs", [])),
                "graphql": len((api.get("graphql") or {}).get("endpoints", [])),
                "subdomains": len(subdomains),
                "endpoints_testable": sum(1 for e in endpoints if e.get("params")),
                "endpoints_write": sum(
                    1 for e in endpoints
                    if any(m.upper() in ("POST", "PUT", "PATCH", "DELETE")
                           for m in (e.get("methods") or []) if m)),
            },
            "complete": all(v == "ok" for v in probe_status.values()),
            "truncated": bool(session.exhausted or any(s.get("bytes", 0) for s in js.get("scripts", []))
                              and js.get("stats", {}).get("fetched", 0) < js.get("stats", {}).get("requested", 0)),
        },
        "assets": assets,
        # Ranked, not discovery order: parameterised write endpoints first. The table is
        # what a reader actually works through, so its order has to carry the triage.
        "endpoints": _score_endpoints(endpoints),
        "parameters": api.get("parameters", []),
        "secrets": js.get("secrets", []),
        "specs": [{k: v for k, v in s.items() if k != "endpoints"} for s in api.get("specs", [])],
        "graphql": (api.get("graphql") or {}).get("endpoints", []),
        "findings": findings,
        "hypotheses": hyp,
        # Error records carry URLs: a failed request to `https://u:p@host/?token=…` would
        # otherwise paste credentials into the report through the back door.
        "errors": scrub_urls(session.errors),
        "artifacts": [],
    }
    # Scoring is a pure function of the assembled report, so it can be recomputed offline
    # from report.json alone — no re-scan needed to audit or re-weight a score.
    report["score"] = scoremod.score_report(report)
    # Passive intel and the target profile are attached last, but *before* the digest, so a
    # reader can verify the whole package with one hash.
    report["intel"] = intel or {}
    # Fifth redaction layer: a shape-based sweep over the *whole* report, so fields added
    # later (JS-derived host URLs, third-party archive rows, well-known bodies) are covered
    # by default. Runs before the profile/digest so every derived artefact sees masked text.
    report = redactmod.scrub_report(report)
    report["profile"] = triagemod.build(report, report["intel"])
    report["meta"]["deterministic_digest"] = sha256_text(
        canonical_json(_digest_view(report)))[:16]
    return report


# `date` is regenerated per response; including it would make "same target, same digest"
# false by construction. The constant lives in util so score.py cannot drift from it.


def _stable_intel(intel) -> dict:
    """Observed values only: drop fetch timestamps and error text (volatile by nature)."""
    if not isinstance(intel, dict):
        return {}
    out = {}
    for key, node in intel.items():
        if isinstance(node, dict):
            out[key] = {k: v for k, v in node.items() if k not in ("fetched_at", "reason")}
        else:
            out[key] = node
    return out


def _stable_profile(prof) -> dict:
    """Keep the verdict and the check outcomes; drop prose that quotes network errors."""
    if not isinstance(prof, dict):
        return {}
    view = {k: v for k, v in prof.items()
            if k not in ("checks", "dimensions", "assumptions", "disclaimer")}
    view["checks"] = [{k: c.get(k) for k in ("id", "axis", "status", "weight", "earned")}
                      for c in (prof.get("checks") or [])]
    dims = prof.get("dimensions") or {}
    view["dimensions"] = {
        key: ({k: v for k, v in node.items() if k != "reason"} if isinstance(node, dict) else node)
        for key, node in dims.items()
    }
    return view


def _digest_view(report: dict) -> dict:
    """The report as it enters the determinism digest.

    Intel and the profile are third-party observations: their timestamps and error strings
    change between two scans of an unchanged target, so only their stable projection enters
    the digest. Everything that describes the target itself stays verbatim.
    """
    view = {k: v for k, v in report.items() if k not in ("meta", "intel", "profile")}
    # `probe_stats` counts *our* requests and `deps` describes this machine: both are
    # properties of the run, not of the target, and both can differ by a few units between
    # two scans of an unchanged site. They stay out of the digest so "same target, same
    # digest" keeps meaning what it says.
    view["meta"] = {kk: vv for kk, vv in report["meta"].items()
                    if kk not in ("generated_at", "started_at", "elapsed_seconds",
                                  "probe_stats", "deps", "authorization", "egress")}
    # Who was authorised to look is not a property of the target: two operators scanning the
    # same site with different paperwork must digest the same. The notice version stays, so a
    # change in the wording of the notice is still visible in the digest.
    auth = (report["meta"].get("authorization") or {})
    if auth:
        view["meta"]["authorization"] = {"notice_version": auth.get("notice_version", "")}
    if "intel" in report:
        view["intel"] = _stable_intel(report.get("intel"))
    if "profile" in report:
        view["profile"] = _stable_profile(report.get("profile"))
    headers = ((view.get("assets") or {}).get("http") or {}).get("headers")
    if isinstance(headers, dict) and headers:
        assets = view["assets"]
        view["assets"] = {
            **assets,
            "http": {**assets["http"],
                     "headers": {k: v for k, v in headers.items()
                                 if k.lower() not in VOLATILE_HEADERS}},
        }
    return view


def _score_markdown(report: dict) -> list[str]:
    """Score section for the human-readable report.

    Publishes the denominator with every percentage and lists the checks that could not be
    evaluated, so a reader can reproduce or contest the number instead of trusting it.
    """
    block = report.get("score") or {}
    if not block:
        return []
    lines = ["", "## 量化评估", ""]
    axes = block.get("axes") or {}
    lines += ["| 轴 | 分数 | 等级 | 覆盖率 | 已判定 | 得分/可得分权重 |", "|---|---|---|---|---|---|"]
    for key, label in (("hygiene", "维护水平"), ("opportunity", "可评估机会")):
        a = axes.get(key) or {}
        pct = a.get("score")
        lines.append("| {} | {} | {} | {}% | {}/{} | {:g}/{:g} |".format(
            label,
            "—" if pct is None else f"{pct:.1f}",
            a.get("grade") or "—",
            f"{a.get('coverage_pct', 0):.0f}",
            a.get("checks_evaluated", 0), a.get("checks_total", 0),
            a.get("earned_weight", 0), a.get("evaluated_weight", 0)))
    lines += ["", f"**{block.get('summary', '')}**", ""]
    verdict = block.get("triage") or {}
    if verdict:
        lines += ["---", "", f"## ⚠ 结论：{verdict.get('label', '')}", "",
                  verdict.get("why", ""), ""]
        if verdict.get("actions"):
            lines += ["**建议动作**", ""] + [f"1. {a}" for a in verdict["actions"]] + [""]
        if verdict.get("blind_spots"):
            lines += ["> **本评分的不覆盖范围（必须先读）**", ">"]
            lines += [f"> - {b}" for b in verdict["blind_spots"]]
            lines += ["", "> 完整结论：外围配置分**不能**用于判断鉴权、租户隔离、"
                          "容器/沙箱边界或业务逻辑的强度。这些必须实测。", ""]
        if verdict.get("drivers"):
            lines += ["判定依据（引用的检查项）：", ""] + \
                     [f"- `{d}`" for d in verdict["drivers"]] + [""]
        lines += ["---", ""]

    unknown = [c for c in (block.get("checks") or []) if c.get("status") == "unknown"]
    if unknown:
        lines += ["未采集项（不计分、也不视为通过 —— 这些是评估的真空区）：", ""]
        lines += [f"- `{c['id']}` {c['title']}：{c['detail']}" for c in unknown]
        lines += [""]

    failing = [c for c in (block.get("checks") or [])
               if c.get("status") in ("fail", "warn")]
    if failing:
        lines += ["失分项（按权重降序，权重与依据可复核）：", "",
                  "| 检查项 | 判定 | 权重 | 依据 | 评分基准 |", "|---|---|---|---|---|"]
        for c in sorted(failing, key=lambda x: -x.get("weight", 0)):
            lines.append(f"| `{c['id']}` | {c['status']} | {c.get('weight', 0):g} | "
                         f"{(c.get('detail') or '').replace('|', '/')[:120]} | {c.get('source', '')} |")
        lines += [""]
    if block.get("disclaimer"):
        lines += ["> " + block["disclaimer"], ""]
    return lines


def _profile_markdown(report: dict) -> list[str]:
    """Target profile: worth / hardness / opportunity window, with provenance per row."""
    prof = report.get("profile") or {}
    if not prof:
        return []
    axes = prof.get("axes") or {}
    succ = prof.get("success") or {}
    dims = prof.get("dimensions") or {}
    worth = axes.get("worth") or {}
    hard = axes.get("hardness") or {}
    site = (dims.get("site_type") or {})
    geo = (dims.get("geo") or {})
    subs = (dims.get("subdomains") or {})
    hist = (dims.get("history") or {})
    cve = (dims.get("cve_hints") or {})
    def _score(axis: dict) -> str:
        value = axis.get("score")
        return "—" if value is None else f"{value}"

    def _cell(node: dict, ok_text: str) -> str:
        """Show the value when observed, otherwise the honest status (never a fake zero)."""
        status = node.get("status") or "unavailable"
        if status in ("ok", "empty"):
            return ok_text
        reason = node.get("reason") or ("未启用" if status == "disabled" else "")
        return status + (f"：{reason}" if reason else "")

    place = [str(x) for x in (geo.get("country"), geo.get("city"), geo.get("asn")) if x]
    if geo.get("isp") and geo["isp"] not in " ".join(place):
        place.append(str(geo["isp"]))
    site_ok = ("unknown（未命中任何站点特征）" if site.get("status") == "empty"
               else f"{site.get('primary')}（{site.get('source', '')}）")
    window = ("withheld（覆盖率不足，不出结论）" if succ.get("index") is None
              else f"{succ.get('index')} · {succ.get('band')}（{succ.get('label')}）")
    subs_ok = f"{subs.get('count', 0)} 个（{subs.get('source', '')}）"
    hist_ok = (f"{hist.get('snapshots', 0)} 条快照，"
               f"{hist.get('first') or '?'} → {hist.get('last') or '?'}")
    cve_ok = f"{len(cve.get('hits') or [])} 条"
    lines = [
        "", "## 目标画像（被动情报 + 规则判定，无 AI）", "",
        "| 维度 | 值 |", "|---|---|",
        f"| 价值（是否值得测） | {_score(worth)} / 100（覆盖 {worth.get('coverage_pct')}%） |",
        f"| 难度（是否容易打） | {_score(hard)} / 100（覆盖 {hard.get('coverage_pct')}%） |",
        f"| 机会窗口 | {window} |",
        f"| 网站类型 | {_cell(site, site_ok)} |",
        f"| 地理位置 | {_cell(geo, ' / '.join(place))} |",
        f"| 子域 | {_cell(subs, subs_ok)} |",
        f"| 历史存档 | {_cell(hist, hist_ok)} |",
        f"| CVE 线索 | {_cell(cve, cve_ok)} |",
        "",
        "> " + (prof.get("disclaimer") or ""),
        "",
    ]
    unknown = (prof.get("coverage") or {}).get("unknown") or []
    if unknown:
        lines += ["未判定项（既不计分也不视为通过）：" + "、".join(f"`{u}`" for u in unknown), ""]
    return lines


def _authorization_markdown(report: dict) -> list[str]:
    """The notice, verbatim, at the top of the human-readable report.

    A report gets forwarded, archived and pasted into tickets; the person reading it is often
    not the person who ran the scan. So the premises travel with the data instead of living
    only in a README that nobody opens.
    """
    auth = ((report.get("meta") or {}).get("authorization") or {})
    if not auth:
        return []
    by = auth.get("authorized_by") or ""
    lines = ["## 授权声明", "", "> " + (auth.get("notice") or AUTHORIZED_USE), "",
             f"- 授权依据：{by if by else '**未声明**（运行时未提供 --authorized-by）'}",
             f"- 声明版本：{auth.get('notice_version', '?')}",
             "- 使用前提："]
    lines += [f"  {i}. {item}" for i, item in enumerate(auth.get("premises") or [], 1)]
    lines += ["", "本报告中的数据（端点、密钥线索、历史路径、子域）按授权范围保密；"
                  "泄露给未获授权的第三方可能同时构成违约与违法。", ""]
    return lines


def render_markdown(report: dict) -> str:
    t = report["target"]
    c = report["coverage"]["counts"]
    lines = [f"# recon-one 报告：{t['domain']}", "",
             f"- 根地址：{t['root_url']}（HTTP {t['status']}）",
             f"- 生成时间：{report['meta']['generated_at']}，耗时 {report['meta']['elapsed_seconds']}s",
             f"- 请求数 {report['meta']['requests']}，字节 {report['meta']['bytes']}",
             f"- 覆盖完整：{report['coverage']['complete']}，截断：{report['coverage']['truncated']}", ""]
    lines += _authorization_markdown(report)
    lines += ["## 覆盖计数", "",
              "| 项 | 数量 |", "|---|---|"]
    for key, value in c.items():
        lines.append(f"| {key} | {value} |")
    lines += _score_markdown(report)
    lines += _profile_markdown(report)
    lines += ["", "## 技术栈", ""]
    lines += [f"- {tech['name']}（{', '.join(tech['evidence'])}）" for tech in report["assets"]["technology"]] or ["- 未识别"]
    lines += ["", "## 发现", "", "| ID | 级别 | 类别 | 标题 |", "|---|---|---|---|"]
    for f in report["findings"][:60]:
        lines.append(f"| {f['id']} | {f['severity']} | {f['category']} | {f['title']} |")
    lines += ["", "## 端点（按置信度）", "", "| 路径 | 方法 | 置信度 | 参数 |", "|---|---|---|---|"]
    for e in report["endpoints"][:80]:
        lines.append(f"| `{e['path']}` | {','.join(e['methods'])} | {e.get('confidence', '')} | "
                     f"{','.join(e.get('params', []))} |")
    lines += ["", "## 假设（按优先级）", ""]
    for h in report["hypotheses"][:12]:
        blocked = "（需额外访问）" if h["blocked"] else ""
        lines.append(f"{h['rank']}. **{h['title']}**{blocked} — 得分 {h['priority_score']}，"
                     f"成本 {h['cost_minutes']}min，增益 {h['information_gain']}/5")
    if report["errors"]:
        lines += ["", "## 错误分类", "", "| 类型 | 数量 |", "|---|---|"]
        kinds: dict[str, int] = {}
        for err in report["errors"]:
            kinds[err["kind"]] = kinds.get(err["kind"], 0) + 1
        lines += [f"| {k} | {v} |" for k, v in sorted(kinds.items())]
    return "\n".join(lines) + "\n"


def render_handoff(report: dict) -> str:
    """The document an operator or an agent reads first: what is known, what is not, what next."""
    counts = report["coverage"]["counts"]
    hyp = report["hypotheses"]
    blocked = [h for h in hyp if h["blocked"]]
    ready = [h for h in hyp if not h["blocked"]]
    lines = [
        f"# HANDOFF — {report['target']['domain']}",
        "",
        "## 0. 使用约定",
        f"- 报告 schema：`{report['schema']}`；机器读取请用 `report/report.json`，不要解析本文件。",
        f"- 资产哈希见 `report/manifest.json`；原始证据在 `raw/`，端点证据带 file+offset。",
        "- 本文件是决策摘要：只列出已确认事实、未知项与建议的下一步。",
        f"- **授权**：{((report.get('meta') or {}).get('authorization') or {}).get('summary', AUTHORIZED_USE_SHORT)}"
        f" 依据：{(((report.get('meta') or {}).get('authorization') or {}).get('authorized_by')) or '未声明'}。",
        "",
        "## 1. 已确认事实（可直接采信）",
        f"- 目标可达：{report['target']['root_url']}，HTTP {report['target']['status']}，标题「{report['target']['title']}」。",
        f"- 爬取 {counts['pages']} 页，脚本 {counts['scripts']} 个，端点 {counts['endpoints']} 个，参数 {counts['parameters']} 个。",
        f"- 前端密钥 {counts['secrets']} 个（报告中已脱敏，原文仅在 raw/ 内，注意保管）。",
        f"- API 规范 {counts['specs']} 份，GraphQL 端点 {counts['graphql']} 个，source map {counts['sourcemaps']} 份。",
    ]
    tech = ", ".join(t["name"] for t in report["assets"]["technology"][:12])
    if tech:
        lines.append(f"- 技术栈：{tech}")
    lines += ["", "## 2. 未覆盖与不确定项（不要当成结论）", ""]
    for name, status in sorted(report["coverage"]["probes"].items()):
        if status != "ok":
            lines.append(f"- `{name}`：{status}")
    if report["coverage"]["truncated"]:
        lines.append("- 本次扫描触达预算上限（字节/时间），结果不完整。")
    lines += [
        "- 无认证态：所有结果均为匿名视角，登录后的功能面未测绘。",
        "- 未做漏洞验证：本程序只测绘与推断，不发送攻击载荷。",
        "",
        "## 3. 建议动作（按 优先级得分 排序，blocked=True 需先取得访问条件）",
        "",
        "| # | 动作 | 得分 | 成本 | 增益 | 需要 | 阻塞 |",
        "|---|---|---|---|---|---|---|",
    ]
    for h in hyp[:12]:
        lines.append(f"| {h['rank']} | {h['title']} | {h['priority_score']} | {h['cost_minutes']}min | "
                     f"{h['information_gain']}/5 | {'；'.join(h['requires'])} | {'是' if h['blocked'] else '否'} |")
    lines += ["", "### 立即可执行（无额外前置条件）", ""]
    if ready:
        for h in ready[:5]:
            lines.append(f"- **{h['id']} {h['title']}** — 成功信号：{h['success_signal']}")
            for step in h["verify"]:
                lines.append(f"  - {step}")
    else:
        lines.append("- 无。本次未产出可独立执行的假设（目标无 API 面、无管理路径、无凭据线索），"
                     "扩展侦察不会增加信息量，应转入人工确认测试条件。")
    lines += ["", "### 需先取得访问条件", ""]
    if blocked:
        for h in blocked[:5]:
            lines.append(f"- **{h['id']} {h['title']}** — 需要：{'；'.join(h['requires'])}")
    else:
        lines.append("- 无。")
    lines += ["", "## 4. 停机条件", "",
              "- 顶层 `ready` 列表为空且 `blocked` 全部依赖同一主体（如缺少测试账号）→ 停止扩展侦察，向委托方索要条件。",
              "- 若某动作连续两次未改变任何假设状态，标记为低价值并跳过。", ""]
    return "\n".join(lines)


def write_all(report: dict, out_dir: str) -> dict:
    # The package root is the directory that *contains* report/ and raw/. Normalising here
    # means manifest paths are always relative to the run directory, even if a caller hands
    # us the package subdirectory or a path with a trailing separator.
    out_dir = os.path.abspath(out_dir)
    if os.path.basename(out_dir) in ("report", "raw"):
        out_dir = os.path.dirname(out_dir)
    report_dir = os.path.join(out_dir, "report")
    os.makedirs(report_dir, exist_ok=True)
    paths = {}

    def dump(name, text):
        path = os.path.join(report_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        paths[name] = path
        return path

    dump("report.json", json.dumps(report, ensure_ascii=False, indent=1, sort_keys=False) + "\n")
    dump("report.md", render_markdown(report))
    dump("handoff.md", render_handoff(report))
    dump("schema.json", json.dumps(SCHEMA, ensure_ascii=False, indent=1) + "\n")
    with open(os.path.join(report_dir, "endpoints.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
        for endpoint in report["endpoints"]:
            fh.write(json.dumps(endpoint, ensure_ascii=False) + "\n")
    with open(os.path.join(report_dir, "findings.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
        for finding in report["findings"]:
            fh.write(json.dumps(finding, ensure_ascii=False) + "\n")
    with open(os.path.join(report_dir, "hypotheses.jsonl"), "w", encoding="utf-8", newline="\n") as fh:
        for hypothesis in report["hypotheses"]:
            fh.write(json.dumps(hypothesis, ensure_ascii=False) + "\n")
    # Only this run's artifacts belong in the manifest. Walking out_dir blindly would pull in
    # stale raw/js and raw/maps from a previous scan into the same --out directory, which breaks
    # the "same target, same manifest" promise without changing deterministic_digest.
    run_started = report["meta"].get("started_at") or ""
    artifacts = []
    for root, _dirs, files in os.walk(out_dir):
        for filename in files:
            full = os.path.join(root, filename)
            rel = os.path.relpath(full, out_dir).replace("\\", "/")
            if rel.startswith("report/manifest.json"):
                continue
            if rel.startswith("raw/"):
                try:
                    mtime = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(full)))
                except OSError:
                    mtime = run_started
                if run_started and mtime < run_started:
                    continue          # left over from an earlier scan
            if rel.startswith("raw/js/"):
                # A hash of a file containing live secrets is an offline oracle: exclude it.
                artifacts.append({"path": rel, "bytes": os.path.getsize(full), "sha256_16": "redacted"})
                continue
            with open(full, "rb") as fh:
                digest = sha256_text(fh.read().decode("utf-8", "replace"))[:16]
            artifacts.append({"path": rel, "bytes": os.path.getsize(full), "sha256_16": digest})
    manifest = {
        "tool": "recon-one", "tool_version": VERSION, "schema": SCHEMA_ID,
        "generated_at": report["meta"]["generated_at"],
        "deterministic_digest": report["meta"].get("deterministic_digest"),
        "target": report["target"]["domain"],
        "counts": report["coverage"]["counts"],
        "artifacts": sorted(artifacts, key=lambda a: a["path"]),
        "validation": {"schema_errors": validate(report)},
    }
    dump("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1) + "\n")
    return paths
