"""AI-facing recon brief: condense a report package into one budget-bounded Markdown block.

Why this exists
---------------
A structured JSON report is the right *machine* source of truth, but an agent's first
turn is spent guessing what to look at. Field experience (and the way ARTEX consumes a
task description) shows the same thing: hand the model the whole public surface up
front and its first move stops being "scan the frontend again".

So this module renders the opposite view of the same facts: a single narrative block,
ordered by decision value, truncated by a hard character budget, with an explicit
"already done, do not repeat" section.

Constraints honoured
--------------------
* Output starts with a bare target line so host-extracting parsers (ARTEX's
  seed()/parseTarget) pick up the domain, not a file name from a bullet list.
* Nothing here is inferred: every claim comes from the report dict. Secrets stay
  masked; raw evidence is only referenced by path.
* Truncation is deterministic and reported ("omitted N of M") so an agent knows the
  brief is partial rather than complete.
"""
from __future__ import annotations

from .util import clip

DEFAULT_BUDGET = 14_000          # ARTEX task description caps at 16,000 runes
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CONF_ORDER = {"high": 0, "medium": 1, "low": 2}
PRIORITY_ORDER = {"primary": 0, "secondary": 1, "inventory": 2}


class _Budget:
    """Append-only writer that refuses to exceed a character budget."""

    def __init__(self, limit: int):
        self.limit = limit
        self.lines: list[str] = []
        self.used = 0
        self.dropped = 0

    def add(self, text: str, count_drop: int = 1) -> bool:
        cost = len(text) + 1
        if self.used + cost > self.limit:
            self.dropped += count_drop
            return False
        self.lines.append(text)
        self.used += cost
        return True

    def room(self) -> int:
        return max(0, self.limit - self.used)


def _num(value) -> str:
    """Render a profile score; `?` when the rule table refused to score (coverage gap)."""
    if value is None:
        return "?"
    return f"{float(value):.1f}"


def _with_priority(endpoints: list[dict]) -> list[dict]:
    """Backfill the priority label for reports written before it existed.

    Older packages on disk carry no `priority` field. Without this the whole table would
    sink to `inventory` and the brief would silently lose its triage, which is the one
    thing that makes it worth more than the raw JSON.
    """
    out = []
    for e in endpoints:
        if e.get("priority"):
            out.append(e)
            continue
        params = e.get("params") or []
        methods = [m.upper() for m in (e.get("methods") or []) if m]
        write = any(m in ("POST", "PUT", "PATCH", "DELETE") for m in methods)
        if params and write:
            priority = "primary"
        elif params or write:
            priority = "secondary"
        else:
            priority = "inventory"
        out.append(dict(e, priority=priority))
    return out


def _endpoint_rows(report: dict, limit: int) -> tuple[list[str], int]:
    """Table rows, most-testable first.

    Ordering by priority (not discovery order, not confidence alone) is what makes the
    table usable: a bundle yields far more parameterless GET routes than anything an
    operator can actually vary, and those are inventory, not leads.
    """
    eps = sorted(
        _with_priority(report.get("endpoints") or []),
        key=lambda e: (PRIORITY_ORDER.get(e.get("priority", "inventory"), 2),
                       CONF_ORDER.get(e.get("confidence", "low"), 2), e.get("path", "")),
    )
    rows = []
    for e in eps[:limit]:
        methods = ",".join(e.get("methods") or ["GET?"])
        params = ", ".join(e.get("params") or []) or "-"
        prio = e.get("priority", "")
        rows.append(f"| `{e.get('path','')}` | {methods} | {prio} | {params} |")
    return rows, max(0, len(eps) - limit)


def _endpoint_mix(report: dict) -> str:
    """One line summarising how much of the endpoint inventory is actually testable."""
    eps = _with_priority(report.get("endpoints") or [])
    if not eps:
        return ""
    primary = sum(1 for e in eps if e.get("priority") == "primary")
    secondary = sum(1 for e in eps if e.get("priority") == "secondary")
    inventory = len(eps) - primary - secondary
    parts = []
    if primary:
        parts.append(f"{primary} 个可变异写端点（优先）")
    if secondary:
        parts.append(f"{secondary} 个可变异只读/无参写端点")
    if inventory:
        parts.append(f"{inventory} 个无参（仅清单）")
    return " / ".join(parts)


def build_brief(report: dict, budget: int = DEFAULT_BUDGET, report_dir: str = "") -> str:
    """Render the brief. Never raises on a sparse report; degrades to what exists."""
    t = report.get("target") or {}
    counts = (report.get("coverage") or {}).get("counts") or {}
    assets = report.get("assets") or {}
    b = _Budget(budget)

    domain = t.get("domain") or "unknown"
    root = t.get("root_url") or f"https://{domain}/"

    # --- Header -----------------------------------------------------------------
    # Line 3 is the bare target on purpose: host extractors scan top-down and the
    # first match must be the real target, never a path from a bullet list.
    b.add(f"# 侦察简报：{domain}")
    b.add("")
    b.add(root)

    # --- 0. Contract ------------------------------------------------------------
    b.add("")
    b.add("## 0. 这份简报怎么用")
    b.add("- 下列信息**已由自动化侦察完成并带证据**，不要重复抓取、下载或逆向前端。")
    b.add("- 端点的 `偏移` 与原文片段在报告包的 `raw/` 内，需要复核时按报告目录定位。")
    b.add("- 「未覆盖」一节列出**确实没做**的事，那才是需要你投入的方向。")

    # --- 1. Profile: is it worth attacking, how hard, how good the odds ---------
    # Placed above the factual sections on purpose: an operator decides *whether* the
    # target deserves the time before deciding *where* to spend it. Nothing here is
    # inferred from prose - it is the rule table's own output, and a dimension the run
    # could not observe prints as unknown instead of vanishing.
    prof = report.get("profile") or {}
    if prof:
        b.add("")
        b.add("## 1. 目标画像（规则表算出，不是漏洞预测）")
        axes = prof.get("axes") or {}
        worth = axes.get("worth") or {}
        hard = axes.get("hardness") or {}
        succ = prof.get("success") or {}
        line = f"- 值得打 {_num(worth.get('score'))}/100 ｜ 难打 {_num(hard.get('score'))}/100 ｜ "
        if succ.get("index") is None:
            line += "机会指数 withheld（覆盖率不足，宁可不说）"
        else:
            line += (f"机会指数 {int(succ['index'])}/100 → {succ.get('band', '')}"
                     f"（{succ.get('label', '')}，区间 {succ.get('range')}；这是指数不是概率）")
        b.add(line)

        dims = prof.get("dimensions") or {}
        facts = []
        site = dims.get("site_type") or {}
        if site.get("primary") and site["primary"] != "unknown":
            facts.append(f"类型 {site['primary']}")
        sub = dims.get("subdomains") or {}
        if sub.get("status") == "ok":
            facts.append(f"子域 {sub.get('count', 0)} 个（{sub.get('source', '')}）")
        hist = dims.get("history") or {}
        if hist.get("status") == "ok":
            seg = f"存档 {hist.get('snapshots', 0)} 个快照"
            if hist.get("first"):
                seg += f"（{hist['first'][:10]} → {(hist.get('last') or '')[:10]}）"
            if hist.get("sensitive_paths"):
                seg += f"，历史敏感路径 {len(hist['sensitive_paths'])} 条"
            facts.append(seg)
        geo = dims.get("geo") or {}
        if geo.get("status") == "ok":
            where = [x for x in (geo.get("country"), geo.get("city"), geo.get("asn")) if x]
            isp = geo.get("isp") or ""
            if isp and isp not in " ".join(where):
                where.append(isp)
            if where:
                facts.append("位置 " + " / ".join(where))
        if facts:
            b.add("- " + "；".join(facts))

        cve = dims.get("cve_hints") or {}
        if cve.get("hits"):
            hits = ", ".join(f"{h.get('product', '')} {h.get('version', '')}→{h.get('id', '')}"
                             for h in cve["hits"][:3])
            b.add(f"- 版本 CVE 线索（只说明该版本被分配过 CVE，未验证可利用）：{hits}")

        split = prof.get("mode_split") or {}
        passive = split.get("passive") or []
        active = split.get("active") or []
        if passive or active:
            b.add(f"- 评分口径：被动 {len(passive)} 项（未向目标发包）/ 主动 {len(active)} 项")
            if passive:
                b.add("  - 被动：" + ", ".join(passive[:12]))

        cov = prof.get("coverage") or {}
        unknown = cov.get("unknown") or []
        if unknown:
            b.add(f"- 未观测（不计分，也不当作通过；覆盖率 {cov.get('combined_pct', 0)}%）："
                  + ", ".join(unknown))
        if prof.get("disclaimer"):
            b.add("")
            b.add(f"> {prof['disclaimer']}")

    # --- 2. Coverage: what was already done --------------------------------
    probes = (report.get("coverage") or {}).get("probes") or {}
    done = [k for k, v in probes.items() if v == "ok"]
    gaps = {k: v for k, v in probes.items() if v != "ok"}
    b.add("")
    b.add("## 2. 已完成的探测（勿重复）")
    if done:
        b.add(f"- 已完成：{', '.join(sorted(done))}")
    b.add(f"- 爬取 {counts.get('pages',0)} 页 / 脚本 {counts.get('scripts',0)} 个 / "
          f"端点 {counts.get('endpoints',0)} 个 / 参数 {counts.get('parameters',0)} 个")
    b.add(f"- 前端密钥 {counts.get('secrets',0)} / API 规范 {counts.get('specs',0)} 份 / "
          f"GraphQL {counts.get('graphql',0)} 个 / source map {counts.get('sourcemaps',0)} 份")
    if gaps:
        b.add("")
        b.add("**未覆盖（不要当作已排除，这些是真空区）**")
        for k in sorted(gaps):
            b.add(f"- `{k}`：{gaps[k]}")

    # --- 3. Target facts --------------------------------------------------------
    b.add("")
    b.add("## 3. 目标")
    bits = [f"HTTP {t.get('status', 0)}", f"HTTPS={t.get('https', False)}"]
    if t.get("title"):
        bits.append(f"标题「{clip(t['title'], 80)}」")
    b.add("- " + "，".join(bits))

    tech = assets.get("technology") or []
    if tech:
        names = ", ".join(f"{x['name']}({x.get('category','')})" for x in tech[:12])
        b.add(f"- 技术栈：{names}")

    # --- 4. Public surface: hosts / DNS / TLS ----------------------------------
    dns = (assets.get("dns") or {}).get("records") or {}
    hosts = assets.get("hosts") or []
    internal = [h for h in hosts if h.get("kind") == "internal"]
    external = [h for h in hosts if h.get("kind") == "external"]
    reference = [h for h in hosts if h.get("kind") == "reference"]
    if dns or internal or external:
        b.add("")
        b.add("## 4. 公开面资产")
        for rtype in ("A", "AAAA", "CNAME", "MX", "NS"):
            vals = dns.get(rtype) or []
            if vals:
                b.add(f"- {rtype}: {', '.join(vals[:6])}")
        tls = assets.get("tls") or {}
        if tls.get("san"):
            b.add(f"- 证书 SAN：{', '.join(tls['san'][:10])}")
        if tls.get("not_after"):
            b.add(f"- 证书有效期至：{tls['not_after']}（{tls.get('issuer', {}).get('O', '')}）")
        if internal:
            b.add("")
            b.add("**内部命名空间（前端 bundle 里出现，外网通常不可达）**")
            for h in internal[:8]:
                b.add(f"- `{h.get('url','')}`  ← {h.get('source','')}")
        if external:
            b.add("")
            b.add("**外部依赖主机**（CDN/SDK/第三方，通常不是攻击面，除非存在接管风险）")
            for h in external[:10]:
                b.add(f"- `{h.get('url','')}`")
        if reference:
            b.add("")
            b.add("**自引用地址**（指向访问者本机，不是目标内网）")
            for h in reference[:4]:
                b.add(f"- `{h.get('url','')}`  ← {h.get('source','')}")

    # --- 5. API surface: specs / graphql / endpoints ---------------------------
    specs = report.get("specs") or []
    gql = report.get("graphql") or []
    eps = report.get("endpoints") or []
    if specs or gql or eps:
        b.add("")
        b.add("## 5. API 面")
        for s in specs[:3]:
            b.add(f"- 规范：`{s.get('url','')}`（{s.get('kind','')}，{s.get('endpoint_count',0)} 个端点）")
            schemes = s.get("security_schemes") or []
            if schemes:
                b.add(f"  - 认证模型：{', '.join(x.get('type','') + '/' + (x.get('scheme') or '-') for x in schemes)}")
        for g in gql[:3]:
            b.add(f"- GraphQL：`{g.get('url','')}`（{g.get('type_count',0)} 个对象类型，introspection 开启）")

        if eps:
            b.add("")
            b.add("### 已知端点（按可测性排序）")
            mix = _endpoint_mix(report)
            if mix:
                b.add(f"共 {len(eps)} 个：{mix}。`优先` 行有参数或写方法，值得先测；"
                      "`清单` 行只是存在性证据，没有可变的输入。")
            b.add("| 路径 | 方法 | 优先级 | 参数 |")
            b.add("|---|---|---|---|")
            # Reserve room for later sections rather than spending it all here.
            reserve = 2_600
            room = max(600, b.room() - reserve)
            cap = max(3, room // 70)
            rows, dropped = _endpoint_rows(report, cap)
            for row in rows:
                if not b.add(row):
                    break
            if dropped:
                b.add(f"- …另有 {dropped} 个端点未列出（预算限制），完整列表见报告包")

    # --- 6. Parameters ----------------------------------------------------------
    params = report.get("parameters") or []
    if params:
        b.add("")
        b.add("## 6. 参数面")
        shown = []
        for p in params[:25]:
            eps_for = p.get("endpoints") or []
            if eps_for:
                shown.append(f"`{p['name']}`({p.get('in','')}) → {', '.join(eps_for[:2])}")
        for chunk_start in range(0, len(shown), 4):
            if not b.add("- " + "；".join(shown[chunk_start:chunk_start + 4])):
                break

    # --- 7. Findings + secrets --------------------------------------------------
    findings = sorted(
        report.get("findings") or [],
        key=lambda f: (SEVERITY_ORDER.get(f.get("severity", "info"), 9), f.get("id", "")),
    )
    secrets = report.get("secrets") or []
    if findings or secrets:
        b.add("")
        b.add("## 7. 风险与线索")
        for f in findings[:12]:
            if not b.add(f"- [{f.get('severity','')}] {f.get('title','')} — {clip(f.get('detail',''), 110)}"):
                break
        for s in secrets[:8]:
            b.add(f"- [密钥/{s.get('severity','')}] {s.get('type','')}：`{s.get('masked','')}`"
                  f"（长度 {s.get('length',0)}，sha256:{s.get('sha256_12','')}，原文仅在 raw/）")

    # --- 8. Next actions --------------------------------------------------------
    hyp = report.get("hypotheses") or []
    if hyp:
        b.add("")
        b.add("## 8. 建议下一步（按信息增益/成本排序）")
        for h in hyp[:8]:
            blocked = "（需先取得访问条件）" if h.get("blocked") else ""
            if not b.add(f"{h.get('rank','')}. **{h.get('title','')}**{blocked} "
                         f"— 成本 {h.get('cost_minutes',0)}min，增益 {h.get('information_gain',0)}/5"):
                break
            if not b.add(f"   - 成功信号：{clip(h.get('success_signal',''), 100)}"):
                break

    # --- 9. Where the raw material is -------------------------------------------
    if report_dir:
        b.add("")
        b.add("## 9. 报告包位置")
        b.add(f"- `{report_dir}\\report\\report.json` — 机器事实源（schema=recon-one/1）")
        b.add(f"- `{report_dir}\\report\\handoff.md` — 决策摘要")
        b.add(f"- `{report_dir}\\raw\\js\\` — 原始 bundle（密钥原文仅在此）")

    if b.dropped:
        b.add("")
        b.add(f"> 注意：受字符预算限制，本简报省略了约 {b.dropped} 条明细，"
              "完整内容以 report.json 为准。")

    return "\n".join(b.lines) + "\n"
