"""Command line interface: `scan`, `validate` and `ui`."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

from . import apiprobe, crawl as crawler, dns as dnsmod, egress as egressmod, hypotheses
from . import jsanalyze, report as reportmod
from . import brief as briefmod
from . import doctor as doctormod
from . import intel as intelmod
from . import verify as verifymod
from . import webprobe
from .config import (AUTHORIZED_USE, AUTHORIZED_USE_SHORT, PROFILES, RESERVED_RUN_NAMES,
                     VERSION, ensure_out_dir, find_existing_run, profile as load_profile,
                     run_dir_name)
from .http import Session
from .util import ensure_dir, now_iso


class ScanCancelled(Exception):
    """Raised from the progress callback so the GUI can abort between stages."""


_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)*)\b")


def _versioned_products(headers: dict) -> list[str]:
    """`nginx/1.24.0` → `nginx/1.24.0`, `PHP/7.4` → `PHP/7.4`; only when a version exists.

    CVE lookup is a keyword search, so feeding it a product without a version would return
    hundreds of unrelated hits. Two products max keeps the (rate-limited) NVD quiet.
    """
    out: list[str] = []
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        value = str((headers or {}).get(name, "") or "").strip()
        if value and _VERSION_RE.search(value):
            out.append(value.split("(")[0].strip()[:60])
    return out[:2]


def _is_ip_target(value: str) -> bool:
    """CT logs and the web archive index host names, not addresses: skip them for IPs."""
    try:
        ipaddress.ip_address(str(value or "").split(":")[0])
        return True
    except ValueError:
        return False


def _passive_endpoints(domain: str, web: dict, crawl_result: dict, intel: dict) -> list[dict]:
    """Endpoints that need no bundle download: links, forms, robots, sitemap, archive."""
    out: list[dict] = []
    crawl = crawl_result or {}
    out += jsanalyze.from_paths(crawl.get("links") or [], domain, "html-link")
    out += jsanalyze.from_paths([f.get("action") for f in crawl.get("forms") or []],
                                domain, "html-form")
    wkp = (web or {}).get("well_known") or {}
    out += jsanalyze.from_paths((wkp.get("/robots.txt") or {}).get("disallow") or [],
                                domain, "robots")
    out += jsanalyze.from_paths((wkp.get("/sitemap.xml") or {}).get("locations") or [],
                                domain, "sitemap")
    archive = (intel or {}).get("archive") or {}
    if archive.get("status") == "ok":
        out += jsanalyze.from_paths(archive.get("paths") or [], domain, "wayback")
    return jsanalyze.merge_endpoints([], out)


def _normalise_domain(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return ""
    return value.strip("/.")


def _guard_run_dir(domain: str, out_dir: str) -> dict | None:
    """Return a refusal report if `out_dir` must not be written, else None.

    Two hazards this catches, both seen in practice:

    * The directory already contains a report for a *different* target. Reusing it merges
      two packages and makes report/raw/report a blend of both runs.
    * The directory name is a reserved package name ("raw"/"report"). The package would
      then nest inside itself.
    """
    name = os.path.basename(os.path.abspath(out_dir))
    reserved = {n.lower() for n in RESERVED_RUN_NAMES}
    existing = os.path.join(out_dir, "report", "report.json")
    reason = ""
    if name.lower() in reserved:
        reason = f"输出目录名 `{name}` 与报告包内部目录冲突（raw/report 为保留名）"
    elif os.path.isfile(existing):
        try:
            with open(existing, "r", encoding="utf-8") as fh:
                prior = (json.load(fh).get("target") or {}).get("domain", "")
        except (OSError, ValueError):
            prior = ""
        if prior and prior.lower() != (domain or "").lower():
            reason = (f"输出目录已存有其它目标 `{prior}` 的报告，拒绝写入以免两个包混在一起"
                      f"（建议使用 {os.path.join(os.path.dirname(out_dir), run_dir_name(domain))}）")
    if not reason:
        return None
    return {
        "schema": "recon-one/1", "refused": True, "reason": reason,
        "target": {"domain": domain}, "out_dir": out_dir,
        "exists": sorted(os.listdir(out_dir))[:20] if os.path.isdir(out_dir) else [],
    }


def run_scan(domain: str, out_dir: str, profile_name: str = "default", overrides: dict | None = None,
             allow_external: bool = False, verify_tls: bool = True, use_dns: bool = True,
             use_graphql: bool = True, quiet: bool = False,
             on_event=None, cancel=None, use_js: bool = True, use_intel: bool = True,
             geo: bool = False, cve: bool = False, authorized_by: str = "",
             egress=None, use_verify: bool = True,
             verify_max: int = verifymod.DEFAULT_MAX_REQUESTS) -> tuple[dict, int]:
    """Run every probe once. `on_event` receives stage dicts; `cancel` is polled between stages.

    `use_js=False` skips bundle download + JS analysis entirely: endpoints then come from
    links, forms, robots, sitemap and the web archive — no frontend reverse engineering.
    `use_intel=False` stops the passive third-party lookups (CT logs, archive, geo, CVE).
    """
    limits = load_profile(profile_name)
    for key, value in (overrides or {}).items():
        if value is not None:
            limits[key] = value
    # Validate before anything is written: a run directory that already holds another
    # target's package, or that would overwrite a domain, is a data-loss event that is much
    # cheaper to refuse than to reconcile afterwards.
    out_dir = ensure_dir(out_dir)
    guard = _guard_run_dir(domain, out_dir)
    if guard:
        return guard, 3
    started_at = now_iso()
    clock = time.time()
    session = Session(
        domain, timeout=limits["timeout"], max_total_bytes=limits["max_total_bytes"],
        allow_external=allow_external, verify_tls=verify_tls, budget_seconds=limits["budget_seconds"],
        egress=egress,
    )

    # `cancel` may be a callable predicate (older callers) or a threading.Event (the web
    # console). Calling an Event raised TypeError on the very first emit, so every scan
    # started from the UI died at stage 0 with no visible error and a 0% progress bar.
    def _cancelled() -> bool:
        if cancel is None:
            return False
        flag = getattr(cancel, "is_set", None)
        if callable(flag):
            return bool(flag())
        return bool(cancel()) if callable(cancel) else bool(cancel)

    # Stage order and weight. Weights approximate where time actually goes on a normal
    # run (crawl and JS analysis dominate), because a progress bar that advances evenly
    # per stage sits at 50% for the whole scan and teaches the user to ignore it.
    STAGE_PLAN = [
        ("start", 2), ("dns", 5), ("web", 10), ("intel", 8), ("crawl", 26),
        ("js", 24), ("api", 8), ("verify", 6), ("analyze", 9), ("report", 8),
    ]
    stage_done = 0.0
    total_weight = sum(w for _, w in STAGE_PLAN) or 1
    seen: set[str] = set()

    def emit(stage: str, message: str, **data):
        nonlocal stage_done
        key = stage if stage in dict(STAGE_PLAN) else None
        if key and key not in seen:
            seen.add(key)
            stage_done += dict(STAGE_PLAN)[key]
        progress = min(99, round(stage_done / total_weight * 100))
        if on_event is not None:
            on_event({"stage": stage, "message": message, "progress": progress, **data})
        if _cancelled():
            raise ScanCancelled(stage)

    status: dict[str, str] = {}
    emit("start", f"开始扫描 {domain}（profile={profile_name}，出口={session.egress.label()}）")
    # Said once, at the top of every run, in the stream the console already shows: the
    # notice has to be visible to the person starting the scan, not only to whoever opens
    # the report afterwards. `--authorized-by` is what turns it from a warning into a record.
    emit("authorize", AUTHORIZED_USE_SHORT +
         (f"（授权依据：{authorized_by.strip()[:120]}）" if (authorized_by or "").strip()
          else "（未填写 --authorized-by：报告会把授权依据记为未声明）"))

    dns_result = {"domain": domain, "records": {}, "errors": [], "dmarc": [], "spf": [], "resolvers": []}
    if use_dns:
        try:
            dns_result = dnsmod.dns_probe(domain)
            status["dns"] = "ok" if not dns_result["errors"] else f"partial({len(dns_result['errors'])})"
            records = dns_result["records"]
            emit("dns", f"DNS 完成：A={len(records.get('A', []))} MX={len(records.get('MX', []))} "
                        f"TXT={len(records.get('TXT', []))}")
        except Exception as exc:
            status["dns"] = f"error: {exc}"[:120]
            emit("dns", f"DNS 失败：{exc}"[:160])
    else:
        status["dns"] = "skipped"
        emit("dns", "DNS 已跳过")

    web = webprobe.probe_web(session, domain)
    status["web"] = "ok" if web.get("reachable") else f"unreachable: {web.get('error', '')}"[:120]
    emit("web", f"HTTP 面：状态 {web.get('status', 0)}，技术栈 {len(web.get('tech', []))} 项，"
                f"安全头缺口 {len((web.get('security') or {}).get('missing', []))} 项")

    # ---- passive intel (third-party indexes only; no packet reaches the target) ---------
    intel: dict = {"passive": True, "domain": domain,
                   "ct": {"status": "disabled"}, "archive": {"status": "disabled"},
                   "geo": {"status": "disabled"}, "cve": {"status": "disabled"},
                   "providers": {}}
    if use_intel and not _is_ip_target(domain):
        a_records = [r for r in (dns_result.get("records", {}).get("A") or []) if r]
        intel = intelmod.gather(domain, geo_enabled=geo, cve_enabled=cve,
                                ip=(a_records[0] if a_records else ""),
                                products=_versioned_products(web.get("headers") or {}))
        ct = intel.get("ct") or {}
        arch = intel.get("archive") or {}
        status["intel"] = "ok" if any((intel.get(k) or {}).get("status") == "ok"
                                      for k in ("ct", "archive")) else "unavailable"
        emit("intel", f"情报：子域 {len(ct.get('subdomains') or [])}（{ct.get('status')}）、"
                      f"历史快照 {arch.get('snapshots', 0)}（{arch.get('status')}）")
    else:
        reason = ("IP 目标：CT 日志与历史存档只索引域名" if use_intel
                  else "已通过 --no-intel 关闭")
        intel = {"passive": True, "domain": domain,
                 "ct": {"status": "disabled", "source": "ct", "reason": reason},
                 "archive": {"status": "disabled", "source": "wayback", "reason": reason},
                 "geo": {"status": "disabled", "source": "ip-api", "reason": reason},
                 "cve": {"status": "disabled", "source": "nvd", "reason": reason},
                 "providers": {}}
        status["intel"] = "skipped"
        emit("intel", "被动情报已跳过：" + reason)

    if not web.get("reachable"):
        emit("fail", "目标不可达，写出空报告")
        # The bar must not stall at 17% on an aborted run: 100% means "the run ended",
        # not "everything succeeded". The report says which stages were skipped.
        if on_event is not None:
            on_event({"stage": "done", "message": "扫描结束（目标不可达）", "progress": 100})
        report = reportmod.assemble(
            domain=domain, root_url=f"https://{domain}/", profile_name=profile_name, limits=limits,
            web=web, dns=dns_result, crawl_result={}, js={}, api={}, findings=[], hyp=[],
            session=session, started_at=started_at, elapsed=time.time() - clock,
            probe_status={**status, "crawl": "skipped", "js": "skipped", "api": "skipped"},
        intel=intel, authorized_by=authorized_by,
        verification=verifymod.run(session, f"https://{domain}/", [],
                                   verifymod.build_roe(domain, allow_external, 0, enabled=False,
                                                       source="skipped:unreachable")),
        )
        reportmod.write_all(report, out_dir)
        return report, 3

    root_url = web.get("final_url") or web.get("root_url")
    crawl_result = crawler.crawl(session, root_url, max_pages=limits["max_pages"],
                                 max_depth=limits["max_depth"], domain=domain)
    status["crawl"] = "ok" if crawl_result["pages"] else "empty"
    emit("crawl", f"爬取 {len(crawl_result['pages'])} 页，脚本引用 {len(crawl_result['scripts'])} 个，"
                  f"表单 {len(crawl_result['forms'])} 个")

    if use_js:
        js = jsanalyze.analyze(
            session, crawl_result["scripts"],
            [s for page in crawl_result["pages"] for s in page.get("inline_scripts", [])],
            domain, out_dir, max_scripts=limits["max_scripts"], max_js_bytes=limits["max_js_bytes"],
            max_total_js_bytes=limits["max_total_js_bytes"],
        )
        status["js"] = "ok" if js["stats"]["fetched"] else "no-scripts"
        emit("js", f"JS {js['stats']['fetched']} 个（{js['stats']['bytes']} B）→ 端点 "
                   f"{len(js['endpoints'])}、密钥 {len(js['secrets'])}、内部主机 "
                   f"{sum(1 for h in js['hosts'] if h['kind'] == 'internal')}")
    else:
        # `--no-js`: the whole point of the mode. No bundle is downloaded; the endpoint map
        # comes from links, forms, robots, sitemap and the archive instead.
        js = {"scripts": [], "endpoints": [], "params": [], "secrets": [], "hints": [],
              "hosts": [], "chunks": [], "graphql": [],
              "stats": {"fetched": 0, "bytes": 0, "requested": 0}}
        status["js"] = "skipped"
        emit("js", "JS 分析已跳过（不下载前端 bundle）")

    passive = _passive_endpoints(domain, web, crawl_result, intel)
    if passive:
        js["endpoints"] = jsanalyze.merge_endpoints(js.get("endpoints") or [], passive)
        js["stats"]["passive_endpoints"] = len(passive)
        by_source: dict[str, int] = {}
        for entry in passive:
            for source in entry.get("sources") or []:
                by_source[source] = by_source.get(source, 0) + 1
        emit("js", "非 JS 来源端点 " + str(len(passive)) + " 个（" +
                   "、".join(f"{k}:{v}" for k, v in sorted(by_source.items())) + "）")

    if use_graphql:
        api = apiprobe.discover(session, root_url, js)
        status["api"] = "ok" if (api["specs"] or (api.get("graphql") or {}).get("endpoints")) else "none-found"
    else:
        # `discover()` probes the spec paths and GraphQL together, so --no-graphql skips
        # both. Reporting that as "none-found" would let the score claim "no public spec"
        # about a stage that never ran; "skipped" is the honest status.
        api = {"specs": [], "spec_probes": [], "graphql": {"endpoints": [], "tried": []},
               "parameters": js.get("params", [])}
        status["api"] = "skipped"
    emit("api", f"API 规范 {len(api['specs'])} 份，GraphQL {len((api.get('graphql') or {}).get('endpoints', []))} 个，"
                f"参数 {len(api['parameters'])} 个")

    sample_paths = [e["path"] for e in js.get("endpoints", [])[:4] if e["path"].startswith("/")]
    web["cors"] = webprobe.probe_cors(session, root_url, sample_paths)
    status["cors"] = "ok"

    # ---- light verification: one GET per endpoint, bound by RoE + scope guard ----------
    # Runs last, after every endpoint source has landed, because it must see the final list.
    verify_targets = list(js.get("endpoints") or [])
    for spec in api.get("specs") or []:
        verify_targets.extend(spec.get("endpoints") or [])
    roe = verifymod.build_roe(domain, allow_external=allow_external, max_requests=verify_max,
                              enabled=use_verify,
                              source=("cli:--verify" if use_verify else "cli:--no-verify"))
    verification = verifymod.run(session, root_url, verify_targets, roe)
    verifymod.annotate(verify_targets, verification)
    summary = verification.get("summary") or {}
    status["verify"] = ("skipped" if not use_verify else
                        ("ok" if summary.get("probed") else "empty"))
    emit("verify", f"验证：可用 {summary.get('usable', 0)} / 不可用 {summary.get('unusable', 0)}"
                   f" / 跳过 {summary.get('skipped', 0)}（请求 {summary.get('requests', 0)}"
                   f"/{summary.get('max_requests', 0)}）")

    findings = reportmod.derive_findings(web, js, api, dns_result)
    sourcemaps = [s["sourcemap"] for s in js.get("scripts", []) if s.get("sourcemap")]
    hyp = hypotheses.build({
        "endpoints": js.get("endpoints", []), "findings": findings, "secrets": js.get("secrets", []),
        "specs": api.get("specs", []), "graphql": (api.get("graphql") or {}).get("endpoints", []),
        "sourcemaps": sourcemaps, "hosts": js.get("hosts", []), "forms": crawl_result.get("forms", []),
        "robots": (web.get("well_known", {}).get("/robots.txt", {}) or {}).get("disallow", []),
        "hints": js.get("hints", []),
    })
    emit("analyze", f"发现 {len(findings)} 条，假设 {len(hyp)} 条（无阻塞 {sum(1 for h in hyp if not h['blocked'])}）")

    # Site type is a rule table over what we just observed; keep it next to the intel so
    # the report has one place for "what is this thing".
    intel["site_type"] = intelmod.classify_site(
        tech=web.get("tech") or [], title=web.get("title") or "",
        paths=[e.get("path") or "" for e in js.get("endpoints") or []],
        headers={k.lower(): v for k, v in (web.get("headers") or {}).items()})

    report = reportmod.assemble(
        domain=domain, root_url=root_url, profile_name=profile_name, limits=limits, web=web,
        dns=dns_result, crawl_result=crawl_result, js=js, api=api, findings=findings, hyp=hyp,
        session=session, started_at=started_at, elapsed=time.time() - clock, probe_status=status,
        intel=intel, authorized_by=authorized_by, verification=verification,
    )
    # The AI-facing brief lives beside the machine report so a task description can be
    # pasted from a file instead of reassembled by hand every time. Write it *before*
    # write_all(): the manifest is built by walking the run directory, so a file created
    # afterwards was silently missing from the "every artifact" list.
    ensure_dir(os.path.join(out_dir, "report"))
    brief_path = os.path.join(out_dir, "report", "brief.md")
    with open(brief_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(briefmod.build_brief(report, report_dir=os.path.abspath(out_dir)))
    reportmod.write_all(report, out_dir)
    emit("report", f"报告已写出：{os.path.join(out_dir, 'report')}", out_dir=out_dir)
    if on_event is not None:
        on_event({"stage": "done", "message": "扫描完成", "progress": 100})

    if not quiet:
        counts = report["coverage"]["counts"]
        print(f"[recon-one] {domain} -> {out_dir}")
        print(f"  pages={counts['pages']} scripts={counts['scripts']} endpoints={counts['endpoints']} "
              f"params={counts['parameters']} secrets={counts['secrets']} findings={counts['findings']} "
              f"hypotheses={counts['hypotheses']}")
        print(f"  requests={report['meta']['requests']} bytes={report['meta']['bytes']} "
              f"elapsed={report['meta']['elapsed_seconds']}s")
        for h in report["hypotheses"][:5]:
            print(f"  {h['rank']}. [{h['priority_score']}] {h['title']}")
    complete = all(v == "ok" for v in status.values())
    return report, 0 if complete else 2


def cmd_scan(args) -> int:
    """Run one scan from the command line."""
    # Printed before the first request, and only for a human at a terminal: a JSON consumer
    # or a quiet run does not need a legal notice in its stdout.
    if not getattr(args, "quiet", False) and not getattr(args, "json", False):
        print("[授权声明] " + AUTHORIZED_USE, file=sys.stderr)
    domain = _normalise_domain(args.domain)
    if not domain or "." not in domain:
        print(f"invalid domain: {args.domain}", file=sys.stderr)
        return 3
    # Absolute, CWD-independent default (see config.output_root). --out still wins, but
    # config.ensure_out_dir refuses to flatten two targets into the runs root and will not
    # let a run directory take a reserved package name (raw/ report/).
    out_dir = ensure_out_dir(domain, args.out)
    overrides = {"max_pages": args.max_pages, "max_depth": args.max_depth,
                 "max_js_bytes": args.max_js_bytes, "timeout": args.timeout,
                 "max_scripts": args.max_scripts}
    # Egress: --proxy wins, then RECONONE_PROXY, then the system proxy. Without any of them
    # the session stays direct and only falls back per-request when a connect attempt fails.
    proxy_url = (getattr(args, "proxy", "") or os.environ.get("RECONONE_PROXY", "")).strip()
    if proxy_url:
        mode = "manual"
    elif getattr(args, "direct", False):
        mode = "direct"
    elif getattr(args, "proxy_from_system", False):
        mode = "system"
    else:
        mode = "auto"
    try:
        egress = egressmod.resolve(mode, proxy_url, getattr(args, "proxy_bypass", ""))
    except ValueError as exc:
        print(f"[egress] {exc}", file=sys.stderr)
        return 2
    report, code = run_scan(domain, out_dir, args.profile, overrides,
                            allow_external=args.allow_external, verify_tls=not args.insecure,
                            use_dns=not args.no_dns, use_graphql=not args.no_graphql,
                            quiet=args.quiet, use_js=not args.no_js,
                            use_intel=not args.no_intel, geo=args.geo, cve=args.cve,
                            authorized_by=getattr(args, "authorized_by", ""), egress=egress,
                            use_verify=not getattr(args, "no_verify", False),
                            verify_max=getattr(args, "verify_max", verifymod.DEFAULT_MAX_REQUESTS))
    if args.json:
        print(json.dumps({"exit_code": code, "counts": report["coverage"]["counts"],
                          "hypotheses": report["hypotheses"][:5]}, ensure_ascii=False))
    return code


def cmd_brief(args) -> int:
    """Render the AI-facing brief for an existing report package."""
    path = args.report
    if os.path.isdir(path):
        path = os.path.join(path, "report", "report.json")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    report_dir = os.path.dirname(os.path.dirname(os.path.abspath(path)))
    text = briefmod.build_brief(data, budget=args.budget, report_dir=report_dir)
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print(f"[brief] {len(text)} chars -> {args.out}")
    else:
        print(text)
    return 0


def cmd_validate(args) -> int:
    with open(args.report, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    errors = reportmod.validate(data)
    if errors:
        print(json.dumps({"valid": False, "errors": errors}, ensure_ascii=False, indent=1))
        return 2
    print(json.dumps({"valid": True, "schema": data.get("schema"),
                      "counts": (data.get("coverage") or {}).get("counts")}, ensure_ascii=False))
    return 0


def cmd_ui(args) -> int:
    from .web import serve
    serve(host=args.host, port=args.port, root=args.root,
          open_browser=not args.no_browser, verbose=args.verbose,
          open_report=args.report)
    return 0


def cmd_doctor(args) -> int:
    """Prove the hard dependencies work here, then exit 0 (ok) or 4 (unusable).

    Separate from `scan` on purpose: a broken httpx/ssl shows up as a minute of timeouts
    inside a scan, which looks like "the target is down". This answers it in a second.
    """
    result = doctormod.run()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    else:
        for check in result["checks"]:
            mark = "ok  " if check["ok"] else "FAIL"
            print(f"  [{mark}] {check['id']:<12} {check['title']} — {check['detail']}")
        print("[doctor] " + doctormod.summary(result))
    return 0 if result["ok"] else 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="recon-one",
                                     description="Local all-in-one recon for one authorized domain.")
    parser.add_argument("--version", action="version", version=f"recon-one {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run a full scan and write a report package")
    scan.add_argument("--authorized-by", default="", metavar="TEXT",
                      help="记录授权依据（工单号/合同编号/授权窗口），写入报告的 meta.authorization")
    scan.add_argument("--domain", required=True, help="authorized target domain, e.g. example.com")
    scan.add_argument("--out", default="",
                      help="output directory (default: <project>/runs/<domain>, "
                           "override the base with RECONONE_OUTPUT_DIR)")
    scan.add_argument("--profile", default="default", choices=sorted(PROFILES))
    scan.add_argument("--max-pages", type=int, default=None)
    scan.add_argument("--max-depth", type=int, default=None)
    scan.add_argument("--max-scripts", type=int, default=None)
    scan.add_argument("--max-js-bytes", type=int, default=None)
    scan.add_argument("--timeout", type=float, default=None)
    scan.add_argument("--allow-external", action="store_true",
                      help="permit requests outside the target domain (off by default)")
    scan.add_argument("--insecure", action="store_true", help="skip TLS verification")
    scan.add_argument("--proxy", default="", metavar="URL",
                      help="route every request through this proxy: http:// or socks5://, "
                           "optional user:pass@; RECONONE_PROXY is the env equivalent")
    scan.add_argument("--proxy-from-system", action="store_true",
                      help="force the system proxy (HTTPS_PROXY / ALL_PROXY / Windows WinINET)")
    scan.add_argument("--direct", action="store_true",
                      help="never use a proxy, including the automatic fallback")
    scan.add_argument("--proxy-bypass", default="", metavar="SUFFIXES",
                      help="comma separated suffixes that stay direct, e.g. localhost,.corp")
    scan.add_argument("--no-dns", action="store_true")
    scan.add_argument("--no-graphql", action="store_true", help="skip active introspection probe")
    scan.add_argument("--no-js", action="store_true",
                      help="do not download front-end bundles; endpoints come from links, "
                           "forms, robots, sitemap and the archive instead")
    scan.add_argument("--no-intel", action="store_true",
                      help="skip passive third-party lookups (CT logs, web archive)")
    scan.add_argument("--no-verify", action="store_true",
                      help="skip the light verification stage (endpoints stay unverified claims)")
    scan.add_argument("--verify-max", type=int, default=verifymod.DEFAULT_MAX_REQUESTS,
                      help="hard cap of verification requests; one GET per endpoint, RoE-bound")
    scan.add_argument("--geo", action="store_true",
                      help="look up the resolved IP's location via ip-api.com (sends the IP to a third party)")
    scan.add_argument("--cve", action="store_true",
                      help="keyword-search NVD for advertised product versions (rate limited)")
    scan.add_argument("--quiet", action="store_true")
    scan.add_argument("--json", action="store_true", help="print a machine summary to stdout")
    scan.set_defaults(func=cmd_scan)

    ui = sub.add_parser("ui", help="start the web console (backend + front end, one process)")
    ui.add_argument("--host", default="127.0.0.1",
                    help="bind address; anything but loopback exposes the console to the network")
    ui.add_argument("--port", type=int, default=8770)
    ui.add_argument("--root", default=None, help="run directory (defaults to the project folder)")
    ui.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    ui.add_argument("--report", default=None, help="直接打开一个已有的运行目录")
    ui.add_argument("-v", "--verbose", action="store_true")
    ui.set_defaults(func=cmd_ui)

    brf = sub.add_parser("brief", help="render an AI-facing brief from a report package")
    brf.add_argument("--report", required=True, help="report.json, or the run directory")
    brf.add_argument("--budget", type=int, default=briefmod.DEFAULT_BUDGET,
                     help=f"character budget (default {briefmod.DEFAULT_BUDGET}, ARTEX caps at 16000)")
    brf.add_argument("--out", default="", help="write to a file instead of stdout")
    brf.set_defaults(func=cmd_brief)

    val = sub.add_parser("validate", help="validate a report.json against the shipped schema")
    val.add_argument("--report", required=True)
    val.set_defaults(func=cmd_validate)
    doc = sub.add_parser("doctor", help="check that httpx / anyio / ssl / dns work here")
    doc.add_argument("--json", action="store_true", help="machine-readable output")
    doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
