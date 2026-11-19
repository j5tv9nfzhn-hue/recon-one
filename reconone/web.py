"""Web UI server: one process, standard library only.

The Tk window is gone. `python -m reconone.web` starts the backend and serves the
console; when the process exits, everything stops. Nothing is installed, nothing is
registered, and no state is written outside the project directory.

Security posture of this file:
  * Bound to 127.0.0.1 by default. `--host 0.0.0.0` is opt-in and prints a warning.
  * Every API that returns recon data requires a session cookie; only `/api/state`
    (login gate: configured/authed/version + progress) is anonymous.
  * Cross-site requests are refused by Origin check + a custom header that a plain
    HTML form cannot set.
  * Responses are JSON only; the UI is served from disk with a strict CSP.
  * Run selection / deletion is confined to `<root>/runs/<name>` after a name check.
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import cli, config, egress as egressmod, score
from . import triage as triagemod
from . import uncertainty as uncertaintymod
from . import verify as verifymod
from .auth import Auth, AuthError
from .util import ensure_dir

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_ROOT = os.path.join(PROJECT_ROOT, "webui")
SESSION_COOKIE = "recon_sid"
CSRF_HEADER = "X-Recon-Request"

MAX_TARGETS = 12
# How many *different sites* are probed at the same time. Per-site request fan-out is
# handled inside the scan (httpx + anyio); this is the outer, cross-site layer.
MAX_TARGET_PARALLEL = max(1, min(8, int(os.environ.get("RECONONE_TARGET_PARALLEL", "4") or 4)))

# The comparison view exists to answer "which of these do I look at first". Twenty rows is
# already more than a page of judgement; beyond that the table stops being readable and the
# per-report re-score starts costing real time.
MAX_COMPARE_RUNS = 20
_RUN_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")


def _norm_target(value: str) -> str:
    """Host-only, lowercase, no scheme/path — same rule the CLI applies."""
    return cli._normalise_domain(str(value or ""))


BET_LABELS = {"worth": "值得打", "not_worth": "不值", "withheld": "证据不足"}


def _bet_label(bet: dict) -> str:
    gross = str((bet or {}).get("verdict") or "")
    return BET_LABELS.get(gross, "")


def _recompute_derived(report: dict) -> dict:
    """Recompute conclusions that are pure functions of the stored evidence.

    `score` was already recomputed on read; `profile` and `bet` were not, so an old package
    could keep a conclusion the current rules would never reach. Re-stamp `authz_open` from
    the stored verification block first: reports written before the split only have
    `verified`, and treating that as "anonymous open" would resurrect the old bug.
    """
    verification = report.get("verification") or {}
    if verification:
        verifymod.annotate(report.get("endpoints") or [], verification)
    report["bet"] = triagemod.bet(report)
    report["uncertainty"] = uncertaintymod.build(report, report["bet"])
    report["profile"] = triagemod.build(report, report.get("intel") or {})
    return report


class Job:
    """One scan batch at a time. Two batches would fight over the same run directories.

    A batch holds 1..MAX_TARGETS sites probed in parallel; each site keeps its own
    progress/state/out_dir so the console can show a per-target row instead of a single
    aggregated bar with no attribution.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.cancel = threading.Event()
        self.events: list[dict] = []
        self.state = "idle"          # idle | running | done | error | cancelled
        self.progress = 0
        self.stage = ""
        self.summary: dict = {}
        self.targets: list[dict] = []
        self.selected = ""           # run directory currently shown by /api/report
        self.target = ""
        self.out_dir = ""
        self.started = 0.0
        self.parallel = 1
        self.egress = None

    def snapshot(self) -> dict:
        return {
            "state": self.state, "target": self.target, "out_dir": self.out_dir,
            "selected": self.selected, "targets": self.targets, "parallel": self.parallel,
            "events": self.events[-400:], "summary": self.summary,
            "progress": self.progress, "stage": self.stage,
            "elapsed": round(time.time() - self.started, 1) if self.started else 0,
        }

    def public_snapshot(self) -> dict:
        """Progress only: what an unauthenticated visitor may see."""
        return {"state": self.state, "progress": self.progress, "stage": self.stage,
                "elapsed": round(time.time() - self.started, 1) if self.started else 0}

    def busy(self) -> bool:
        return self.state == "running"


def _aggregate(job: Job) -> int:
    """Overall progress = mean of per-target progress (caller holds the lock)."""
    if not job.targets:
        return 0
    return int(sum(int(t.get("progress") or 0) for t in job.targets) / len(job.targets))


class Handler(BaseHTTPRequestHandler):
    server_version = "recon-one"
    sys_version = ""

    # ------------------------------------------------------------------ plumbing
    def log_message(self, fmt, *args):   # noqa: A003 - silence default access log
        if self.server.verbose:
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8",
              extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, payload: dict, extra: dict | None = None) -> None:
        self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                   extra=extra)

    def _sid(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie(raw)
        morsel = jar.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _authed(self) -> bool:
        return self.server.auth.session_valid(self._sid())

    def _session_cookie(self, sid: str) -> str:
        """Max-Age makes the login survive a browser restart, not just a page reload."""
        ttl = int(self.server.auth.session_ttl)
        return (f"{SESSION_COOKIE}={sid}; Path=/; Max-Age={ttl}; "
                "HttpOnly; SameSite=Strict")

    def _same_origin(self) -> bool:
        """Reject anything a rogue page could send.

        A custom header cannot be attached cross-origin without a CORS preflight, which
        this server never approves; the Origin check covers the browser cases where a
        header is absent.
        """
        if self.headers.get(CSRF_HEADER) != "1":
            return False
        origin = self.headers.get("Origin")
        if origin:
            host = self.headers.get("Host", "")
            if urlparse(origin).netloc != host:
                return False
        return True

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_000_000:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    # ------------------------------------------------------------------ run directory helpers
    def _runs_root(self) -> str:
        return os.path.join(self.server.root, "runs")

    def _run_path(self, name: str) -> str:
        """Resolve one run directory, refusing anything that escapes `<root>/runs`."""
        name = str(name or "").strip().strip("/\\")
        if not _RUN_NAME_RE.match(name) or name in (".", ".."):
            return ""
        root = os.path.abspath(self._runs_root())
        full = os.path.abspath(os.path.join(root, name))
        if os.path.dirname(full) != root:
            return ""
        return full

    @staticmethod
    def _dir_size(path: str) -> int:
        total = 0
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue
        return total

    def _list_runs(self) -> list[dict]:
        """Every run directory with just enough metadata to triage it in a table."""
        root = self._runs_root()
        if not os.path.isdir(root):
            return []
        out = []
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if not os.path.isdir(full):
                continue
            entry = {"run": name, "has_report": False, "domain": "", "generated_at": "",
                     "verdict": "", "score_verdict": "", "bet": "",
                     "counts": {}, "bytes": 0, "mtime": 0.0}
            try:
                entry["mtime"] = os.path.getmtime(full)
                entry["bytes"] = self._dir_size(full)
            except OSError:
                pass
            report_file = os.path.join(full, "report", "report.json")
            if os.path.isfile(report_file):
                try:
                    with open(report_file, encoding="utf-8") as fh:
                        rep = json.load(fh)
                except (OSError, ValueError):
                    rep = None
                if isinstance(rep, dict):
                    entry["has_report"] = True
                    entry["domain"] = ((rep.get("target") or {}).get("domain") or "")
                    entry["generated_at"] = ((rep.get("meta") or {}).get("generated_at") or "")
                    entry["counts"] = (rep.get("coverage") or {}).get("counts") or {}
                    score_label = str(((rep.get("score") or {}).get("triage") or {})
                                      .get("label") or "")
                    entry["score_verdict"] = score_label
                    try:
                        rep.pop("score", None)
                        rep["score"] = score.score_report(rep)
                        _recompute_derived(rep)
                        bet = rep.get("bet") or {}
                        entry["bet"] = str(bet.get("verdict") or "")
                        entry["verdict"] = _bet_label(bet) or score_label
                    except Exception:                 # noqa: BLE001 - one bad row must not 500
                        entry["verdict"] = score_label
            out.append(entry)
        out.sort(key=lambda r: r["mtime"], reverse=True)
        return out

    # ------------------------------------------------------------------ routes
    def do_GET(self):   # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._static("index.html")
        if path.startswith("/assets/"):
            return self._static(path[len("/assets/"):])
        if path == "/api/state":
            return self._json(200, self._state())
        # Everything below returns recon data (report body, run list, stage log).
        if not self._authed():
            return self._json(401, {"error": "未登录"})
        if path == "/api/events":
            qs = parse_qs(urlparse(self.path).query)
            since = int((qs.get("since") or ["0"])[0] or 0)
            return self._json(200, {"events": self.server.job.events[since:],
                                    "state": self.server.job.state,
                                    "since": len(self.server.job.events)})
        if path == "/api/runs":
            return self._json(200, {"runs": self._list_runs(),
                                    "selected": self.server.job.selected})
        if path == "/api/report":
            qs = parse_qs(urlparse(self.path).query)
            run = (qs.get("run") or [""])[0]
            return self._report(run)
        if path == "/api/compare":
            return self._compare()
        return self._json(404, {"error": "not found"})

    def do_HEAD(self):  # noqa: N802
        return self.do_GET()

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        if not self._same_origin():
            return self._json(403, {"error": "跨站请求被拒绝"})
        body = self._body()

        if path == "/api/claim":
            return self._claim(body)
        if path == "/api/login":
            return self._login(body)
        if path == "/api/logout":
            self.server.auth.logout(self._sid())
            return self._json(200, {"ok": True}, {"Set-Cookie":
                               f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})

        # --- everything below needs a session ---
        if not self._authed():
            return self._json(401, {"error": "未登录"})

        if path == "/api/scan":
            return self._scan(body)
        if path == "/api/stop":
            self.server.job.cancel.set()
            return self._json(200, {"ok": True})
        if path == "/api/runs/select":
            return self._select_run(body)
        if path == "/api/runs/delete":
            return self._delete_run(body)
        return self._json(404, {"error": "not found"})

    # ------------------------------------------------------------------ handlers
    def _state(self) -> dict:
        auth: Auth = self.server.auth
        authed = self._authed()
        job: Job = self.server.job
        payload = {"configured": auth.configured, "authed": authed,
                   "version": self.server.version,
                   "remember_days": auth.session_ttl // 86400,
                   # The notice is public on purpose: it must be readable before anyone logs
                   # in, because "may I point this at X" is decided before authenticating.
                   # It carries no recon data, only the constraint.
                   "authorization": {"summary": config.AUTHORIZED_USE_SHORT,
                                     "notice_version": config.AUTHORIZED_USE_VERSION,
                                     "notice": config.AUTHORIZED_USE},
                   # Before login only progress is visible: the full snapshot names the
                   # target, the run directory and the last 400 stage messages.
                   "job": job.snapshot() if authed else job.public_snapshot()}
        if not auth.configured:
            # The token is only ever readable from the console, never from HTTP.
            payload["pairing"] = {"hint": "令牌已打印在启动它的控制台窗口里"}
        return payload

    def _claim(self, body: dict) -> None:
        try:
            self.server.auth.claim(str(body.get("token", "")), str(body.get("password", "")))
        except AuthError as exc:
            return self._json(400, {"error": str(exc)})
        sid = self.server.auth.login(str(body.get("password", "")))
        self._json(200, {"ok": True}, {"Set-Cookie": self._session_cookie(sid)})

    def _login(self, body: dict) -> None:
        try:
            sid = self.server.auth.login(str(body.get("password", "")))
        except AuthError as exc:
            return self._json(401, {"error": str(exc)})
        self._json(200, {"ok": True}, {"Set-Cookie": self._session_cookie(sid)})

    def _select_run(self, body: dict) -> None:
        job: Job = self.server.job
        with job.lock:
            if job.busy():
                return self._json(409, {"error": "扫描进行中，稍后再切换产物"})
            full = self._run_path(str(body.get("run", "")))
            if not full or not os.path.isfile(os.path.join(full, "report", "report.json")):
                return self._json(404, {"error": "该产物目录下没有 report/report.json"})
            job.selected = full
            job.out_dir = full
            job.target = os.path.basename(full)
        self._json(200, {"ok": True, "run": os.path.basename(full)})

    def _delete_run(self, body: dict) -> None:
        job: Job = self.server.job
        if not body.get("confirm"):
            return self._json(400, {"error": "删除需要二次确认"})
        with job.lock:
            if job.busy():
                return self._json(409, {"error": "扫描进行中，稍后再删除产物"})
            name = str(body.get("run", ""))
            full = self._run_path(name)
            if not full or not os.path.isdir(full):
                return self._json(404, {"error": "产物目录不存在"})
            try:
                shutil.rmtree(full)
            except OSError as exc:
                return self._json(500, {"error": f"删除失败：{exc}"})
            if os.path.abspath(job.selected or "") == full:
                job.selected = ""
                job.out_dir = ""
        self._json(200, {"ok": True, "run": name})

    def _targets_from(self, body: dict) -> list[str]:
        raw = body.get("targets")
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            raw = [body.get("target", "")]
        targets: list[str] = []
        for item in raw:
            for piece in str(item or "").replace(",", "\n").replace(";", "\n").splitlines():
                value = _norm_target(piece)
                if value and value not in targets:
                    targets.append(value)
        return targets

    def _scan(self, body: dict) -> None:
        job: Job = self.server.job
        with job.lock:
            if job.busy():
                return self._json(409, {"error": "已有扫描在进行中"})
            targets = self._targets_from(body)
            if not targets:
                return self._json(400, {"error": "请填写目标域名"})
            if len(targets) > MAX_TARGETS:
                return self._json(400, {"error": f"一次最多 {MAX_TARGETS} 个目标"})
            invalid = [t for t in targets if "." not in t]
            if invalid:
                return self._json(400, {"error": "无效域名：" + "、".join(invalid[:3])})
            profile = str(body.get("profile", "default"))
            if profile not in ("fast", "default", "deep"):
                return self._json(400, {"error": "未知档案"})
            allow_external = bool(body.get("allow_external"))
            if allow_external and not body.get("confirm_external"):
                return self._json(400, {"error": "越界请求需要二次确认"})
            # Egress: same rules as the CLI. Resolved once per batch so every target in it
            # leaves through the same route (and the report can say which).
            proxy_url = str(body.get("proxy") or os.environ.get("RECONONE_PROXY") or "").strip()
            if proxy_url:
                mode = "manual"
            elif body.get("direct"):
                mode = "direct"
            elif body.get("proxy_from_system"):
                mode = "system"
            else:
                mode = "auto"
            try:
                egress = egressmod.resolve(mode, proxy_url, str(body.get("proxy_bypass") or ""))
            except ValueError as exc:
                return self._json(400, {"error": f"代理配置无效：{exc}"})
            job.egress = egress

            job.events = []
            job.summary = {}
            job.progress = 0
            job.stage = ""
            job.state = "running"
            job.targets = [{"target": t, "state": "queued", "progress": 0, "stage": "",
                            "out_dir": "", "error": ""} for t in targets]
            job.target = targets[0]
            job.selected = ""
            job.out_dir = ""
            job.started = time.time()
            job.cancel = threading.Event()
            job.parallel = min(MAX_TARGET_PARALLEL, len(targets))
            job.thread = threading.Thread(target=self._run_batch, daemon=True, args=(
                targets, profile, allow_external, bool(body.get("use_dns", True)),
                bool(body.get("use_graphql", True)), bool(body.get("verify_tls", True)),
                bool(body.get("use_js", True)), bool(body.get("use_intel", True)),
                bool(body.get("geo", False)), bool(body.get("cve", False)),
                str(body.get("authorized_by") or ""), egress,
                bool(body.get("verify", True)), int(body.get("verify_max") or 40),
                str(body.get("cookie") or ""), str(body.get("bearer") or ""),
                [str(h) for h in (body.get("headers") or [])],
                float(body.get("rate") or 0), float(body.get("max_backoff") or 8),
                bool(body.get("use_cookies", True)),
                bool(body.get("use_discovery", True)), int(body.get("discovery_max") or 0),
            ))
            job.thread.start()
        self._json(200, {"ok": True, "targets": targets, "parallel": job.parallel,
                         "egress": job.egress.label() if job.egress else "直连"})

    # ------------------------------------------------------------------ batch runner
    def _run_batch(self, targets, profile, allow_external, use_dns, use_graphql, verify_tls,
                   use_js=True, use_intel=True, geo=False, cve=False, authorized_by="",
                   egress=None, use_verify=True, verify_max=40,
                   cookie="", bearer="", headers=(), rate=0.0, max_backoff=8.0,
                   use_cookies=True, use_discovery=True, discovery_max=0):
        job: Job = self.server.job
        out_root = ensure_dir(os.path.join(self.server.root, "runs"))

        def note(entry: dict, **fields) -> None:
            with job.lock:
                entry.update(fields)
                job.progress = _aggregate(job)

        def on_event(entry: dict, ev: dict) -> None:
            with job.lock:
                pct = ev.get("progress")
                if isinstance(pct, int):
                    entry["progress"] = pct
                entry["stage"] = ev.get("stage", "")
                job.stage = f"{entry['target']} · {entry['stage']}"
                job.events.append({"target": entry["target"], "stage": ev.get("stage", ""),
                                   "message": ev.get("message", ""), "progress": pct})
                job.progress = _aggregate(job)

        def worker(entry: dict) -> None:
            target = entry["target"]
            if job.cancel.is_set():
                note(entry, state="cancelled")
                return
            note(entry, state="running")
            try:
                out_dir = config.ensure_out_dir(target, os.path.join(
                    out_root, config.run_dir_name(target)))
            except Exception as exc:                  # noqa: BLE001 - surfaced per target
                note(entry, state="error", error=f"运行目录不可用：{type(exc).__name__}: {exc}")
                return
            note(entry, out_dir=out_dir)
            try:
                report, code = cli.run_scan(
                    target, out_dir, profile_name=profile,
                    allow_external=allow_external, verify_tls=verify_tls,
                    use_dns=use_dns, use_graphql=use_graphql, quiet=True,
                    use_js=use_js, use_intel=use_intel, geo=geo, cve=cve,
                    authorized_by=authorized_by, egress=egress, use_verify=use_verify,
                    verify_max=verify_max,
                    cookie=cookie, bearer=bearer, headers=headers, rate=rate,
                    max_backoff=max_backoff, injection_source="web",
                    use_cookies=use_cookies, use_discovery=use_discovery,
                    discovery_max=discovery_max,
                    on_event=lambda ev: on_event(entry, ev), cancel=job.cancel,
                )
            except cli.ScanCancelled:
                note(entry, state="cancelled", progress=100)
                return
            except Exception as exc:                  # noqa: BLE001 - surfaced per target
                note(entry, state="error", error=f"{type(exc).__name__}: {exc}")
                return
            score_triage = ((report.get("score") or {}).get("triage") or {})
            bet = report.get("bet") or {}
            reason = {2: "部分探测失败，报告仍可用（coverage.probes 列出未覆盖项）",
                      3: "扫描被拒绝：目标不可达或运行目录不合规"}.get(code, "")
            note(entry, progress=100,
                 state="cancelled" if job.cancel.is_set() else
                       ("done" if code == 0 else ("partial" if code == 2 else "error")),
                 error=reason if code not in (0,) else "",
                 verdict=_bet_label(bet) or score_triage.get("label", ""),
                 summary=(report.get("score") or {}).get("summary", ""))

        try:
            with ThreadPoolExecutor(max_workers=job.parallel) as pool:
                list(pool.map(worker, job.targets))
        finally:
            with job.lock:
                job.progress = 100
                completed = [t for t in job.targets if t.get("out_dir")]
                if job.cancel.is_set():
                    job.state = "cancelled"
                elif any(t["state"] == "error" for t in job.targets):
                    job.state = "error"
                else:
                    job.state = "done"
                job.selected = completed[-1]["out_dir"] if completed else ""
                job.out_dir = job.selected
                job.stage = "完成" if job.state == "done" else job.stage

    def _report(self, run: str = "") -> None:
        job: Job = self.server.job
        run_dir = ""
        if run:
            run_dir = self._run_path(run)
            if not run_dir:
                return self._json(400, {"error": "非法的产物名称"})
        else:
            run_dir = job.selected or job.out_dir
        if not run_dir:
            return self._json(404, {"error": "还没有可读取的报告"})
        path = os.path.join(run_dir, "report", "report.json")
        try:
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
        except (OSError, ValueError):
            return self._json(404, {"error": "报告文件不存在"})

        # Re-score on read. A report written by an older build carries that build's
        # verdict, and the console must never display a conclusion the current model would
        # no longer reach — that is exactly how the "maintenance is fine, skip it"
        # recommendation survived as long as it did.
        report.pop("score", None)
        try:
            report["score"] = score.score_report(report)
        except Exception as exc:                      # noqa: BLE001 - degrade, do not crash
            report["score_error"] = f"{type(exc).__name__}: {exc}"
        try:
            _recompute_derived(report)
        except Exception as exc:                      # noqa: BLE001 - keep the report readable
            report["derive_error"] = f"{type(exc).__name__}: {exc}"
        report["run"] = {"name": os.path.basename(run_dir), "dir": run_dir}
        return self._json(200, report)

    def _compare(self) -> None:
        """Side-by-side numbers for every run that has a report.

        Re-scored on read for the same reason `/api/report` is: a comparison is worthless if
        one column was produced by an older model. The three chart axes are the ones a
        decision actually needs - 价值 (worth), 易度 (100 - hardness) and 机会指数 - and each
        row keeps the raw counts so a reader can disagree with the synthesis.
        """
        job: Job = self.server.job
        rows: list[dict] = []
        for entry in [r for r in self._list_runs() if r.get("has_report")][:MAX_COMPARE_RUNS]:
            name = entry["run"]
            run_dir = self._run_path(name)
            if not run_dir:
                continue
            row = {
                "run": name, "domain": entry.get("domain") or name,
                "generated_at": entry.get("generated_at") or "",
                "selected": bool(job.selected) and os.path.abspath(run_dir) == os.path.abspath(job.selected),
                "error": "",
                "counts": entry.get("counts") or {},
            }
            try:
                with open(os.path.join(run_dir, "report", "report.json"), encoding="utf-8") as fh:
                    report = json.load(fh)
            except (OSError, ValueError) as exc:
                row["error"] = f"report unreadable: {type(exc).__name__}"
                rows.append(row)
                continue
            report.pop("score", None)
            try:
                report["score"] = score.score_report(report)
            except Exception as exc:                  # noqa: BLE001 - one bad row, not a 500
                row["error"] = f"score failed: {type(exc).__name__}"
            try:
                _recompute_derived(report)
            except Exception as exc:                  # noqa: BLE001 - degrade this row only
                row["derive_error"] = f"derive failed: {type(exc).__name__}"
            score_block = report.get("score") or {}
            axes = score_block.get("axes") or {}
            prof = report.get("profile") or {}
            pax = prof.get("axes") or {}
            success = prof.get("success") or {}
            weights = prof.get("weights") or {}
            bet = report.get("bet") or {}
            uncertainty = report.get("uncertainty") or {}
            next_action = (uncertainty.get("next_actions") or [{}])[0]
            score_label = str((score_block.get("triage") or {}).get("label") or "")
            row.update({
                "verdict": _bet_label(bet) or score_label,
                "bet": str(bet.get("verdict") or ""),
                "bet_confidence": str(bet.get("confidence") or ""),
                "bet_identity": str(bet.get("identity") or ""),
                "unknowns": len(uncertainty.get("unknowns") or []),
                "next_action": str(next_action.get("title") or ""),
                "score_verdict": score_label,
                "hygiene": (axes.get("hygiene") or {}).get("score"),
                "hygiene_grade": (axes.get("hygiene") or {}).get("grade") or "",
                "opportunity": (axes.get("opportunity") or {}).get("score"),
                "worth": (pax.get("worth") or {}).get("score"),
                "hardness": (pax.get("hardness") or {}).get("score"),
                "ease": (round(100.0 - float((pax.get("hardness") or {}).get("score") or 0.0), 1)
                         if (pax.get("hardness") or {}).get("score") is not None else None),
                "index": success.get("index"),
                "band": success.get("band") or "unknown",
                "band_label": success.get("label") or "",
                "observed_share_pct": weights.get("observed_share_pct"),
                "profile_available": bool(prof),
            })
            rows.append(row)
        return self._json(200, {
            "runs": rows,
            "selected": job.selected,
            "axes": ["worth", "ease", "index"],
            "note": ("列均按当前模型重算（score / profile / bet）；`index` 为机会指数（非概率），"
                     "`observed_share_pct` 表示该结论里来自主动实测的权重占比。"),
        })

    def _static(self, rel: str) -> None:
        rel = rel.replace("\\", "/").lstrip("/")
        if ".." in rel.split("/"):
            return self._json(403, {"error": "forbidden"})
        path = os.path.join(WEB_ROOT, *rel.split("/"))
        if not os.path.isfile(path):
            return self._json(404, {"error": "not found"})
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        with open(path, "rb") as fh:
            body = fh.read()
        self._send(200, body, ctype, {
            "Content-Security-Policy":
                "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'none'",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-cache",
        })


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, root: str, version: str, verbose: bool = False):
        self.root = os.path.abspath(root)
        self.auth = Auth(self.root)
        self.job = Job()
        self.version = version
        self.verbose = verbose
        super().__init__(addr, Handler)


def serve(host: str = "127.0.0.1", port: int = 8770, root: str | None = None,
          open_browser: bool = True, verbose: bool = False,
          open_report: str | None = None) -> None:
    from .config import VERSION

    # Everything (state/, runs/) lives inside the project directory. Keeping the default
    # here rather than at a platform location is the requirement: nothing is written to
    # the system disk or to any other volume, regardless of where the folder sits.
    root = os.path.abspath(root or PROJECT_ROOT)
    srv = Server((host, port), root, VERSION, verbose=verbose)
    # Reviewing a run from earlier should not require re-scanning the target.
    if open_report:
        run_dir = os.path.abspath(open_report)
        if os.path.isfile(os.path.join(run_dir, "report", "report.json")):
            srv.job.selected = run_dir
            srv.job.out_dir = run_dir
            srv.job.state = "done"
            srv.job.target = os.path.basename(run_dir)
        else:
            print(f"  警告: {run_dir} 下没有 report/report.json，已忽略 --report")
    actual = srv.server_address[1]
    url = f"http://127.0.0.1:{actual}/"

    # Line-buffered: the pairing token below is the only way in on first run. If stdout is
    # a pipe (started from a shell, a service wrapper, or the .pyw launcher) Python's
    # default block buffering would hide it until the process exits.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    print("recon-one web console")
    print(f"  运行目录 : {srv.root}")
    print(f"  监听     : http://{host}:{actual}/")
    print(f"  站点并行 : 会话内最多 {MAX_TARGET_PARALLEL} 个目标同时探测"
          "（RECONONE_TARGET_PARALLEL 可调，上限 8）")
    # Said before the pairing token: the person starting the console is the person who has to
    # be authorised, and this is the last moment it can be said cheaply.
    print(f"  授权要求 : {config.AUTHORIZED_USE_SHORT}")
    print(f"             {config.AUTHORIZED_USE}")
    if not srv.auth.configured:
        token = srv.auth.issue_token()
        print()
        # Box drawn with ASCII-width rules only: CJK glyphs occupy two terminal cells, so a
        # hand-padded Unicode box aligns on one platform and breaks on another.
        print("  +----------------------------------------------+")
        print("  |  first run: one-time pairing token           |")
        print(f"  |  {token:<44}|")
        print("  +----------------------------------------------+")
        print("  首次运行：把上面这行令牌粘进浏览器，然后立即设置密码。")
        print("  密码设置一次即可，之后的访问 30 天内免登录。")
        print()
    else:
        print("  需要使用已设置的密码登录（登录后 30 天内免登录）。")
    if host not in ("127.0.0.1", "localhost"):
        print(f"  ⚠ 已绑定到 {host}：同网络的其他机器可以访问本控制台。")
    print("  按 Ctrl+C 停止（结束进程即停止前后端）。")

    if open_browser:
        threading.Timer(0.8, lambda: __import__("webbrowser").open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        srv.job.cancel.set()
        srv.server_close()


if __name__ == "__main__":                       # pragma: no cover
    import argparse

    ap = argparse.ArgumentParser(description="recon-one web console")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--root", default=None, help="运行目录（默认是项目目录本身）")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--report", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    serve(a.host, a.port, a.root, not a.no_browser, a.verbose, a.report)
