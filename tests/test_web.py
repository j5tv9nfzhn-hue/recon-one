"""Web console: pairing, auth, containment, and the re-score-on-read rule."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import web                                  # noqa: E402
from reconone.auth import Auth, AuthError                 # noqa: E402
from tests import fixture_server                          # noqa: E402

HEADERS = {"X-Recon-Request": "1", "Content-Type": "application/json"}


def _post(url, payload, extra=None, opener=None):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={**HEADERS, **(extra or {})})
    try:
        with (opener or urllib.request).urlopen(req, timeout=10) as res:
            return res.status, json.loads(res.read() or b"{}"), res.headers
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}"), exc.headers


def _get(url, opener=None, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with (opener or urllib.request).urlopen(req, timeout=10) as res:
            return res.status, res.read(), res.headers
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), exc.headers


class TestAuth(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def test_token_is_single_use_and_never_stored_as_plaintext(self):
        auth = Auth(self.dir)
        token = auth.issue_token()
        auth.claim(token, "CorrectHorse9x")
        self.assertTrue(auth.configured)
        with open(auth.store.state_file, encoding="utf-8") as fh:
            blob = fh.read()
        self.assertNotIn(token, blob)          # the token itself is gone from disk
        self.assertNotIn("CorrectHorse9x", blob)
        with self.assertRaises(AuthError):
            Auth(self.dir).claim(token, "AnotherHorse9x")

    def test_weak_password_is_refused(self):
        auth = Auth(self.dir)
        token = auth.issue_token()
        for bad in ("short", "1234567890123", "abcdefghijklm"):
            with self.assertRaises(AuthError):
                auth.claim(token, bad)
        self.assertFalse(auth.configured)

    def test_state_stays_inside_the_run_directory(self):
        auth = Auth(self.dir)
        auth.issue_token()
        self.assertTrue(auth.store.state_file.startswith(os.path.abspath(self.dir)))


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        cls.srv = web.Server(("127.0.0.1", 0), cls.root, "test")
        cls.port = cls.srv.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.root, True)

    def test_state_does_not_leak_the_pairing_token(self):
        status, body, _ = _get(self.base + "/api/state")
        self.assertEqual(status, 200)
        self.assertNotIn("token", json.dumps(json.loads(body)).lower().replace("token_issued", ""))

    def test_report_and_events_require_a_session(self):
        """Anonymous GET must not hand out the report package or the stage log.

        Both used to answer 200 without a cookie, which leaked everything the scan found
        as soon as the console was bound to anything but loopback.
        """
        status, body, _ = _get(self.base + "/api/report")
        self.assertEqual(status, 401, body)
        status, body, _ = _get(self.base + "/api/events?since=0")
        self.assertEqual(status, 401, body)
        # /api/state stays reachable (the login gate needs to know if a password exists),
        # but it must not carry the target, the run directory or the event log.
        status, body, _ = _get(self.base + "/api/state")
        self.assertEqual(status, 200)
        job = json.loads(body).get("job") or {}
        for leaked in ("events", "target", "out_dir", "summary"):
            self.assertNotIn(leaked, job, f"/api/state 未登录时不得返回 {leaked}")
        self.assertIn("state", job)

    def _cookie(self):
        """One session for the whole class; the password is shared by every test here."""
        cls = type(self)
        cached = getattr(cls, "_cookie_cache", None)
        if cached:
            return cached
        if self.srv.auth.configured:
            status, _, headers = _post(self.base + "/api/login",
                                       {"password": "CorrectHorse9x"})
        else:
            status, _, headers = _post(self.base + "/api/claim",
                                       {"token": self.srv.auth.issue_token(),
                                        "password": "CorrectHorse9x"})
        cookie = headers.get("Set-Cookie").split(";")[0]
        cls._cookie_cache = cookie
        return cookie

    def test_runs_api_lists_selects_and_deletes(self):
        """产物管理：列表 / 切换 / 按名字读报告 / 删除（需二次确认，且不许越界）。"""
        cookie = self._cookie()
        run = os.path.join(self.root, "runs", "managed.example")
        os.makedirs(os.path.join(run, "report"), exist_ok=True)
        payload = {
            "target": {"domain": "managed.example", "root_url": "https://managed.example/"},
            "meta": {"generated_at": "2026-01-01T00:00:00Z"},
            "coverage": {"counts": {"endpoints": 3, "findings": 1}, "probes": {}},
            "assets": {"http": {}}, "endpoints": [], "parameters": [], "specs": [],
            "graphql": [], "findings": [], "hypotheses": [], "errors": [], "secrets": [],
        }
        with open(os.path.join(run, "report", "report.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        status, body, _ = _get(self.base + "/api/runs", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        entry = next((r for r in json.loads(body)["runs"] if r["run"] == "managed.example"), None)
        self.assertIsNotNone(entry, "runs 列表必须包含新产物")
        self.assertTrue(entry["has_report"])
        self.assertEqual(entry["counts"]["endpoints"], 3)

        status, _, _ = _post(self.base + "/api/runs/select", {"run": "managed.example"},
                             {"Cookie": cookie})
        self.assertEqual(status, 200)
        status, body, _ = _get(self.base + "/api/report?run=managed.example",
                               headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["target"]["domain"], "managed.example")

        status, _, _ = _post(self.base + "/api/runs/delete", {"run": "managed.example"},
                             {"Cookie": cookie})
        self.assertEqual(status, 400, "删除必须二次确认")
        status, _, _ = _post(self.base + "/api/runs/delete",
                             {"run": "../../etc", "confirm": True}, {"Cookie": cookie})
        self.assertEqual(status, 404, "越界路径必须被拒绝")
        self.assertTrue(os.path.isdir(run), "未确认的删除不得动到磁盘")

        status, _, _ = _post(self.base + "/api/runs/delete",
                             {"run": "managed.example", "confirm": True}, {"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertFalse(os.path.isdir(run))

    def test_compare_lists_every_run_with_three_decision_axes(self):
        """横向对比：需要会话；每行给出 worth/ease/index 与原始计数。"""
        status, _, _ = _get(self.base + "/api/compare")
        self.assertEqual(status, 401, "对比表是侦察数据，匿名不得读取")
        cookie = self._cookie()
        run = os.path.join(self.root, "runs", "cmp.example")
        os.makedirs(os.path.join(run, "report"), exist_ok=True)
        payload = {
            "target": {"domain": "cmp.example", "root_url": "https://cmp.example/"},
            "meta": {"generated_at": "2026-02-02T00:00:00Z"},
            "coverage": {"counts": {"endpoints": 4, "subdomains": 2}, "probes": {}},
            "assets": {"http": {"headers": {}}}, "endpoints": [], "parameters": [],
            "specs": [], "graphql": [], "findings": [], "hypotheses": [], "errors": [],
            "secrets": [],
            # A hand-written profile must NOT pass through: score/profile/bet are all
            # recomputed on read, so a stale conclusion cannot survive because it is on disk.
            "profile": {"axes": {"worth": {"score": 3.0}, "hardness": {"score": 97.0}},
                        "success": {"index": 7, "band": "low", "label": "旧结论"},
                        "weights": {"observed_share_pct": 1.0}},
        }
        with open(os.path.join(run, "report", "report.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh)

        status, body, _ = _get(self.base + "/api/compare", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        data = json.loads(body)
        row = next(r for r in data["runs"] if r["run"] == "cmp.example")
        self.assertNotEqual(row["worth"], 3.0, "旧 profile 不得借缓存还魂")
        self.assertNotEqual(row["index"], 7)
        if row["hardness"] is not None:
            self.assertEqual(row["ease"], round(100.0 - row["hardness"], 1),
                             "易度 = 100 - 难度（按重算后的难度）")
        self.assertEqual(row["counts"]["endpoints"], 4)
        self.assertEqual(row["bet"], "withheld", "没有验证证据的旧报告只能 withheld")
        self.assertEqual(row["verdict"], "证据不足")
        self.assertEqual(data["axes"], ["worth", "ease", "index"])
        self.assertTrue(data["note"])
        self.assertFalse(row["error"])
        shutil.rmtree(run, True)

    def test_cross_site_post_is_refused(self):
        status, body, _ = _post(self.base + "/api/login", {"password": "x"}, {"X-Recon-Request": ""})
        self.assertEqual(status, 403)

    def test_report_is_rescored_on_read(self):
        """A stale verdict must not survive simply because it is on disk."""
        run = os.path.join(self.root, "runs", "t.example")
        os.makedirs(os.path.join(run, "report"), exist_ok=True)
        report = {
            "target": {"domain": "t.example", "root_url": "https://t.example/"},
            "assets": {"http": {"root_url": "https://t.example/", "headers": {}}},
            "coverage": {"counts": {"pages": 1, "endpoints": 12},
                         "probe_status": {}, "truncated": False},
            "endpoints": [{"path": f"/api/x{i}/", "methods": ["POST"], "params": []}
                          for i in range(12)],
            "parameters": [],
            # The conclusion an older build would have written:
            "score": {"triage": {"verdict": "low-yield",
                                 "label": "维护较好且成本不低，酌情放弃"}},
        }
        with open(os.path.join(run, "report", "report.json"), "w", encoding="utf-8") as fh:
            json.dump(report, fh)

        self.srv.job.out_dir = run
        self.srv.job.state = "done"

        # Authenticate through the shared session helper: the password is already set by
        # whichever test ran first, and the one-time token is deliberately single use.
        cookie = self._cookie()

        status, body, _ = _get(self.base + "/api/report", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        triage = payload["score"]["triage"]
        # score, profile and bet are all derived; none may be read back from disk.
        self.assertIn("profile", payload)
        self.assertIn("bet", payload)
        self.assertEqual(payload["bet"]["verdict"], "withheld")
        # The old verdict must never be echoed back, whatever the new score computes.
        self.assertNotEqual(triage["verdict"], "low-yield")
        self.assertNotIn("酌情放弃", triage.get("label", ""))
        # This fixture has no headers, so coverage legitimately collapses and the model
        # says so instead of guessing. Either way it must state its blind spots.
        self.assertIn(triage["verdict"], ("worthwhile", "insufficient-evidence"))
        self.assertTrue(triage.get("blind_spots"))

class TestScanExecution(unittest.TestCase):
    """The scan path had two silent-failure bugs that made the UI look broken:

    * `cancel` was a threading.Event but cli.emit called it, so every run died at stage 0
      with TypeError and a 0% bar.
    * a non-zero exit code set state=error with no accompanying message.
    """

    def test_event_cancel_object_is_accepted(self):
        import threading
        from reconone import cli

        seen = []
        ev = threading.Event()
        # No network is reached: the cancel check runs immediately after the first emit.
        ev.set()
        with self.assertRaises(Exception):
            cli.run_scan("example.invalid", tempfile.mkdtemp(), "fast",
                         use_dns=False, quiet=True,
                         on_event=seen.append, cancel=ev)
        self.assertTrue(seen, "on_event must fire before cancellation is honoured")
        self.assertEqual(seen[0]["stage"], "start")
        self.assertIn("progress", seen[0])

    def test_progress_is_monotonic_and_ends_at_100(self):
        """A run that ends — even by failing — must finish the bar, not freeze it."""
        from reconone import cli
        stages = []
        cli.run_scan("example.invalid", tempfile.mkdtemp(), "fast",
                     use_dns=False, quiet=True, on_event=stages.append)
        prog = [s["progress"] for s in stages if "progress" in s]
        self.assertEqual(prog, sorted(prog), "progress must never go backwards")
        self.assertEqual(prog[-1], 100)
        self.assertGreater(len(set(prog)), 3, "a 0-to-100 bar needs more than a few steps")


class TestRememberedSessions(unittest.TestCase):
    """The password is set once; a browser that logged in keeps working after a restart."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _configured(self):
        auth = Auth(self.dir)
        auth.claim(auth.issue_token(), "CorrectHorse9x")
        return auth

    def test_session_is_remembered_across_a_restart(self):
        sid = self._configured().login("CorrectHorse9x")
        restarted = Auth(self.dir)          # a new console process on the same run dir
        self.assertTrue(restarted.session_valid(sid))

    def test_logout_forgets_the_session_on_disk(self):
        auth = self._configured()
        sid = auth.login("CorrectHorse9x")
        auth.logout(sid)
        self.assertFalse(Auth(self.dir).session_valid(sid))

    def test_raw_session_id_is_never_written_to_disk(self):
        auth = self._configured()
        sid = auth.login("CorrectHorse9x")
        with open(auth.session_file, encoding="utf-8") as fh:
            blob = fh.read()
        self.assertNotIn(sid, blob, "sessions.json 里只能是哈希，不是可直接使用的令牌")

    def test_setting_the_password_drops_pre_existing_sessions(self):
        auth = Auth(self.dir)
        token = auth.issue_token()
        auth.sessions["stale"] = time.time() + 3600
        auth._save_sessions()
        auth.claim(token, "CorrectHorse9x")
        self.assertFalse(Auth(self.dir).session_valid("stale"))


class TestParallelTargets(unittest.TestCase):
    """One batch, several sites: each target keeps its own state and run directory."""

    def test_batch_tracks_every_target(self):
        root = tempfile.mkdtemp()
        srv = web.Server(("127.0.0.1", 0), root, "test")
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(shutil.rmtree, root, True)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        try:
            token = srv.auth.issue_token()
            status, _, headers = _post(base + "/api/claim",
                                       {"token": token, "password": "CorrectHorse9x"})
            cookie = headers.get("Set-Cookie").split(";")[0]
            targets = ["127.0.0.1:1", "127.0.0.1:2"]      # closed ports: fail fast, stay offline
            status, body, _ = _post(base + "/api/scan",
                                    {"targets": targets, "profile": "fast", "use_dns": False},
                                    {"Cookie": cookie})
            self.assertEqual(status, 200, body)
            self.assertEqual(body["targets"], targets)
            self.assertEqual(body["parallel"], min(2, web.MAX_TARGET_PARALLEL))

            deadline = time.time() + 120
            while time.time() < deadline and srv.job.state == "running":
                time.sleep(0.2)
            self.assertNotEqual(srv.job.state, "running", "批次必须在超时内结束")
            states = {t["target"]: t["state"] for t in srv.job.targets}
            self.assertEqual(set(states), set(targets), "每个目标都要有自己的进度条目")
            self.assertTrue(all(v == "error" for v in states.values()), states)
            runs = os.listdir(os.path.join(root, "runs"))
            self.assertEqual(len(runs), 2, f"每个目标一个独立产物目录，实际 {runs}")
        finally:
            srv.shutdown()
            srv.server_close()


class TestConsoleSessionPassThrough(unittest.TestCase):
    """The console body fields must reach the report, and the progress stream must still flow.

    A batch was previously able to drop `on_event`/`cancel` while still returning a report; the
    scan then finished silently with an empty stage log. Both are asserted here because both
    are invisible in the report itself.
    """

    def test_cookie_bearer_rate_reach_the_report_and_events_flow(self):
        fixture = fixture_server.start()
        root = tempfile.mkdtemp()
        srv = web.Server(("127.0.0.1", 0), root, "test")
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(shutil.rmtree, root, True)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.addCleanup(fixture_server.stop, fixture)
        token = srv.auth.issue_token()
        status, _, headers = _post(base + "/api/claim",
                                   {"token": token, "password": "CorrectHorse9x"})
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie").split(";")[0]
        target = f"127.0.0.1:{fixture_server.PORT_HOLDER['port']}"
        status, body, _ = _post(base + "/api/scan", {
            "targets": [target], "profile": "fast", "use_js": False, "use_intel": False,
            "verify": False, "direct": True, "rate": 50,
            "cookie": "sid=WEBSECRET; role=ops", "bearer": "WEBBEARER",
            "headers": ["X-Api-Key: WEBKEY"],
        }, {"Cookie": cookie})
        self.assertEqual(status, 200, body)

        deadline = time.time() + 120
        while time.time() < deadline and srv.job.state == "running":
            time.sleep(0.2)
        self.assertEqual(srv.job.state, "done", srv.job.events[-3:])
        self.assertTrue(srv.job.events, "进度事件流不能为空（on_event 被丢掉时会静默失败）")

        out_dir = srv.job.targets[0]["out_dir"]
        with open(os.path.join(out_dir, "report", "report.json"), encoding="utf-8") as fh:
            report = json.load(fh)
        sess = report["meta"]["session"]
        self.assertEqual(sess["source"], "web")
        self.assertEqual(sess["cookie_names"], ["sid", "role"])
        self.assertTrue(sess["bearer"])
        self.assertIn("X-Api-Key", sess["headers"])
        self.assertEqual(report["meta"]["rate"]["rate_per_s"], 50.0)
        self.assertGreater(report["meta"]["rate"]["waits"], 0)
        self.assertEqual(report["assets"]["http"]["status"], 200, "必须真的打到目标")
