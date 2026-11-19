"""Session injection + per-host pacing.

Two claims are tested here, and they pull in opposite directions:

* the credentials **must** reach the target — a scan that silently drops the cookie is a scan
  that mislabels every protected endpoint;
* the credentials **must never** reach the disk — the report records names and shapes only.

The pacing side is tested with an injected clock, because a test that sleeps for real is a
test that fails on a loaded machine. The wire-level test keeps one real sleep in place: it is
the only way to prove `Session` actually consults the limiter.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import inject as injectmod  # noqa: E402
from reconone import rate as ratemod  # noqa: E402
from reconone.cli import run_scan  # noqa: E402
from reconone.http import Session  # noqa: E402
from tests import fixture_server  # noqa: E402
from reconone import egress as egressmod  # noqa: E402

COOKIE = "sid=S3CRETCOOKIE; role=admin"
BEARER = "S3CRETBEARER"
APIKEY = "S3CRETAPIKEY"
SECRETS = ("S3CRETCOOKIE", "S3CRETBEARER", "S3CRETAPIKEY")


class _Recorder:
    """Headers of every request, so a test can assert what actually went out."""

    def __init__(self):
        self.lock = threading.Lock()
        self.seen: list[dict] = []
        self.times: list[float] = []

    def note(self, headers, path: str) -> None:
        with self.lock:
            self.seen.append({k.lower(): v for k, v in headers.items()})
            self.times.append(time.monotonic())

    @property
    def last(self) -> dict:
        with self.lock:
            return self.seen[-1] if self.seen else {}


class _Quiet(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass


def _serve(handler_class):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_class)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _recording_site(recorder: _Recorder, status: int = 200, extra_headers=None):
    class Handler(_Quiet):
        def do_GET(self):                      # noqa: N802
            recorder.note(dict(self.headers.items()), self.path)
            body = b"ok"
            self.send_response(status)
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


class TestInjectionReachesServer(unittest.TestCase):
    """A credential that does not arrive is worse than none: it looks like a 401 finding."""

    def setUp(self):
        self.recorder = _Recorder()
        self.server, self.port = _serve(_recording_site(self.recorder))
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _session(self, injection) -> Session:
        return Session("127.0.0.1", timeout=3, injection=injection)

    def test_cookie_and_bearer_arrive(self):
        inj = injectmod.build("sid=abc; role=admin", "tok123")
        self._session(inj).request(self.base + "/x")
        headers = self.recorder.last
        self.assertEqual(headers.get("cookie"), "sid=abc; role=admin")
        self.assertEqual(headers.get("authorization"), "Bearer tok123")

    def test_custom_header_arrives(self):
        inj = injectmod.build(headers=["X-Api-Key: key789", "X-Tenant: acme"])
        self._session(inj).request(self.base + "/x")
        headers = self.recorder.last
        self.assertEqual(headers.get("x-api-key"), "key789")
        self.assertEqual(headers.get("x-tenant"), "acme")

    def test_injection_overrides_caller_header_case_insensitively(self):
        inj = injectmod.build(bearer="fresh")
        self._session(inj).request(self.base + "/x", headers={"authorization": "Bearer stale"})
        self.assertEqual(self.recorder.last.get("authorization"), "Bearer fresh")

    def test_no_injection_keeps_the_request_untouched(self):
        base = {"X-Keep": "1"}
        self.assertIs(injectmod.Injection().apply(base), base, "无注入时不应复制或改写 headers")
        self._session(injectmod.Injection()).request(self.base + "/x")
        self.assertNotIn("cookie", self.recorder.last)
        self.assertNotIn("authorization", self.recorder.last)

    def test_injected_headers_survive_a_redirect(self):
        inj = injectmod.build(bearer="tok")
        inj_headers: list[dict] = []

        class Handler(_Quiet):
            def do_GET(self):                  # noqa: N802
                inj_headers.append({k.lower(): v for k, v in self.headers.items()})
                if self.path == "/old":
                    self.send_response(302)
                    self.send_header("Location", "/new")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server, port = _serve(Handler)
        try:
            Session("127.0.0.1", timeout=3, injection=inj).request(f"http://127.0.0.1:{port}/old")
            self.assertEqual(len(inj_headers), 2)
            self.assertEqual(inj_headers[0].get("authorization"), "Bearer tok")
            self.assertEqual(inj_headers[1].get("authorization"), "Bearer tok")
        finally:
            server.shutdown()
            server.server_close()


class TestDescribeHoldsNoValues(unittest.TestCase):
    """`meta.session` is the only exposure of credentials; it must be worthless to an attacker."""

    def test_describe_lists_names_not_values(self):
        inj = injectmod.build(COOKIE, BEARER, [f"X-Api-Key: {APIKEY}"])
        text = json.dumps(inj.describe(), ensure_ascii=False)
        for secret in SECRETS:
            self.assertNotIn(secret, text)
        data = inj.describe()
        self.assertTrue(data["enabled"])
        self.assertTrue(data["bearer"])
        self.assertEqual(data["cookie_names"], ["sid", "role"])
        self.assertIn("X-Api-Key", data["headers"])
        self.assertIn("Authorization", data["secret_headers"])
        self.assertIn("Cookie", data["secret_headers"])

    def test_describe_of_nothing_is_explicitly_disabled(self):
        data = injectmod.Injection().describe()
        self.assertFalse(data["enabled"])
        self.assertEqual(data["headers"], [])
        self.assertEqual(data["cookie_names"], [])

    def test_build_returns_empty_injection_when_nothing_is_given(self):
        inj = injectmod.build("", "", [])
        self.assertFalse(inj.enabled)
        self.assertEqual(inj.describe()["source"], "cli")

    def test_explicit_header_wins_over_the_flag_shorthand(self):
        inj = injectmod.build(bearer="from-flag", headers=["Authorization: Bearer from-header"])
        self.assertEqual(dict(inj.headers)["Authorization"], "Bearer from-header")

    def test_from_env_reads_all_three_sources(self):
        keys = ("RECONONE_COOKIE", "RECONONE_BEARER", "RECONONE_HEADERS")
        saved = {k: os.environ.get(k) for k in keys}
        try:
            os.environ["RECONONE_COOKIE"] = "a=1"
            os.environ["RECONONE_BEARER"] = "envtok"
            os.environ["RECONONE_HEADERS"] = "X-One: 1\r\nX-Two: 2\n"
            inj = injectmod.from_env()
            self.assertEqual(inj.describe()["source"], "env")
            names = dict(inj.headers)
            self.assertEqual(names["Cookie"], "a=1")
            self.assertEqual(names["Authorization"], "Bearer envtok")
            self.assertEqual(names["X-One"], "1")
            self.assertEqual(names["X-Two"], "2")
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_from_env_without_variables_is_empty(self):
        keys = ("RECONONE_COOKIE", "RECONONE_BEARER", "RECONONE_HEADERS")
        saved = {k: os.environ.pop(k, None) for k in keys}
        try:
            self.assertFalse(injectmod.from_env().enabled)
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

    def test_parse_header_specs_rejects_malformed_input(self):
        for bad in ("NoColonHere", ": value", "Name: ", "Name:"):
            with self.assertRaises(ValueError, msg=bad):
                injectmod.parse_header_specs([bad])
        with self.assertRaises(ValueError):
            injectmod.parse_header_specs(["X-A: a\rb"])
        self.assertEqual(injectmod.parse_header_specs(["", "   "]), [])
        self.assertEqual(injectmod.parse_header_specs(["X-A: v:w"]), [("X-A", "v:w")],
                         "值里的冒号必须保留")


class _FakeClock:
    """Monotonic clock that only advances when someone sleeps on it."""

    def __init__(self, start: float = 1000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += max(0.0, seconds)


def _limiter(**kwargs) -> tuple[ratemod.Limiter, _FakeClock]:
    clock = _FakeClock()
    kwargs.setdefault("clock", clock)
    kwargs.setdefault("sleep", clock.sleep)
    return ratemod.Limiter(**kwargs), clock


class TestLimiterPacing(unittest.TestCase):
    def test_interval_is_enforced_per_request(self):
        limiter, clock = _limiter(rate=2.0)               # 0.5s interval
        waits = [limiter.before("example.com") for _ in range(3)]
        self.assertEqual(waits[0], 0.0, "第一个请求不该等待")
        self.assertAlmostEqual(waits[1], 0.5, places=3)
        self.assertAlmostEqual(waits[2], 0.5, places=3)
        self.assertAlmostEqual(clock.t, 1001.0, places=3)
        stats = limiter.stats()
        self.assertEqual(stats["rate_per_s"], 2.0)
        self.assertEqual(stats["interval_ms"], 500.0)
        self.assertEqual(stats["waits"], 2)
        self.assertAlmostEqual(stats["slept_s"], 1.0, places=3)

    def test_hosts_are_paced_independently(self):
        limiter, _clock = _limiter(rate=1.0)              # 1s interval
        self.assertEqual(limiter.before("a.test"), 0.0)
        self.assertEqual(limiter.before("b.test"), 0.0, "一个 host 忙不该拖慢另一个")
        self.assertAlmostEqual(limiter.before("a.test"), 1.0, places=3)
        self.assertEqual(limiter.before("b.test"), 0.0)

    def test_rate_zero_never_sleeps(self):
        limiter, clock = _limiter(rate=0.0)
        for _ in range(5):
            self.assertEqual(limiter.before("example.com"), 0.0)
        self.assertEqual(clock.t, 1000.0)
        self.assertEqual(limiter.stats()["waits"], 0)
        self.assertEqual(limiter.stats()["interval_ms"], 0.0)

    def test_retry_after_is_honoured(self):
        limiter, _clock = _limiter(rate=0.0)
        limiter.after("example.com", 429, {"retry-after": "2"})
        self.assertAlmostEqual(limiter.before("example.com"), 2.0, places=3)
        self.assertEqual(limiter.stats()["throttled"], 1)
        self.assertAlmostEqual(limiter.stats()["max_backoff_s"], 2.0, places=3)

    def test_backoff_doubles_then_caps(self):
        limiter, clock = _limiter(rate=0.0, base_backoff=0.5, max_backoff=8.0)
        seen = []
        for _ in range(6):
            limiter.after("h.test", 503, {})
            seen.append(round(limiter.hosts["h.test"]["block_until"] - clock.t, 3))
        self.assertEqual(seen, [0.5, 1.0, 2.0, 4.0, 8.0, 8.0])
        self.assertAlmostEqual(limiter.stats()["max_backoff_s"], 8.0, places=3)

    def test_success_resets_the_backoff(self):
        limiter, clock = _limiter(rate=0.0, base_backoff=0.5, max_backoff=8.0)
        limiter.after("h.test", 429, {})
        limiter.after("h.test", 429, {})
        self.assertEqual(limiter.hosts["h.test"]["strikes"], 2)
        clock.t = limiter.hosts["h.test"]["block_until"]
        limiter.after("h.test", 200, {})
        self.assertEqual(limiter.hosts["h.test"]["strikes"], 0)
        limiter.after("h.test", 429, {})
        self.assertAlmostEqual(limiter.hosts["h.test"]["block_until"] - clock.t, 0.5, places=3)

    def test_one_wait_is_capped_so_a_hostile_retry_after_cannot_stall_the_scan(self):
        limiter, _clock = _limiter(rate=0.0, max_wait=5.0)
        limiter.after("h.test", 429, {"retry-after": "600"})
        self.assertAlmostEqual(limiter.before("h.test"), 5.0, places=3)

    def test_deadline_shrinks_the_wait(self):
        limiter, clock = _limiter(rate=0.0, max_wait=30.0)
        limiter.after("h.test", 429, {"retry-after": "10"})
        waited = limiter.before("h.test", deadline=clock.t + 0.25)
        self.assertAlmostEqual(waited, 0.25, places=3)

    def test_a_non_throttling_status_is_not_a_throttle(self):
        limiter, _clock = _limiter(rate=0.0)
        for status in (200, 404, 500):
            limiter.after("h.test", status, {})
        self.assertEqual(limiter.stats()["throttled"], 0)
        self.assertEqual(limiter.before("h.test"), 0.0)

    def test_stats_only_list_hosts_that_were_used(self):
        limiter, _clock = _limiter(rate=0.0)
        limiter.before("idle.test")
        limiter.after("busy.test", 200, {})
        hosts = limiter.stats()["hosts"]
        self.assertEqual(list(hosts), ["busy.test"])
        self.assertEqual(hosts["busy.test"]["requests"], 1)


class TestPacingOnTheWire(unittest.TestCase):
    """The limiter is only real if `Session` consults it; this keeps one genuine sleep."""

    def setUp(self):
        self.recorder = _Recorder()
        self.server, self.port = _serve(_recording_site(self.recorder))
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_three_requests_respect_the_interval(self):
        limiter = ratemod.Limiter(20.0)                    # 50ms interval
        session = Session("127.0.0.1", timeout=3, limiter=limiter)
        started = time.monotonic()
        for path in ("/a", "/b", "/c"):
            self.assertEqual(session.request(self.base + path).status, 200)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.085, "两次等待应合计约 100ms")
        waits = [entry.get("wait_ms", 0) for entry in session.log]
        self.assertEqual(len(waits), 3)
        self.assertEqual(waits[0], 0, "第一个请求不等待")
        self.assertGreaterEqual(sum(waits), 85)
        self.assertEqual(limiter.stats()["waits"], 2)

    def test_unlimited_rate_records_no_wait(self):
        limiter = ratemod.Limiter(0.0)
        session = Session("127.0.0.1", timeout=3, limiter=limiter)
        for path in ("/a", "/b", "/c"):
            session.request(self.base + path)
        self.assertEqual([e.get("wait_ms") for e in session.log], [0, 0, 0])
        self.assertEqual(limiter.stats()["waits"], 0)

    def test_429_pushes_the_next_request_back(self):
        recorder = _Recorder()
        server, port = _serve(_recording_site(recorder, status=429,
                                              extra_headers={"Retry-After": "1"}))
        try:
            limiter = ratemod.Limiter(0.0)
            session = Session("127.0.0.1", timeout=5, limiter=limiter)
            started = time.monotonic()
            self.assertEqual(session.request(f"http://127.0.0.1:{port}/a").status, 429)
            self.assertEqual(session.request(f"http://127.0.0.1:{port}/a").status, 429)
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 0.9, "Retry-After: 1 必须被等待")
            stats = limiter.stats()
            self.assertEqual(stats["throttled"], 2)
            self.assertGreaterEqual(stats["max_backoff_s"], 1.0)
            self.assertEqual(stats["hosts"][f"127.0.0.1"]["throttles"], 2)
        finally:
            server.shutdown()
            server.server_close()


class TestSessionMetaInReport(unittest.TestCase):
    """End to end: a real scan carries the credentials and still writes none of them."""

    @classmethod
    def setUpClass(cls):
        cls.server = fixture_server.start()
        cls.target = f"127.0.0.1:{fixture_server.PORT_HOLDER['port']}"
        cls.tmp = tempfile.mkdtemp(prefix="recon-one-session-")
        cls.out = os.path.join(cls.tmp, "run")
        cls.report, cls.code = run_scan(
            cls.target, cls.out, "fast", {"max_pages": 3},
            use_dns=False, use_js=False, use_intel=False, use_verify=False,
            cookie=COOKIE, bearer=BEARER, headers=[f"X-Api-Key: {APIKEY}"], rate=100.0,
            egress=egressmod.resolve("direct"), quiet=True)

    @classmethod
    def tearDownClass(cls):
        fixture_server.stop(cls.server)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_session_is_recorded_as_a_shape(self):
        sess = self.report["meta"]["session"]
        self.assertTrue(sess["enabled"])
        self.assertEqual(sess["source"], "cli")
        self.assertEqual(sess["cookie_names"], ["sid", "role"])
        self.assertTrue(sess["bearer"])
        self.assertIn("X-Api-Key", sess["headers"])
        self.assertIn("Cookie", sess["secret_headers"])
        self.assertIn("Authorization", sess["secret_headers"])

    def test_rate_configuration_is_recorded(self):
        rate = self.report["meta"]["rate"]
        self.assertEqual(rate["rate_per_s"], 100.0)
        self.assertEqual(rate["interval_ms"], 10.0)
        self.assertIn("hosts", rate)
        self.assertTrue(rate["note"])

    def test_the_scan_actually_reached_the_target(self):
        """An unreachable target still produces `meta.session`; that must not pass as success."""
        self.assertEqual(self.report["assets"]["http"]["status"], 200)
        self.assertGreaterEqual(self.report["coverage"]["counts"]["pages"], 1)
        self.assertGreater(self.report["meta"]["rate"]["hosts"]["127.0.0.1"]["requests"], 0)

    def test_no_credential_reaches_any_written_file(self):
        suspects = []
        for root, _dirs, files in os.walk(self.out):
            for name in files:
                path = os.path.join(root, name)
                if path.lower().endswith((".json", ".md", ".txt", ".html", ".ndjson", ".csv")):
                    suspects.append(path)
        self.assertTrue(suspects, "扫描至少应写出 report.json")
        for path in suspects:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for secret in SECRETS:
                self.assertNotIn(secret, text, f"{os.path.basename(path)} 泄露了凭据")

    def test_markdown_says_what_was_carried_and_what_it_costs(self):
        with open(os.path.join(self.out, "report", "report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("会话与速率", text)
        self.assertIn("Cookie 名称：sid, role", text)
        self.assertIn("Bearer", text)
        self.assertIn("100.0/s per host", text)

    def test_digest_ignores_who_we_were(self):
        from reconone.report import _digest_view
        other = json.loads(json.dumps(self.report))
        other["meta"]["session"] = {"enabled": False}
        other["meta"]["rate"] = {"rate_per_s": 0.0, "hosts": {}}
        self.assertEqual(_digest_view(self.report), _digest_view(other))


if __name__ == "__main__":
    unittest.main(verbosity=2)
