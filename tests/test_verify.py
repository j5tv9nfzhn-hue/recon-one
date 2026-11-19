"""Light verification: one GET per endpoint, bound by RoE and the scope guard.

What is asserted here is exactly what the console shows: **可用（红）** for endpoints the
server actually answered, **不可用（灰）** for dead ones — and, just as important, that the
requests which were *not* sent are recorded with the rule that stopped them.
"""
from __future__ import annotations

import http.server
import os
import socketserver
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import egress as egressmod  # noqa: E402
from reconone import verify as verifymod  # noqa: E402
from reconone.http import Session, probe_tls_certificate  # noqa: E402


class _Counter:
    def __init__(self):
        self.lock = threading.Lock()
        self.paths: list[str] = []
        self.connects: list[str] = []

    def hit(self, path: str) -> None:
        with self.lock:
            self.paths.append(path)

    def connect(self, target: str) -> None:
        with self.lock:
            self.connects.append(target)


def _serve(handler_class):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_class)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class _Quiet(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass


def _site_factory(counter: _Counter):
    class Handler(_Quiet):
        def do_GET(self):                      # noqa: N802
            counter.hit(self.path)
            status = {"/ok": 200, "/protected": 401, "/gone": 404,
                      "/broken": 500, "/needs": 400, "/logout": 200}.get(self.path, 404)
            body = b"x"
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


def _endpoints(paths):
    return [{"path": path, "methods": ["GET"], "params": []} for path in paths]


class TestVerdicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.counter = _Counter()
        cls.server, cls.port = _serve(_site_factory(cls.counter))
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.session = Session("127.0.0.1", timeout=3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _run(self, paths, **roe_kwargs):
        roe = verifymod.build_roe("127.0.0.1", **roe_kwargs)
        return verifymod.run(self.session, self.base, _endpoints(paths), roe)

    def test_answered_paths_are_usable_and_dead_ones_are_unusable(self):
        block = self._run(["/ok", "/protected", "/gone", "/broken", "/needs"])
        verdicts = {r["path"]: r["verdict"] for r in block["results"]}
        self.assertEqual(verdicts["/ok"], verifymod.USABLE)
        self.assertEqual(verdicts["/protected"], verifymod.USABLE, "401 说明端点存在，标红")
        self.assertEqual(verdicts["/gone"], verifymod.UNUSABLE)
        self.assertEqual(verdicts["/broken"], verifymod.UNUSABLE)
        self.assertEqual(verdicts["/needs"], verifymod.UNUSABLE)
        for entry in block["results"]:
            if entry["verdict"] == verifymod.UNUSABLE:
                self.assertTrue(entry["reason"], f"{entry['path']} 灰必须有原因")
        summary = block["summary"]
        self.assertEqual(summary["usable"] + summary["unusable"], 5)
        self.assertEqual(summary["requests"], 5)

    def test_destructive_paths_are_skipped_not_probed(self):
        before = len(self.counter.paths)
        block = self._run(["/logout", "/ok"])
        self.assertEqual(self.counter.paths[before:], ["/ok"], "logout 不能被请求")
        logout = next(r for r in block["results"] if r["path"] == "/logout")
        self.assertEqual(logout["verdict"], verifymod.SKIPPED)
        self.assertTrue(logout["audit"]["excluded"])
        self.assertEqual(logout["audit"]["requests_used"], 0)
        self.assertIn("excluded", logout["reason"])

    def test_budget_caps_requests_and_records_what_was_dropped(self):
        block = self._run(["/ok", "/protected", "/gone", "/broken"], max_requests=2)
        self.assertEqual(block["summary"]["requests"], 2)
        skipped = [r for r in block["results"] if r["verdict"] == verifymod.SKIPPED]
        self.assertEqual(len(skipped), 2)
        self.assertTrue(all("budget" in r["reason"] for r in skipped))
        self.assertTrue(all(r["audit"]["requests_used"] == 0 for r in skipped))

    def test_disabled_verification_sends_nothing_but_is_recorded(self):
        before = len(self.counter.paths)
        block = self._run(["/ok"], enabled=False)
        self.assertEqual(len(self.counter.paths), before)
        self.assertFalse(block["enabled"])
        self.assertEqual(block["summary"]["requests"], 0)
        self.assertEqual(block["results"][0]["verdict"], verifymod.SKIPPED)
        self.assertIn("--no-verify", block["results"][0]["reason"])


class TestScopeGuardBinding(unittest.TestCase):
    """The engine must not send what the scope guard would refuse; refusals are recorded."""

    def test_off_scope_endpoint_is_not_requested(self):
        counter = _Counter()
        server, port = _serve(_site_factory(counter))
        try:
            session = Session("127.0.0.1", timeout=2)          # scope: this host only
            roe = verifymod.build_roe("127.0.0.1", max_requests=5)
            # base_url points somewhere else entirely, so every URL is out of scope
            block = verifymod.run(session, f"http://other.test:{port}",
                                  _endpoints(["/ok"]), roe)
            self.assertEqual(counter.paths, [], "越界请求不得发出")
            entry = block["results"][0]
            self.assertEqual(entry["verdict"], verifymod.SKIPPED)
            self.assertFalse(entry["audit"]["in_scope"])
            self.assertIn("scope guard", entry["reason"])
            self.assertEqual(block["summary"]["requests"], 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_roe_is_serialised_for_the_report(self):
        roe = verifymod.build_roe("example.com", allow_external=False, max_requests=7,
                                  source="test")
        data = roe.as_dict()
        self.assertEqual(data["scope_domain"], "example.com")
        self.assertEqual(data["max_requests"], 7)
        self.assertEqual(data["allowed_methods"], ["GET", "HEAD"])
        self.assertIn("logout", data["excluded"])
        self.assertIn("RoE", data["note"])

    def test_only_get_is_ever_sent(self):
        seen: list[str] = []

        class Handler(_Quiet):
            def do_GET(self):                  # noqa: N802
                seen.append("GET")
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):                 # noqa: N802
                seen.append("POST")
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        server, port = _serve(Handler)
        try:
            session = Session("127.0.0.1", timeout=2)
            roe = verifymod.build_roe("127.0.0.1", max_requests=3)
            verifymod.run(session, f"http://127.0.0.1:{port}", _endpoints(["/a", "/b"]), roe)
            self.assertEqual(seen, ["GET", "GET"])
        finally:
            server.shutdown()
            server.server_close()


class TestAnnotate(unittest.TestCase):
    def test_endpoints_get_the_verdict_stamped(self):
        verification = {"by_path": {"/ok": "usable", "/gone": "unusable"}}
        endpoints = _endpoints(["/ok", "/gone", "/unknown"])
        verifymod.annotate(endpoints, verification)
        self.assertEqual(endpoints[0]["verified"], "usable")
        self.assertEqual(endpoints[1]["verified"], "unusable")
        self.assertNotIn("verified", endpoints[2], "未验证的端点不应被错误标注")


class TestTlsProbeUsesEgress(unittest.TestCase):
    """The certificate probe must leave through the proxy, not dial direct."""

    def test_probe_goes_through_connect(self):
        counter = _Counter()

        class Proxy(_Quiet):
            def do_CONNECT(self):              # noqa: N802
                counter.connect(self.path)
                self.send_response(200, "Connection Established")
                self.end_headers()
                self.close_connection = True

        server, port = _serve(Proxy)
        try:
            egress = egressmod.resolve("manual", f"http://127.0.0.1:{port}")
            out = probe_tls_certificate("127.0.0.1", port=443, timeout=2, egress=egress)
            self.assertEqual(out["egress"], "proxy")
            self.assertTrue(counter.connects, "证书探测必须先问代理（CONNECT）")
            self.assertEqual(counter.connects[-1], "127.0.0.1:443")
            self.assertIn("error_kind", out)
        finally:
            server.shutdown()
            server.server_close()

    def test_direct_probe_still_reports_direct(self):
        out = probe_tls_certificate("127.0.0.1", port=1, timeout=1)
        self.assertEqual(out["egress"], "direct")
        self.assertIn("error_kind", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
