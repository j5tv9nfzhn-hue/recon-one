"""Subdomain liveness: criterion 2 must be an observation, not a certificate.

What is asserted here:
1. the classification table (gated / exposed / public / dead) — the only thing that can promote a
   target to `worth`, so it is tested as a table;
2. `probe()` behaviour: HTTPS → HTTP fallback only on transport failures, out-of-scope names
   recorded and **never requested**, and the host cap honoured;
3. the report merge (`_subdomain_assets`) and the bet sheet reading the result.
"""
from __future__ import annotations

import http.server
import os
import socketserver
import sys
import threading
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import subs, triage  # noqa: E402
from reconone.http import Session  # noqa: E402
from reconone.report import _subdomain_assets  # noqa: E402


class _FakeSession:
    """Records the URLs it was asked for and answers from a script."""

    def __init__(self, script):
        self.script = script
        self.calls: list[str] = []

    def request(self, url, method="GET", max_bytes=None):
        self.calls.append(url)
        status, error, body = self.script.get(url, (0, "refused: no route", b""))
        return SimpleNamespace(status=status, error=error, body=body, elapsed_ms=0)


class TestClassification(unittest.TestCase):
    def test_gated_statuses_are_a_non_public_face(self):
        for status in (401, 403):
            label, non_public = subs.classify(status, "api.example.com", "")
            self.assertEqual(label, "gated")
            self.assertTrue(non_public)

    def test_internal_looking_host_or_title_is_exposed(self):
        self.assertEqual(subs.classify(200, "jenkins.example.com", "Dashboard")[0], "exposed")
        self.assertEqual(subs.classify(200, "a.example.com", "Grafana")[0], "exposed")

    def test_marketing_page_is_public_not_evidence(self):
        label, non_public = subs.classify(200, "www.example.com", "Welcome to Example")
        self.assertEqual((label, non_public), ("public", False))

    def test_dead_and_error_are_not_evidence(self):
        self.assertEqual(subs.classify(404, "x.example.com", ""), ("dead", False))
        self.assertEqual(subs.classify(0, "x.example.com", ""), ("dead", False))
        self.assertEqual(subs.classify(500, "x.example.com", ""), ("error", False))

    def test_a_login_titled_page_counts_as_gated(self):
        body = b"<html><title>Sign in</title><form>...</form></html>"
        self.assertEqual(subs.classify(200, "x.example.com", "Sign in", body)[0], "gated")

    def test_a_login_host_with_a_plain_page_is_gated(self):
        body = b"<html><title>Welcome</title><input type='password'></html>"
        self.assertEqual(subs.classify(200, "login.example.com", "Welcome", body)[0], "gated")

    def test_a_nav_login_link_does_not_make_a_marketing_page_gated(self):
        """The word "Login" in a nav is content, not a wall. This was a real false positive."""
        body = (b'<html><title>Acme - Home</title><nav><a href="/login">Login</a>'
                b'<a href="/signup">Sign up</a></nav><h1>Welcome</h1></html>')
        label, non_public = subs.classify(200, "www.example.com", "Acme - Home", body)
        self.assertEqual((label, non_public), ("public", False))

    def test_a_password_input_alone_does_not_make_a_page_gated(self):
        """Login modals on public pages exist; a password input without a login signal is not enough."""
        body = b'<html><title>Acme - Home</title><div class="modal"><input type="password"></div></html>'
        label, non_public = subs.classify(200, "www.example.com", "Acme - Home", body)
        self.assertEqual((label, non_public), ("public", False))


class TestScope(unittest.TestCase):
    def test_only_names_under_the_target_are_in_scope(self):
        self.assertTrue(subs.in_scope("example.com", "example.com"))
        self.assertTrue(subs.in_scope("a.b.example.com", "example.com"))
        self.assertFalse(subs.in_scope("evilexample.com", "example.com"))
        self.assertFalse(subs.in_scope("example.com.evil.test", "example.com"))

    def test_a_target_given_with_a_port_keeps_its_hosts_in_scope(self):
        # The CLI and the console both accept `host:port`; the scope is the host part.
        self.assertTrue(subs.in_scope("127.0.0.1", "127.0.0.1:8080"))
        self.assertTrue(subs.in_scope("admin.example.com:443", "example.com:443"))
        self.assertFalse(subs.in_scope("evil.other.test", "example.com:8443"))


class TestProbe(unittest.TestCase):
    def test_https_failure_falls_back_to_http_once(self):
        script = {
            "https://admin.example.com/": (0, "tls: handshake failed", b""),
            "http://admin.example.com/": (200, "", b"<title>Jenkins</title>"),
        }
        session = _FakeSession(script)
        rows = subs.probe(session, ["admin.example.com"], "example.com")
        self.assertEqual(session.calls,
                         ["https://admin.example.com/", "http://admin.example.com/"])
        self.assertEqual(rows[0]["label"], "exposed")
        self.assertTrue(rows[0]["non_public"])
        self.assertTrue(rows[0]["probed"])
        self.assertEqual(rows[0]["url"], "http://admin.example.com/")

    def test_a_plain_public_host_costs_one_request(self):
        session = _FakeSession({"https://www.example.com/":
                                (200, "", b"<title>Welcome</title>")})
        rows = subs.probe(session, ["www.example.com"], "example.com")
        self.assertEqual(len(session.calls), 1, "成功就不该再发第二个请求")
        self.assertEqual(rows[0]["label"], "public")
        self.assertFalse(rows[0]["non_public"])

    def test_out_of_scope_names_are_recorded_but_never_requested(self):
        session = _FakeSession({})
        rows = subs.probe(session, ["evil.other.test"], "example.com")
        self.assertEqual(session.calls, [], "证书里别的域一个请求都不能发")
        self.assertEqual(rows[0]["skipped"], "out_of_scope")
        self.assertFalse(rows[0]["probed"])

    def test_the_host_cap_is_honoured(self):
        script = {f"https://h{i}.example.com/": (200, "", b"<title>ok</title>")
                  for i in range(5)}
        session = _FakeSession(script)
        rows = subs.probe(session, [f"h{i}.example.com" for i in range(5)],
                          "example.com", max_hosts=2)
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(sum(1 for row in rows if row["probed"]), 2)
        self.assertEqual(sum(1 for row in rows if row.get("skipped") == "max_hosts"), 3)

    def test_stats_count_labels_without_bodies(self):
        rows = [{"label": "gated", "probed": True, "status": 401, "non_public": True},
                {"label": "public", "probed": True, "status": 200, "non_public": False},
                {"label": "skipped", "probed": False, "status": 0, "non_public": False}]
        block = subs.stats(rows)
        self.assertEqual(block["probed"], 2)
        self.assertEqual(block["non_public"], 1)
        self.assertEqual(block["labels"], {"gated": 1, "public": 1, "skipped": 1})
        self.assertNotIn("title", block)


class TestProbeOverASocket(unittest.TestCase):
    """One real request path, including the HTTPS → HTTP fallback."""

    @classmethod
    def setUpClass(cls):
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def handle_one_request(self):
                # The probe tries HTTPS first, so this plain-HTTP server receives a TLS
                # ClientHello; silence the 400 it would otherwise print.
                try:
                    super().handle_one_request()
                except Exception:                                # noqa: BLE001
                    self.close_connection = True

            def do_GET(self):                                    # noqa: N802
                body = b"<html><title>Internal Admin</title></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        cls.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_a_plain_http_host_is_still_found_and_classified(self):
        session = Session("127.0.0.1", timeout=2)
        rows = subs.probe(session, ["127.0.0.1"], "127.0.0.1", port=self.port)
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["probed"], rows[0])
        self.assertEqual(rows[0]["status"], 200)
        self.assertEqual(rows[0]["title"], "Internal Admin")
        self.assertEqual(rows[0]["label"], "exposed")
        self.assertTrue(rows[0]["non_public"])


class TestBetReadsTheObservation(unittest.TestCase):
    def _report(self, subdomains):
        return {
            "target": {"domain": "example.com"},
            "meta": {"session": {"enabled": False}},
            "coverage": {"complete": True, "truncated": False},
            "verification": {"enabled": True,
                             "summary": {"identity_model": "single", "probed": 1}},
            "endpoints": [],
            "assets": {"subdomains": subdomains},
            "intel": {"ct": {"status": "ok", "subdomains": ["h.example.com"]}},
        }

    def test_a_probed_non_public_host_promotes_to_worth(self):
        bet = triage.bet(self._report([{"host": "h.example.com", "probed": True,
                                        "status": 401, "non_public": True, "label": "gated"}]))
        self.assertEqual(bet["criteria"][1]["status"], "hit")
        self.assertEqual(bet["verdict"], "worth")

    def test_a_probed_public_host_is_a_miss_not_a_unknown(self):
        bet = triage.bet(self._report([{"host": "h.example.com", "probed": True,
                                        "status": 200, "non_public": False, "label": "public"}]))
        self.assertEqual(bet["criteria"][1]["status"], "miss")
        self.assertEqual(bet["verdict"], "not_worth")

    def test_an_unprobed_host_is_still_unknown(self):
        bet = triage.bet(self._report([{"host": "h.example.com", "probed": False}]))
        self.assertEqual(bet["criteria"][1]["status"], "unknown")
        self.assertIn("子域面未评估", "；".join(bet["unknowns"]))



    def test_observation_beats_the_ip_default(self):
        """An IP target has no subdomain dimension — unless a probe actually found one."""
        report = self._report([{"host": "127.0.0.1", "probed": True, "status": 200,
                                "non_public": True, "label": "exposed"}])
        report["target"]["domain"] = "127.0.0.1:8080"
        bet = triage.bet(report)
        self.assertEqual(bet["criteria"][1]["status"], "hit", bet["criteria"][1])

class TestReportMerge(unittest.TestCase):
    def test_ct_claims_and_observations_land_on_one_row(self):
        intel = {"ct": {"status": "ok", "source": "certspotter",
                        "subdomains": ["admin.example.com", "www.example.com"],
                        "first_cert": "2019-01-01", "last_cert": "2025-01-01"}}
        probe = [{"host": "admin.example.com", "probed": True, "status": 401,
                  "title": "Login", "label": "gated", "non_public": True},
                 {"host": "www.example.com", "probed": True, "status": 200,
                  "title": "Welcome", "label": "public", "non_public": False}]
        rows = {row["host"]: row for row in _subdomain_assets(intel, probe)}
        self.assertTrue(rows["admin.example.com"]["probed"])
        self.assertTrue(rows["admin.example.com"]["non_public"])
        self.assertTrue(rows["admin.example.com"]["passive"], "证书来源不应被抹掉")
        self.assertEqual(rows["admin.example.com"]["source"], "certspotter")
        self.assertFalse(rows["www.example.com"]["non_public"])

    def test_without_a_probe_the_claim_stays_unprobed(self):
        intel = {"ct": {"status": "ok", "subdomains": ["admin.example.com"]}}
        rows = _subdomain_assets(intel, None)
        self.assertFalse(rows[0]["probed"], "没探就必须说没探")


if __name__ == "__main__":
    unittest.main(verbosity=2)
