"""Set-Cookie session persistence.

Three levels are tested, because each can fail on its own:

1. **The jar's rules** — `Domain`/`Path`/`Secure`/expiry. Getting these wrong is how a scanner
   becomes a confused deputy: it accepts a cookie for `.com` and hands the target's session to
   a host the operator never authorised.
2. **The wiring** — `Session` must absorb `Set-Cookie` from a response and put the value on the
   *next* request. A jar that stores but never sends is decoration.
3. **The report** — a session cookie *is* a credential, so the report must record that the jar
   worked (counts, names) and none of the values.
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
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import cookiejar, egress as egressmod, inject  # noqa: E402
from reconone.cli import run_scan  # noqa: E402
from reconone.http import Session  # noqa: E402

SITE_SID = "S3CRETSITESESSION"
SITE_THEME = "S3CRETTHEME"
OPERATOR_SID = "S3CRETOPERATOR"


class TestJarRules(unittest.TestCase):
    def _jar(self, **kwargs):
        kwargs.setdefault("enabled", True)
        kwargs.setdefault("scope_domain", "example.com")
        return cookiejar.CookieJar(**kwargs)

    def test_session_cookie_comes_back(self):
        jar = self._jar()
        self.assertEqual(jar.store("example.com", "/", False, ["sid=abc123"]), 1)
        self.assertEqual(jar.header_for("example.com", "/", False), "sid=abc123")
        self.assertEqual(jar.stats()["names"], ["sid"])

    def test_path_scope_is_honoured(self):
        jar = self._jar()
        jar.store("example.com", "/app/login", False, ["sid=abc123; Path=/app"])
        self.assertEqual(jar.header_for("example.com", "/app/dashboard", False), "sid=abc123")
        self.assertEqual(jar.header_for("example.com", "/other", False), "")
        self.assertEqual(jar.header_for("example.com", "/application", False), "",
                         "`/app` 不得匹配 `/application`")

    def test_default_path_is_the_requesting_directory(self):
        jar = self._jar()
        jar.store("example.com", "/app/login", False, ["sid=abc123"])
        self.assertEqual(jar.header_for("example.com", "/app/x", False), "sid=abc123")
        self.assertEqual(jar.header_for("example.com", "/", False), "")

    def test_host_only_cookie_is_not_sent_to_a_subdomain(self):
        jar = self._jar()
        jar.store("example.com", "/", False, ["sid=abc123"])
        self.assertEqual(jar.header_for("app.example.com", "/", False), "")

    def test_domain_cookie_is_sent_to_a_subdomain(self):
        jar = self._jar()
        jar.store("app.example.com", "/", False, ["sid=abc123; Domain=example.com"])
        self.assertEqual(jar.header_for("app.example.com", "/", False), "sid=abc123")
        self.assertEqual(jar.header_for("www.example.com", "/", False), "sid=abc123")

    def test_a_domain_we_are_not_allowed_to_touch_is_rejected(self):
        jar = self._jar()
        self.assertEqual(jar.store("a.example.com", "/", False, ["sid=x; Domain=other.com"]), 0)
        self.assertEqual(jar.store("a.example.com", "/", False, ["sid=x; Domain=com"]), 0,
                         "Domain=.com 是超域（supercookie）：必须拒收")
        self.assertEqual(jar.stats()["rejected"], 2)
        self.assertEqual(jar.stats()["live"], 0)
        self.assertEqual(jar.header_for("other.com", "/", False), "",
                         "被拒的 cookie 绝不能发到别的域")

    def test_an_ip_scope_accepts_no_domain_attribute_but_its_own(self):
        jar = cookiejar.CookieJar(enabled=True, scope_domain="127.0.0.1")
        self.assertEqual(jar.store("127.0.0.1", "/", False, ["sid=x; Domain=0.0.1"]), 0)
        self.assertEqual(jar.store("127.0.0.1", "/", False, ["sid=abc; Domain=127.0.0.1"]), 1)
        self.assertEqual(jar.header_for("127.0.0.1", "/", False), "sid=abc")

    def test_a_host_with_a_port_is_not_an_ip_scope(self):
        """`example.com:8443` must still accept a Domain cookie for example.com."""
        jar = cookiejar.CookieJar(enabled=True, scope_domain="example.com:8443")
        self.assertEqual(jar.store("app.example.com", "/", False,
                                   ["sid=abc123; Domain=example.com"]), 1)
        self.assertEqual(jar.header_for("app.example.com", "/", False), "sid=abc123")

    def test_secure_needs_tls_in_both_directions(self):
        jar = self._jar()
        self.assertEqual(jar.store("example.com", "/", False, ["sid=x; Secure"]), 0,
                         "明文响应不得设置 Secure cookie")
        jar.store("example.com", "/", True, ["sid=abc123; Secure"])
        self.assertEqual(jar.header_for("example.com", "/", True), "sid=abc123")
        self.assertEqual(jar.header_for("example.com", "/", False), "",
                         "Secure cookie 不得走明文")

    def test_max_age_zero_deletes_and_expired_cookies_are_dropped(self):
        jar = self._jar()
        jar.store("example.com", "/", False, ["sid=abc123"])
        jar.store("example.com", "/", False, ["sid=; Max-Age=0"])
        self.assertEqual(jar.header_for("example.com", "/", False), "")
        jar.store("example.com", "/", False,
                  ["old=abc123; Expires=Thu, 01 Jan 1970 00:00:00 GMT"])
        self.assertEqual(jar.header_for("example.com", "/", False), "")

    def test_malformed_set_cookie_is_counted_not_stored(self):
        jar = self._jar()
        self.assertEqual(jar.store("example.com", "/", False, ["=novalue", "novalue"]), 0)
        self.assertGreaterEqual(jar.stats()["rejected"], 1)

    def test_storage_is_bounded_and_evicts_oldest(self):
        jar = self._jar(max_cookies=2)
        for index in range(3):
            jar.store("example.com", "/", False, [f"c{index}=v{index}"])
        header = jar.header_for("example.com", "/", False)
        self.assertNotIn("c0=", header, "最旧的应先被淘汰")
        self.assertIn("c2=", header)
        self.assertEqual(jar.stats()["live"], 2)

    def test_header_is_longest_path_first_and_stable(self):
        jar = self._jar()
        jar.store("example.com", "/", False, ["a=1", "b=2"])
        jar.store("example.com", "/deep/x", False, ["c=3"])
        first = jar.header_for("example.com", "/deep/x", False)
        self.assertEqual(first, "c=3; a=1; b=2")
        self.assertEqual(jar.header_for("example.com", "/deep/x", False), first,
                         "同一状态必须给出同一头部（顺序不能抖动）")

    def test_stats_never_contain_a_value(self):
        jar = self._jar()
        jar.store("example.com", "/", False, [f"sid={SITE_SID}"])
        jar.header_for("example.com", "/", False)
        text = json.dumps(jar.stats(), ensure_ascii=False)
        self.assertNotIn(SITE_SID, text)
        self.assertEqual(jar.stats()["names"], ["sid"])

    def test_disabled_jar_does_nothing(self):
        jar = cookiejar.CookieJar(enabled=False, scope_domain="example.com")
        self.assertEqual(jar.store("example.com", "/", False, ["sid=abc123"]), 0)
        self.assertEqual(jar.header_for("example.com", "/", False), "")
        self.assertFalse(jar.stats()["enabled"])


class _Quiet(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass


def _serve(handler_class):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_class)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _session_site(seen: list):
    """`/` and `/login` hand out cookies; `/app/*` only answers to a cookie holder."""

    class Handler(_Quiet):
        def do_GET(self):                      # noqa: N802
            seen.append({k.lower(): v for k, v in self.headers.items()})
            if self.path in ("/", "/login"):
                body = b"<html><body><a href='/app/inner'>in</a></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Set-Cookie", f"sid={SITE_SID}; Path=/")
                self.send_header("Set-Cookie", f"theme={SITE_THEME}; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.startswith("/app"):
                ok = f"sid={SITE_SID}" in (self.headers.get("Cookie") or "")
                body = b"inner" if ok else b"wall"
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return Handler


class TestSessionWiring(unittest.TestCase):
    def setUp(self):
        self.seen: list = []
        self.server, self.port = _serve(_session_site(self.seen))
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _session(self, **kwargs) -> Session:
        kwargs.setdefault("cookies",
                          cookiejar.CookieJar(enabled=True, scope_domain="127.0.0.1"))
        return Session("127.0.0.1", timeout=3, **kwargs)

    def test_the_next_request_is_authenticated(self):
        session = self._session()
        self.assertEqual(session.request(self.base + "/login").status, 200)
        self.assertEqual(session.request(self.base + "/app/x").status, 200,
                         "第二跳必须带上第一跳拿到的会话")
        self.assertIn(f"theme={SITE_THEME}", self.seen[-1].get("cookie", ""))

    def test_injected_cookie_wins_over_the_jar_for_the_same_name(self):
        session = self._session(injection=inject.build(f"sid={OPERATOR_SID}", ""))
        self.assertEqual(session.request(self.base + "/login").status, 200)
        session.request(self.base + "/app/x")
        cookie = self.seen[-1].get("cookie", "")
        self.assertIn(f"sid={OPERATOR_SID}", cookie, "运维显式给的身份不得被站点覆盖")
        self.assertNotIn(SITE_SID, cookie)
        self.assertIn(f"theme={SITE_THEME}", cookie, "其它站点 cookie 仍应合并进来")

    def test_only_one_cookie_header_is_sent(self):
        session = self._session(injection=inject.build("sid=op", ""))
        session.request(self.base + "/login")
        session.request(self.base + "/app/x")
        raw = self.seen[-1]
        self.assertNotIn("cookie2", raw)
        self.assertEqual(raw.get("cookie", "").count("sid="), 1, "同一个 cookie 名只能出现一次")

    def test_a_disabled_jar_sends_nothing(self):
        session = Session("127.0.0.1", timeout=3,
                          cookies=cookiejar.CookieJar(enabled=False))
        session.request(self.base + "/login")
        self.assertEqual(session.request(self.base + "/app/x").status, 401)
        self.assertNotIn("cookie", self.seen[-1])


class TestReportedWithoutValues(unittest.TestCase):
    """End to end: crawl a site that only serves the inner page to a cookie holder."""

    @classmethod
    def setUpClass(cls):
        cls.seen: list = []
        cls.server, cls.port = _serve(_session_site(cls.seen))
        cls.tmp = tempfile.mkdtemp(prefix="recon-one-jar-")
        cls.out = os.path.join(cls.tmp, "run")
        cls.report, cls.code = run_scan(
            f"127.0.0.1:{cls.port}", cls.out, "fast", {"max_pages": 3},
            use_dns=False, use_js=False, use_intel=False, use_verify=False,
            egress=egressmod.resolve("direct"), quiet=True)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_inner_page_was_reached_because_the_cookie_came_back(self):
        pages = {page["url"].split(str(self.port))[-1]: page["status"]
                 for page in self.report["assets"]["pages"]}
        self.assertEqual(pages.get("/app/inner"), 200,
                         f"没有会话保持时这一页会是 401：{pages}")
        self.assertGreaterEqual(self.report["meta"]["session"]["cookies"]["carried_requests"], 1)

    def test_the_jar_is_recorded_as_counts_and_names(self):
        block = self.report["meta"]["session"]["cookies"]
        self.assertTrue(block["enabled"])
        self.assertGreaterEqual(block["received"], 2)
        self.assertGreaterEqual(block["stored"], 2)
        self.assertEqual(block["live"], 2)
        self.assertEqual(block["names"], ["sid", "theme"])
        self.assertTrue(block["note"])

    def test_no_cookie_value_reaches_any_written_file(self):
        files = []
        for root, _dirs, names in os.walk(self.out):
            for name in names:
                files.append(os.path.join(root, name))
        self.assertTrue(files)
        for path in files:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            for secret in (SITE_SID, SITE_THEME):
                self.assertNotIn(secret, text, f"{os.path.basename(path)} 泄露了 {secret}")

    def test_markdown_says_the_jar_was_used(self):
        with open(os.path.join(self.out, "report", "report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("Set-Cookie 会话保持", text)
        self.assertIn("站点下发的 Cookie 名称：sid, theme", text)

    def test_no_cookies_flag_turns_the_jar_off(self):
        out = os.path.join(self.tmp, "nojar")
        report, _code = run_scan(
            f"127.0.0.1:{self.port}", out, "fast", {"max_pages": 2},
            use_dns=False, use_js=False, use_intel=False, use_verify=False,
            use_cookies=False, egress=egressmod.resolve("direct"), quiet=True)
        block = report["meta"]["session"]["cookies"]
        self.assertFalse(block["enabled"])
        self.assertEqual(block["stored"], 0)
        self.assertEqual(block["carried_requests"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
