"""Egress: proxy routing, system proxy discovery, SOCKS5, and failure classification.

The four tests named E1–E4 in the roadmap live here, each against a real local server:

* **E1** every request leaves through the proxy and the target is never touched directly;
* **E2** the system proxy is discovered from the environment; PAC is reported, not faked;
* **E3** SOCKS5 works (hand-rolled client, no extra dependency);
* **E4** failures are classified, and only connection-level failures retry via fallback.

Nothing here resolves a public name or opens a socket to a remote host.
"""
from __future__ import annotations

import http.server
import os
import select
import socket
import socketserver
import ssl
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import egress as egressmod  # noqa: E402
from reconone.http import Session  # noqa: E402


# --------------------------------------------------------------------------- helpers
class _Counter:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = 0
        self.paths: list[str] = []
        self.connects: list[str] = []
        self.socks: list[str] = []

    def hit(self, path: str = "") -> None:
        with self.lock:
            self.requests += 1
            if path:
                self.paths.append(path)

    def connect(self, target: str) -> None:
        with self.lock:
            self.connects.append(target)

    def sock(self, target: str) -> None:
        with self.lock:
            self.socks.append(target)


def _serve(handler_class):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_class)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


class _Quiet(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):        # keep the test output readable
        pass


def _target_factory(counter: _Counter):
    class Handler(_Quiet):
        def do_GET(self):                # noqa: N802
            counter.hit(self.path)
            body = b"target-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


def _proxy_factory(counter: _Counter):
    class Handler(_Quiet):
        def do_GET(self):                # noqa: N802  absolute-URI form (RFC 7230 5.3.2)
            counter.hit(self.path)
            body = b"proxied-ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_CONNECT(self):            # noqa: N802
            counter.connect(self.path)
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.close_connection = True
    return Handler


class _Socks(_Quiet):
    """Minimal SOCKS5 (no auth) relay: just enough to prove the client's handshake."""

    counter = _Counter()

    def setup(self):
        super().setup()
        self.connection.settimeout(5.0)

    def _recv(self, size: int) -> bytes:
        buf = b""
        while len(buf) < size:
            chunk = self.connection.recv(size - len(buf))
            if not chunk:
                raise OSError("closed")
            buf += chunk
        return buf

    def handle(self):
        try:
            _ver, nmethods = self._recv(2)
            self._recv(nmethods)
            self.connection.sendall(b"\x05\x00")
            _ver, _cmd, _rsv, atyp = self._recv(4)
            if atyp == 3:
                host = self._recv(self._recv(1)[0]).decode()
            elif atyp == 1:
                host = socket.inet_ntoa(self._recv(4))
            else:
                host = socket.inet_ntop(socket.AF_INET6, self._recv(16))
            port = int.from_bytes(self._recv(2), "big")
            self.counter.sock(f"{host}:{port}")
            upstream = socket.create_connection((host, port), timeout=5.0)
            try:
                self.connection.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00" * 2)
                self._relay(upstream)
            finally:
                upstream.close()
        except (OSError, ValueError):
            pass

    def _relay(self, upstream: socket.socket) -> None:
        """Pump both directions until either side closes.

        A request/response pair is not 1:1 on the wire (headers and body arrive in separate
        segments), so a strict read-then-write loop deadlocks on the first split response.
        """
        peers = {self.connection: upstream, upstream: self.connection}
        socks = [self.connection, upstream]
        for sock in socks:
            sock.settimeout(0.2)
        while True:
            ready, _, _ = select.select(socks, [], [], 5.0)
            if not ready:
                return
            for sock in ready:
                try:
                    data = sock.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                peers[sock].sendall(data)


# --------------------------------------------------------------------------- E1
class TestProxyEgress(unittest.TestCase):
    """E1 — the request goes through the proxy; the target is never contacted directly."""

    @classmethod
    def setUpClass(cls):
        cls.proxy_counter = _Counter()
        cls.target_counter = _Counter()
        cls.proxy, cls.proxy_port = _serve(_proxy_factory(cls.proxy_counter))
        cls.target, cls.target_port = _serve(_target_factory(cls.target_counter))

    @classmethod
    def tearDownClass(cls):
        for server in (cls.proxy, cls.target):
            server.shutdown()
            server.server_close()

    def test_every_request_goes_through_the_proxy(self):
        egress = egressmod.resolve("manual", f"http://127.0.0.1:{self.proxy_port}")
        session = Session("127.0.0.1", timeout=3, egress=egress)
        before_proxy = self.proxy_counter.requests
        before_target = self.target_counter.requests
        resp = session.request(f"http://127.0.0.1:{self.target_port}/probe?x=1")
        self.assertIsNone(resp.error, resp.error)
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, b"proxied-ok", "请求必须由代理应答，而不是直连目标")
        self.assertEqual(self.proxy_counter.requests - before_proxy, 1)
        self.assertEqual(self.target_counter.requests - before_target, 0,
                         "目标不该被直接访问：那说明代理没有生效")
        self.assertTrue(self.proxy_counter.paths[-1].startswith("http://127.0.0.1:"),
                        "代理必须收到绝对 URI：" + self.proxy_counter.paths[-1])
        reported = session.egress.view(session.fallback_count, session.requests)
        self.assertEqual(reported["type"], "http")
        self.assertEqual(reported["mode"], "manual")
        self.assertIn("127.0.0.1", reported["host"])
        self.assertEqual(session.log[-1]["egress"], "proxy")

    def test_https_through_proxy_uses_connect(self):
        egress = egressmod.resolve("manual", f"http://127.0.0.1:{self.proxy_port}")
        session = Session("127.0.0.1", timeout=2, egress=egress)
        resp = session.request(f"https://127.0.0.1:{self.target_port}/x")
        # The fake proxy answers CONNECT then closes, so the TLS handshake cannot finish —
        # the point is that we asked the proxy instead of dialling the target.
        self.assertIsNotNone(resp.error)
        self.assertTrue(self.proxy_counter.connects, "https 必须走 CONNECT 隧道")
        self.assertEqual(self.proxy_counter.connects[-1], f"127.0.0.1:{self.target_port}")
        self.assertIn(session.errors[-1]["kind"], ("tls", "reset"))


# --------------------------------------------------------------------------- E2
class TestSystemProxy(unittest.TestCase):
    """E2 — system proxy comes from the environment; PAC is reported, never faked."""

    def setUp(self):
        self._saved = {key: os.environ.pop(key, None) for key in egressmod.ENV_KEYS}

    def tearDown(self):
        for key, value in self._saved.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)

    def test_env_is_discovered(self):
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
        egress = egressmod.resolve("system")
        self.assertEqual(egress.mode, "system")
        self.assertEqual((egress.proxy.host, egress.proxy.port), ("127.0.0.1", 7897))
        self.assertIn("HTTPS_PROXY", egress.source)

    def test_auto_keeps_direct_primary_and_proxy_as_fallback(self):
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
        egress = egressmod.resolve("auto")
        self.assertEqual(egress.mode, "auto")
        self.assertIsNone(egress.proxy, "auto 模式首选直连")
        self.assertIsNotNone(egress.fallback, "auto 模式必须有回退代理")

    def test_direct_flag_beats_the_environment(self):
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
        egress = egressmod.resolve("direct")
        self.assertIsNone(egress.proxy)
        self.assertIsNone(egress.fallback)

    def test_bypass_suffixes_stay_direct(self):
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:7897"
        egress = egressmod.resolve("system", no_proxy="localhost, .corp")
        self.assertIsNone(egress.route_for("localhost"))
        self.assertIsNone(egress.route_for("a.corp"))
        self.assertIsNotNone(egress.route_for("example.com"))

    def test_view_always_states_pac_support(self):
        egress = egressmod.resolve("auto")
        self.assertIn("pac", egress.view())
        self.assertFalse(egress.view()["pac"]["supported"])

    def test_manual_requires_a_url(self):
        with self.assertRaises(ValueError):
            egressmod.resolve("manual", "")


# --------------------------------------------------------------------------- E3
class TestSocks5(unittest.TestCase):
    """E3 — SOCKS5 works without pulling in a dependency."""

    @classmethod
    def setUpClass(cls):
        cls.counter = _Counter()
        handler = type("SocksHandler", (_Socks,), {"counter": cls.counter})
        cls.socks, cls.socks_port = _serve(handler)
        cls.target_counter = _Counter()
        cls.target, cls.target_port = _serve(_target_factory(cls.target_counter))

    @classmethod
    def tearDownClass(cls):
        for server in (cls.socks, cls.target):
            server.shutdown()
            server.server_close()

    def test_request_travels_through_the_socks_tunnel(self):
        egress = egressmod.resolve("manual", f"socks5://127.0.0.1:{self.socks_port}")
        session = Session("127.0.0.1", timeout=4, egress=egress)
        before = len(self.counter.socks)
        resp = session.request(f"http://127.0.0.1:{self.target_port}/via-socks")
        self.assertIsNone(resp.error, resp.error)
        self.assertEqual(resp.body, b"target-ok")
        self.assertEqual(len(self.counter.socks) - before, 1)
        self.assertEqual(self.counter.socks[-1], f"127.0.0.1:{self.target_port}")
        self.assertEqual(session.egress.view(0, session.requests)["type"], "socks5")


# --------------------------------------------------------------------------- E4
class TestFailureClassification(unittest.TestCase):
    """E4 — kinds are actionable, and only connect-level failures retry."""

    def test_kind_mapping(self):
        kind = Session._kind
        self.assertEqual(kind(socket.timeout("slow")), "connect-timeout")
        self.assertEqual(kind(TimeoutError("slow")), "connect-timeout")
        self.assertEqual(kind(ConnectionResetError("reset")), "reset")
        self.assertEqual(kind(ConnectionRefusedError("refused")), "refused")
        self.assertEqual(kind(socket.gaierror("dns")), "dns")
        self.assertEqual(kind(ssl.SSLError("tls")), "tls")
        self.assertEqual(kind(ValueError("other")), "connect")

    def test_failure_is_recorded_not_swallowed(self):
        session = Session("127.0.0.1", timeout=1)
        resp = session.request("http://127.0.0.1:1/")
        self.assertIsNotNone(resp.error)
        # A closed port may answer with RST (refused) or be silently dropped by the local
        # firewall (timeout); both are connection-level and both must be visible.
        self.assertIn(session.errors[-1]["kind"], ("refused", "connect-timeout"))

    def test_timeout_and_reset_are_distinguished(self):
        import http.client as httpclient

        original = httpclient.HTTPConnection.connect

        def timeout(self):
            raise socket.timeout("no route")

        def reset(self):
            raise ConnectionResetError("peer reset")

        for raiser, expected in ((timeout, "connect-timeout"), (reset, "reset")):
            httpclient.HTTPConnection.connect = raiser
            try:
                session = Session("127.0.0.1", timeout=1)
                session.request("http://127.0.0.1:9/x")
                self.assertEqual(session.errors[-1]["kind"], expected)
            finally:
                httpclient.HTTPConnection.connect = original

    def test_fallback_is_used_once_for_connect_failures(self):
        counter = _Counter()
        proxy, proxy_port = _serve(_proxy_factory(counter))
        try:
            egress = egressmod.Egress(
                mode="auto", proxy=None, source="test",
                fallback=egressmod.parse_proxy(f"http://127.0.0.1:{proxy_port}"))
            session = Session("127.0.0.1", timeout=1, egress=egress)
            resp = session.request("http://127.0.0.1:1/x")
            self.assertIsNone(resp.error, resp.error)
            self.assertEqual(resp.body, b"proxied-ok")
            self.assertEqual([entry["egress"] for entry in session.log], ["fallback", "proxy"])
            self.assertEqual(session.fallback_count, 1)
            self.assertEqual(counter.requests, 1)
            view = session.egress.view(session.fallback_count, session.requests)
            self.assertTrue(view["fallback"])
            self.assertEqual(view["fallback_used"], 1)
            self.assertEqual(view["fallback_requests_pct"], 50.0)
        finally:
            proxy.shutdown()
            proxy.server_close()

    def test_tls_failure_does_not_retry_through_the_proxy(self):
        counter = _Counter()
        proxy, proxy_port = _serve(_proxy_factory(counter))
        try:
            egress = egressmod.Egress(
                mode="auto", proxy=None, source="test",
                fallback=egressmod.parse_proxy(f"http://127.0.0.1:{proxy_port}"))
            session = Session("127.0.0.1", timeout=2, egress=egress)
            resp = session.request(f"https://127.0.0.1:{proxy_port}/x")
            self.assertIsNotNone(resp.error)
            self.assertEqual(session.errors[-1]["kind"], "tls")
            self.assertEqual(session.fallback_count, 0, "TLS 错误不该靠换路由重试")
            self.assertFalse(counter.connects, "没有回退时不应该碰代理")
        finally:
            proxy.shutdown()
            proxy.server_close()


# --------------------------------------------------------------------------- report
class TestReportEgressBlock(unittest.TestCase):
    def test_view_is_report_shaped_and_carries_no_credentials(self):
        egress = egressmod.resolve("manual", "http://user:secret@127.0.0.1:8080",
                                   no_proxy=".corp")
        view = egress.view(fallback_count=2, requests=10)
        self.assertEqual(view["type"], "http")
        self.assertEqual(view["host"], "127.0.0.1:8080")
        self.assertNotIn("secret", str(view))
        self.assertNotIn("user", str(view))
        self.assertEqual(view["fallback_requests_pct"], 20.0)
        self.assertEqual(view["no_proxy"], [".corp"])
        self.assertFalse(view["pac"]["supported"])

    def test_cli_and_report_share_the_same_block(self):
        """`meta.egress` is the session's own view — one shape, one source."""
        from reconone import http as httpmod

        session = Session("example.com", timeout=1,
                          egress=egressmod.resolve("direct"))
        view = httpmod.egress_view(session)
        self.assertEqual(view["type"], "direct")
        self.assertEqual(view["fallback_used"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
