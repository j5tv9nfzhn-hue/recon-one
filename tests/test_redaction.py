"""授权声明与敏感数据脱敏。

Two rules under test:

1. **A credential never reaches the report.** Header values, URL userinfo and sensitive query
   values are replaced with a self-describing marker; the *shape* survives (length + hash) so a
   reader can still prove "this is the value I saw", but nothing reusable remains.
2. **The notice is recorded, not assumed.** Every report carries `meta.authorization`, and an
   empty `--authorized-by` is reported as 未声明 instead of being silently omitted.

The negative assertions matter more than the positive ones: a test that only checks the marker
exists would still pass if the raw value sat next to it.
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

from reconone import config, egress as egressmod, redact, report as reportmod, util  # noqa: E402
from reconone.cli import run_scan  # noqa: E402


class TestHeaderRedaction(unittest.TestCase):
    def test_set_cookie_keeps_attributes_and_drops_value(self):
        raw = "sessionid=SECRETSESSIONVALUE123; Path=/; HttpOnly; Secure; SameSite=Lax"
        out = util.redact_header("Set-Cookie", raw)
        self.assertNotIn("SECRETSESSIONVALUE123", out)
        # The analysis needs the attributes; a blanket mask would destroy the finding.
        for attr in ("Path=/", "HttpOnly", "Secure", "SameSite=Lax"):
            self.assertIn(attr, out)
        self.assertIn("sessionid=[redacted:", out)
        self.assertIn("len=21", out)

    def test_marker_keeps_length_and_hash_but_no_run_of_the_value(self):
        value = "abc123XYZ789"
        marker = util.redacted_marker(value)
        self.assertTrue(marker.startswith("[redacted:"))
        self.assertIn("len=12", marker)
        # The hash is hex and may contain any digit; what must not appear is the value's own
        # run of characters, which is what would let someone recognise or rebuild it.
        self.assertNotIn("abc123", marker)
        self.assertNotIn("XYZ789", marker)

    def test_credential_headers_are_masked_and_others_pass_through(self):
        cases = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "X-Api-Key": "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk",
            "Cookie": "sid=COOKIEVALUE1; theme=DARKMODE2",
            "Proxy-Authorization": "Basic dXNlcjpwYXNzd29yZA==",
        }
        for name, value in cases.items():
            with self.subTest(header=name):
                out = util.redact_header(name, value)
                self.assertIn("redacted", out)
                for chunk in value.replace("Bearer ", "").split("; "):
                    secret = chunk.split("=")[-1]
                    if len(secret) >= 8:
                        self.assertNotIn(secret, out, f"{name} 的值泄露了")
        for name, value in (("server", "nginx/1.24.0"), ("content-type", "text/html"),
                            ("strict-transport-security", "max-age=63072000")):
            self.assertEqual(util.redact_header(name, value), value)

    def test_scrub_headers_preserves_names_and_count(self):
        headers = {"set-cookie": "sid=abcdefghijklmnop; HttpOnly",
                   "server": "nginx/1.24.0", "authorization": "Bearer LONGTOKENVALUE"}
        out = util.scrub_headers(headers)
        self.assertEqual(sorted(out), sorted(headers))
        self.assertIn("nginx/1.24.0", out["server"])
        self.assertNotIn("abcdefghijklmnop", out["set-cookie"])
        self.assertNotIn("LONGTOKENVALUE", out["authorization"])

    def test_empty_values_do_not_become_markers(self):
        self.assertEqual(util.redact_header("set-cookie", ""), "")
        self.assertEqual(util.redact_header("authorization", None), "")


class TestUrlRedaction(unittest.TestCase):
    def test_userinfo_is_dropped_and_path_survives(self):
        out = util.redact_url("https://admin:hunter2@example.com/api/v1/users?page=2")
        self.assertNotIn("hunter2", out)
        self.assertNotIn("admin:", out)
        self.assertIn("example.com/api/v1/users", out)
        self.assertIn("page=2", out, "非敏感参数必须保留，否则端点面就被抹掉了")

    def test_sensitive_query_values_are_masked(self):
        out = util.redact_url("https://example.com/cb?access_token=AAAABBBBCCCC&state=xyz")
        self.assertNotIn("AAAABBBBCCCC", out)
        self.assertIn("state=xyz", out)

    def test_scrub_urls_walks_nested_structures(self):
        payload = {"errors": [{"url": "https://u:p@h/?token=tok123", "kind": "network"}],
                   "note": "no url here", "n": 3}
        out = util.scrub_urls(payload)
        text = json.dumps(out)
        self.assertNotIn("tok123", text)
        self.assertNotIn("u:p@", text)
        self.assertEqual(out["note"], "no url here")
        self.assertEqual(out["n"], 3)


class TestReportCarriesNoCredential(unittest.TestCase):
    """The end-to-end guard: build a report whose inputs are full of secrets."""

    def _report(self, authorized_by=""):
        class _Session:
            requests = 7
            bytes_total = 1234
            exhausted = False
            off_scope_attempts = []
            errors = [{"url": "https://user:pw@example.com/x?token=ERRTOKEN1", "kind": "timeout"}]
            log = [{"url": "https://example.com/", "status": 200, "bytes": 10}]

        web = {
            "root_url": "https://example.com/",
            "final_url": "https://example.com/home?session=SESSVAL99",
            "redirect_chain": ["https://user:pw@example.com/start", "https://example.com/home"],
            "headers": {"set-cookie": "sid=COOKIESECRET42; HttpOnly; Secure",
                        "authorization": "Bearer TOKENVALUE77",
                        "server": "nginx/1.24.0"},
            "status": 200, "tech": [], "security": {}, "cookies": [],
            "tls": {}, "well_known": {}, "title": "t", "https_available": True,
        }
        return reportmod.assemble(
            domain="example.com", root_url="https://example.com/", profile_name="fast",
            limits={}, web=web, dns={}, crawl_result={"pages": [], "forms": [], "scripts": []},
            js={"scripts": [], "endpoints": [], "params": [], "secrets": [], "hints": [],
                "hosts": [], "chunks": [], "stats": {"fetched": 0}},
            api={"specs": [], "parameters": [], "graphql": {"endpoints": []}},
            findings=[], hyp=[], session=_Session(), started_at="", elapsed=0.1,
            probe_status={}, intel={}, authorized_by=authorized_by)

    def test_no_secret_survives_anywhere_in_the_report_json(self):
        report = self._report(authorized_by="SOW-2026-014")
        blob = json.dumps(report, ensure_ascii=False)
        for secret in ("COOKIESECRET42", "TOKENVALUE77", "SESSVAL99", "ERRTOKEN1", "pw@"):
            self.assertNotIn(secret, blob, f"{secret} 泄露到了报告里")
        # And the evidence that matters is still there.
        self.assertIn("HttpOnly", blob)
        self.assertIn("nginx/1.24.0", blob)
        self.assertIn("/home", blob)

    def test_authorization_block_is_complete(self):
        auth = self._report(authorized_by="SOW-2026-014")["meta"]["authorization"]
        self.assertEqual(auth["notice_version"], config.AUTHORIZED_USE_VERSION)
        self.assertEqual(auth["notice"], config.AUTHORIZED_USE)
        self.assertEqual(auth["summary"], config.AUTHORIZED_USE_SHORT)
        self.assertEqual(auth["premises"], list(config.AUTHORIZED_USE_PREMISES))
        self.assertEqual(auth["authorized_by"], "SOW-2026-014")
        self.assertTrue(auth["declared"])

    def test_missing_authorized_by_is_recorded_as_undeclared(self):
        auth = self._report()["meta"]["authorization"]
        self.assertEqual(auth["authorized_by"], "")
        self.assertFalse(auth["declared"])
        self.assertTrue(auth["notice"], "未填写也要给出完整声明，不能变成空字段")

    def test_notice_reaches_every_rendered_artefact(self):
        report = self._report(authorized_by="SOW-2026-014")
        md = reportmod.render_markdown(report)
        handoff = reportmod.render_handoff(report)
        self.assertIn("## 授权声明", md)
        self.assertIn("SOW-2026-014", md)
        self.assertIn("授权", handoff)
        self.assertIn("SOW-2026-014", handoff)
        # An undeclared run must say so rather than show an empty bullet.
        undeclared = reportmod.render_markdown(self._report())
        self.assertIn("未声明", undeclared)

    def test_digest_ignores_who_was_authorised(self):
        """The digest describes the target, not the paperwork behind the scan."""
        a = reportmod._digest_view(self._report(authorized_by="A"))
        b = reportmod._digest_view(self._report(authorized_by="B"))
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        # The notice version does enter the digest: a changed notice is a changed promise.
        self.assertEqual(a["meta"]["authorization"]["notice_version"],
                         config.AUTHORIZED_USE_VERSION)
    def test_finding_evidence_snippet_is_scrubbed(self):
        """The real leak path: `derive_findings()` stores a raw header block as evidence."""
        snippet = ("authorization: Bearer SHOULDNOTAPPEAR123\n"
                   "content-type: text/html\n"
                   "set-cookie: sid=COOKIESECRET42; HttpOnly")
        findings = [{"id": "F-001", "severity": "high", "detail": "see below",
                     "evidence": [{"file": "https://example.com/", "offset": 0,
                                   "snippet": snippet}]}]
        out = reportmod._scrub_findings(findings)
        text = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("SHOULDNOTAPPEAR123", text)
        self.assertNotIn("COOKIESECRET42", text)
        # The rest of the block is the evidence and must survive.
        self.assertIn("content-type: text/html", text)
        self.assertIn("HttpOnly", text)

    def test_hypothesis_text_is_scrubbed_too(self):
        hyp = [{"id": "H-001", "detail": "authorization: Bearer LEAKYTOKENVALUE9",
                "success_signal": "200 OK", "precondition": "none"}]
        out = reportmod._scrub_hypothesis(hyp[0])
        self.assertNotIn("LEAKYTOKENVALUE9", json.dumps(out, ensure_ascii=False))
        self.assertEqual(out["success_signal"], "200 OK")


class TestCliWiring(unittest.TestCase):
    def test_scan_accepts_authorized_by(self):
        from reconone import cli
        parser = cli.build_parser()
        args = parser.parse_args(["scan", "--domain", "example.com",
                                  "--authorized-by", "SOW-1"])
        self.assertEqual(args.authorized_by, "SOW-1")
        default = parser.parse_args(["scan", "--domain", "example.com"])
        self.assertEqual(default.authorized_by, "")




class TestWholeReportSweep(unittest.TestCase):
    """第五层：按「形状」扫完整份报告，覆盖四层定点脱敏够不到的字段。

    这几条对应的都是真实缺口：`assets.hosts[].url` 来自 JS 字符串字面量、
    `report.intel` 是第三方 JSON（Wayback 行里可能带 token）、`assets.well_known` 存原始正文。
    """

    def test_bearer_jwt_and_inline_pairs_are_masked(self):
        text = ("Authorization: Bearer abcdef1234567890 "
                "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop "
                "and https://example.com/reset?token=TOPSECRET&page=2")
        out = redact.scrub_text(text)
        for secret in ("abcdef1234567890", "TOPSECRET", "eyJhbGciOiJIUzI1NiJ9"):
            self.assertNotIn(secret, out)
        self.assertIn("page=2", out, "非敏感参数必须保留，否则端点面就被抹掉了")

    def test_fields_that_used_to_leak_are_covered(self):
        report = {
            "assets": {
                "hosts": [{"url": "https://user:pw@internal.example.com/api", "kind": "internal"}],
                "well_known": {"/robots.txt": {"status": 200,
                                               "body": "Disallow: /admin?api_key=KEY12345"}},
                "http": {"headers": {"set-cookie": "sid=SESSIONSECRET; Path=/; HttpOnly"}},
            },
            "intel": {"archive": {"urls": [
                {"url": "https://example.com/reset?token=WAYBACKTOKEN",
                 "path": "/reset", "query": "token=WAYBACKTOKEN"}]}},
            "coverage": {"counts": {"endpoints": 3}},
        }
        out = redact.scrub_report(report)
        text = json.dumps(out, ensure_ascii=False)
        for secret in ("pw@", "KEY12345", "SESSIONSECRET", "WAYBACKTOKEN"):
            self.assertNotIn(secret, text, secret)
        # 结构、计数与可用属性必须原样保留，否则报告失去可核查性
        self.assertEqual(out["coverage"]["counts"]["endpoints"], 3)
        self.assertEqual(out["assets"]["hosts"][0]["kind"], "internal")
        self.assertIn("internal.example.com", text)
        self.assertIn("Path=/", text)
        self.assertIn("/reset", text)

    def test_strict_keys_are_masked_and_already_masked_values_are_left_alone(self):
        out = redact.scrub_report({"token": "raw-token-value", "auth_surface": "8 个认证表单"})
        self.assertNotIn("raw-token-value", out["token"])
        self.assertEqual(out["auth_surface"], "8 个认证表单", "检查项 id 不能被当成凭据键")
        again = redact.scrub_report(out)
        self.assertEqual(json.dumps(out, sort_keys=True), json.dumps(again, sort_keys=True))

    def test_scope_note_names_the_raw_artefact_exception(self):
        note = redact.scope_note()
        self.assertEqual(len(note["layers"]), 5)
        self.assertIn("unredacted", note["raw_artifacts"])
        self.assertTrue(any("security.txt" in item for item in note["not_redacted"]))
        self.assertIn("回显", note["credential_echoes"])



ECHO_COOKIE = "sid=S3CRETCOOKIE"
ECHO_BEARER = "S3CRETBEARER"
ECHO_KEY = "S3CRETAPIKEY"
ECHO_SECRETS = ("S3CRETCOOKIE", "S3CRETBEARER", "S3CRETAPIKEY")


class _EchoingSite(http.server.BaseHTTPRequestHandler):
    """A target that reflects our own credentials back at us — the case shapes cannot see."""

    protocol_version = "HTTP/1.1"
    seen: list[dict] = []

    def log_message(self, *args):
        pass

    def do_GET(self):                          # noqa: N802
        _EchoingSite.seen.append({k.lower(): v for k, v in self.headers.items()})
        cookie = self.headers.get("Cookie", "")
        token = self.headers.get("Authorization", "")
        key = self.headers.get("X-Api-Key", "")
        body = (f"<html><head><title>欢迎 {cookie}</title></head><body>"
                f"<p>授权 {token} / 密钥 {key}</p><a href='/next'>next</a></body></html>"
                ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # A response header that echoes the request key: the report stores response headers.
        self.send_header("X-Echo-Api-Key", key)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestSentCredentialsAreMaskedByValue(unittest.TestCase):
    """The values we send are masked literally, on top of the shape sweep."""

    def test_echoes_in_any_field_are_masked(self):
        report = {
            "meta": {},
            "target": {"title": f"欢迎 {ECHO_COOKIE}"},
            "assets": {
                "pages": [{"url": "https://x.test/", "title": f"你好 {ECHO_COOKIE}"}],
                "well_known": {"/robots.txt": {"status": 200, "body": f"Bearer {ECHO_BEARER}"}},
                "http": {"headers": {"x-echo-api-key": ECHO_KEY}},
            },
            "findings": [{"id": "F-001", "snippet": f"X-Api-Key: {ECHO_KEY}"}],
        }
        out = redact.scrub_report(report, secrets=ECHO_SECRETS)
        text = json.dumps(out, ensure_ascii=False)
        for secret in ECHO_SECRETS:
            self.assertNotIn(secret, text, secret)
        self.assertIn("[redacted:sent-credential]", text)
        self.assertEqual(out["meta"]["redaction"]["sent_credentials"]["registered"], 3)
        # 结构不能被抹掉：标题里的其它字、URL、finding id 都要保留
        self.assertIn("欢迎", out["target"]["title"])
        self.assertEqual(out["findings"][0]["id"], "F-001")

    def test_masking_is_idempotent(self):
        once = redact.scrub_report({"t": f"a {ECHO_COOKIE} b"}, secrets=ECHO_SECRETS)
        twice = redact.scrub_report(once, secrets=ECHO_SECRETS)
        self.assertEqual(json.dumps(once, sort_keys=True), json.dumps(twice, sort_keys=True))

    def test_longest_value_wins_so_no_tail_survives(self):
        # 刻意不用 `token=…` 形状：形状层会先遮掉，那样就测不到字面量层的排序。
        out = redact.scrub_report({"t": "prefix Zx9Abc123456 suffix"},
                                  secrets=("Zx9Abc", "Zx9Abc123456"))
        self.assertEqual(out["t"], "prefix [redacted:sent-credential] suffix")
        self.assertNotIn("123456", out["t"])

    def test_nothing_is_registered_when_nothing_was_sent(self):
        out = redact.scrub_report({"t": "ordinary text"}, secrets=())
        self.assertNotIn("sent_credentials", out.get("meta", {}).get("redaction") or {})
        self.assertEqual(out["t"], "ordinary text")


class TestEchoedCredentialsNeverReachTheReport(unittest.TestCase):
    """End to end: a real scan of a site that reflects our Cookie/Bearer/Key back."""

    @classmethod
    def setUpClass(cls):
        _EchoingSite.seen = []
        cls.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EchoingSite)
        cls.server.daemon_threads = True
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        port = cls.server.server_address[1]
        cls.tmp = tempfile.mkdtemp(prefix="recon-one-echo-")
        cls.out = os.path.join(cls.tmp, "run")
        cls.report, cls.code = run_scan(
            f"127.0.0.1:{port}", cls.out, "fast", {"max_pages": 2},
            use_dns=False, use_js=False, use_intel=False, use_verify=False,
            cookie=ECHO_COOKIE, bearer=ECHO_BEARER, headers=[f"X-Api-Key: {ECHO_KEY}"],
            egress=egressmod.resolve("direct"), quiet=True)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_the_server_really_received_and_echoed_our_credentials(self):
        """Without this the leak test would pass on a scan that sent nothing."""
        self.assertTrue(_EchoingSite.seen, "扫描必须真的发出请求")
        self.assertEqual(_EchoingSite.seen[0].get("cookie"), ECHO_COOKIE)
        self.assertEqual(_EchoingSite.seen[0].get("authorization"), f"Bearer {ECHO_BEARER}")
        self.assertEqual(_EchoingSite.seen[0].get("x-api-key"), ECHO_KEY)
        self.assertEqual(self.report["assets"]["http"]["status"], 200)

    def test_no_written_package_file_contains_the_credentials(self):
        files = []
        for root, _dirs, names in os.walk(self.out):
            for name in names:
                path = os.path.join(root, name)
                if path.lower().endswith((".json", ".md", ".txt", ".html", ".ndjson", ".csv")):
                    files.append(path)
        self.assertTrue(files, "扫描至少要写出 report.json")
        for path in files:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for secret in ECHO_SECRETS:
                self.assertNotIn(secret, text, f"{os.path.basename(path)} 泄露了 {secret}")

    def test_the_report_says_the_values_were_masked(self):
        block = self.report["meta"]["redaction"]["sent_credentials"]
        self.assertEqual(block["registered"], 3)
        self.assertTrue(block["masked"])
        self.assertEqual(self.report["meta"]["session"]["cookie_names"], ["sid"])
        self.assertNotIn("opaque_cookie_segments", json.dumps(
            {k: v for k, v in self.report["meta"]["session"].items() if v}), "0 片段时不必出现")

    def test_report_and_markdown_state_the_masking(self):
        with open(os.path.join(self.out, "report", "report.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("报告侧脱敏", text)
        self.assertIn("字面量", text)
        # report.md 不渲染页面标题/响应头，回显只出现在 report.json —— 标记要在那里。
        with open(os.path.join(self.out, "report", "report.json"), encoding="utf-8") as fh:
            self.assertIn("[redacted:sent-credential]", fh.read(),
                          "回显被遮蔽时 report.json 里应留下标记")


if __name__ == "__main__":
    unittest.main(verbosity=2)
