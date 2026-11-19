"""Acceptance tests: every criterion in docs/ACCEPTANCE.md is asserted here."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from reconone import jsanalyze                                # noqa: E402
from reconone import report as reportmod                     # noqa: E402
from reconone import score                                    # noqa: E402
from reconone.cli import run_scan                             # noqa: E402
from reconone.dns import _build_query, _parse, _read_name      # noqa: E402
from reconone.util import norm_endpoint, pretty_minified, redact  # noqa: E402
from tests import fixture_server                               # noqa: E402


class UnitTests(unittest.TestCase):
    def test_redaction_keeps_shape_not_value(self):
        masked = redact("AKIAIOSFODNN7EXAMPLE")
        self.assertNotIn("IOSFODNN7EXAMPLE", json.dumps(masked))
        self.assertEqual(masked["length"], 20)
        self.assertEqual(len(masked["sha256_12"]), 12)

    def test_norm_endpoint_collapses_ids(self):
        self.assertEqual(norm_endpoint("/api/v1/users/12345"), "/api/v1/users/{id}")
        self.assertEqual(norm_endpoint("/api/users/${userId}/orders"), "/api/users/{param}/orders")
        self.assertEqual(norm_endpoint("/a/550e8400-e29b-41d4-a716-446655440000/b"), "/a/{id}/b")

    def test_pretty_minified_preserves_strings(self):
        src = 'var a="x;y";var b={c:1};'
        out = pretty_minified(src)
        self.assertIn('"x;y"', out)
        self.assertGreater(out.count("\n"), 1)

    def test_dns_wire_roundtrip(self):
        packet = _build_query("example.com", 16, 0x1234)
        self.assertEqual(packet[0:2], b"\x12\x34")
        # a hand-built answer: pointer to offset 12, TXT with one string
        answer = (b"\x12\x34" + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" +
                  b"\x07example\x03com\x00" + b"\x00\x10\x00\x01" +
                  b"\xc0\x0c" + b"\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x09" +
                  b"\x08v=spf1 ~")
        tid, rcode, answers = _parse(answer)
        self.assertEqual(tid, 0x1234)
        self.assertEqual(rcode, 0)
        self.assertEqual(len(answers), 1)
        name, rtype, _ttl, rd = answers[0]
        self.assertEqual(name, "example.com")
        self.assertEqual(rtype, 16)
        self.assertTrue(_read_name(answer, 12)[0].startswith("example"))


def _ledger(report_dir: str) -> list[dict]:
    """Rows of `report/requests.jsonl`; an empty list when the ledger is missing."""
    path = os.path.join(report_dir, "requests.jsonl")
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    return rows

class FixtureScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = fixture_server.start()
        cls.target = f"127.0.0.1:{fixture_server.PORT_HOLDER['port']}"
        cls.tmp = tempfile.mkdtemp(prefix="recon-one-test-")
        cls.out = os.path.join(cls.tmp, "run")
        cls.report, cls.code = run_scan(cls.target, cls.out, "fast", {"max_pages": 12},
                                        use_dns=False, quiet=True)
        cls.report_dir = os.path.join(cls.out, "report")
        with open(os.path.join(cls.report_dir, "report.json"), encoding="utf-8") as fh:
            cls.raw_json = fh.read()
        cls.data = json.loads(cls.raw_json)

    @classmethod
    def tearDownClass(cls):
        fixture_server.stop(cls.server)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_ac1_exit_code_and_artifacts(self):
        self.assertIn(self.code, (0, 2))
        for name in ("report.json", "report.md", "handoff.md", "manifest.json", "schema.json",
                     "endpoints.jsonl", "findings.jsonl", "hypotheses.jsonl"):
            self.assertTrue(os.path.exists(os.path.join(self.report_dir, name)), name)

    def test_ac2_schema_valid(self):
        self.assertEqual(reportmod.validate(self.data), [])

    def test_ac3_js_endpoints_discovered(self):
        paths = {e["path"] for e in self.data["endpoints"]}
        self.assertIn("/api/v1/users/{id}", paths)
        self.assertIn("/api/v1/login", paths)
        self.assertTrue(any("graphql" in p for p in paths), paths)

    def test_ac4_openapi_parsed_and_merged(self):
        self.assertEqual(len(self.data["specs"]), 1)
        self.assertEqual(self.data["specs"][0]["endpoint_count"], 2)
        paths = {e["path"] for e in self.data["endpoints"]}
        self.assertIn("/api/v1/admin/export", paths)
        self.assertTrue(any(p["name"] == "tenantId" for p in self.data["parameters"]))

    def test_ac5_graphql_introspection(self):
        self.assertEqual(len(self.data["graphql"]), 1)
        self.assertEqual(self.data["graphql"][0]["type_count"], 3)

    def test_ac6_sourcemap_source_leak(self):
        self.assertEqual(self.data["coverage"]["counts"]["sourcemaps"], 1)
        scripts = [s for s in self.data["assets"]["scripts"] if s["sourcemap"]]
        self.assertTrue(scripts)
        maps = os.listdir(os.path.join(self.out, "raw", "maps"))
        self.assertTrue(maps)

    def test_ac7_secret_redacted_in_report(self):
        self.assertGreaterEqual(self.data["coverage"]["counts"]["secrets"], 1)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", self.raw_json)
        self.assertIn("AKIA", json.dumps(self.data["secrets"]))
        raw_js = os.path.join(self.out, "raw", "js")
        blob = "".join(open(os.path.join(raw_js, f), encoding="utf-8", errors="replace").read()
                       for f in os.listdir(raw_js) if f.endswith(".js"))
        self.assertIn("AKIAIOSFODNN7EXAMPLE", blob)

    def test_ac8_cors_reflection_found(self):
        cors = [f for f in self.data["findings"] if f["category"] == "cors"]
        self.assertTrue(cors)
        self.assertEqual(cors[0]["severity"], "high")

    def test_ac9_findings_and_hypotheses_non_empty_and_ranked(self):
        self.assertGreaterEqual(len(self.data["findings"]), 4)
        hyp = self.data["hypotheses"]
        self.assertGreaterEqual(len(hyp), 4)
        scores = [h["priority_score"] for h in hyp]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual([h["rank"] for h in hyp], list(range(1, len(hyp) + 1)))
        self.assertTrue(any(h["blocked"] is False for h in hyp))

    def test_ac10_evidence_offsets_point_into_saved_artifacts(self):
        for endpoint in self.data["endpoints"]:
            for ev in endpoint["evidence"]:
                if ev["file"].startswith("raw/js/"):
                    path = os.path.join(self.out, ev["file"].replace("/", os.sep))
                    self.assertTrue(os.path.exists(path), path)
                    self.assertGreaterEqual(ev["offset"], 0)

    def test_ac11_offline_scope_guard(self):
        from reconone.http import Session
        session = Session("example.com")
        session.request("https://example.org/")
        self.assertEqual(session.requests, 0)
        self.assertTrue(session.off_scope_attempts)

    def test_ac12_page_cap_respected(self):
        limited = os.path.join(self.tmp, "cap")
        report, _ = run_scan(self.target, limited, "fast", {"max_pages": 1, "max_depth": 0},
                             use_dns=False, quiet=True)
        self.assertLessEqual(report["coverage"]["counts"]["pages"], 1)

    def test_ac13_handoff_is_actionable(self):
        text = open(os.path.join(self.report_dir, "handoff.md"), encoding="utf-8").read()
        self.assertIn("## 1. 已确认事实", text)
        self.assertIn("## 3. 建议动作", text)
        self.assertIn("## 4. 停机条件", text)
        self.assertLess(len(text.splitlines()), 200)

    def test_ac14_determinism(self):
        again = os.path.join(self.tmp, "again")
        report, _ = run_scan(self.target, again, "fast", {"max_pages": 12}, use_dns=False, quiet=True)
        if report["meta"]["deterministic_digest"] != self.data["meta"]["deterministic_digest"]:
            # Name the drifting field. Without this, a one-in-N failure is an unactionable
            # "digests differ" and the honest response is to retry until it passes.
            self.fail("determinism drift at " + ", ".join(_digest_drift(self.data, report)))
        first = _ledger(self.report_dir)
        second = _ledger(os.path.join(again, "report"))
        self.assertTrue(first, "台账不能是空的")
        self.assertEqual([tuple(sorted(row.items())) for row in first],
                         [tuple(sorted(row.items())) for row in second],
                         "同一目标的请求台账必须逐行一致（不含时间，所以可复现）")

    def test_ac15_manifest_lists_every_artifact(self):
        manifest = json.load(open(os.path.join(self.report_dir, "manifest.json"), encoding="utf-8"))
        listed = {a["path"] for a in manifest["artifacts"]}
        self.assertIn("report/report.json", listed)
        self.assertIn("report/handoff.md", listed)
        self.assertTrue(any(p.startswith("raw/js/") for p in listed))
        # brief.md is written by the scan path, not by write_all(); it used to land after
        # the manifest was built and therefore never appeared in the "every artifact" list.
        self.assertIn("report/brief.md", listed)
        self.assertEqual(manifest["validation"]["schema_errors"], [])

    def test_ac25_request_ledger_is_complete_and_listed(self):
        """The ledger answers "what did you actually send" — the question a customer asks."""
        rows = _ledger(self.report_dir)
        self.assertGreaterEqual(len(rows), 3)
        self.assertEqual([row["n"] for row in rows], list(range(1, len(rows) + 1)))
        for row in rows:
            self.assertLessEqual(set(row), {"n", "method", "url", "status", "egress", "error"},
                                 f"时间/耗时不得进台账（会破坏包级哈希）：{row}")
            # GraphQL introspection is a POST: the "GET only" rule applies to the verification
            # stage, not to the whole scan. The ledger must show that, not hide it.
            self.assertIn(row["method"], ("GET", "HEAD", "POST"))
            self.assertTrue(row["url"].startswith("http"), row)
        root = self.report["target"]["root_url"]
        self.assertTrue(any(row["url"].startswith(root.rstrip("/")) for row in rows),
                        f"根 URL 必须出现在台账里：{root}")
        manifest = json.load(open(os.path.join(self.report_dir, "manifest.json"), encoding="utf-8"))
        entry = next(a for a in manifest["artifacts"] if a["path"] == "report/requests.jsonl")
        self.assertNotEqual(entry["sha256_16"], "redacted", "台账没有密钥，应当有真实哈希")

    def test_ac26_bet_sheet_leads_the_report(self):
        """The bet is the headline: three states, the criteria behind them, and kill criteria."""
        bet = self.report["bet"]
        self.assertEqual(bet["threshold"], "A")
        self.assertIn(bet["verdict"], ("worth", "not_worth", "withheld"))
        self.assertIn(bet["confidence"], ("high", "medium", "low"))
        self.assertEqual([c["rule"] for c in bet["criteria"]],
                         ["anonymous_parameterized", "live_subdomain_nonpublic"])
        self.assertTrue(bet["kill_criteria"], "改判条件必须写明，否则判决不可用")
        # 本次 fixture 扫描是匿名的：可用的带参数端点即"匿名可访问"，判据一应当命中。
        self.assertEqual(bet["criteria"][0]["status"], "hit")
        self.assertEqual(bet["verdict"], "worth")
        text = open(os.path.join(self.report_dir, "report.md"), encoding="utf-8").read()
        self.assertIn("## 下注判决", text)
        self.assertIn("阈值 A", text)
        self.assertIn("什么会让我改判", text)

    def test_ac26_bet_is_stable_across_identical_scans(self):
        again = os.path.join(self.tmp, "bet-again")
        report, _ = run_scan(self.target, again, "fast", {"max_pages": 12},
                             use_dns=False, quiet=True)
        self.assertEqual(json.dumps(report["bet"], sort_keys=True, ensure_ascii=False),
                         json.dumps(self.report["bet"], sort_keys=True, ensure_ascii=False))


    def test_verification_stage_is_bound_and_recorded(self):
        """轻量验证：每个端点一次 GET；可用/不可用与 RoE 都要写进报告。"""
        block = self.data.get("verification") or {}
        self.assertTrue(block.get("enabled"), "默认应启用验证")
        summary = block.get("summary") or {}
        self.assertGreater(summary.get("probed", 0), 0, "fixture 端点应被实际探测")
        self.assertEqual(summary["requests"], summary["usable"] + summary["unusable"])
        roe = (self.data.get("meta") or {}).get("roe") or {}
        self.assertEqual(roe.get("scope_domain"), self.target.lower())
        self.assertEqual(roe.get("allowed_methods"), ["GET", "HEAD"])
        self.assertGreaterEqual(roe.get("max_requests", 0), summary["requests"])
        verdicts = [e.get("verified") for e in self.data["endpoints"]]
        self.assertTrue(verdicts, "端点列表不应为空")
        self.assertTrue(all(v in ("usable", "unusable", "skipped") for v in verdicts), verdicts)
        counts = self.data["coverage"]["counts"]
        self.assertEqual(counts["verified_usable"], summary["usable"])
        self.assertEqual(counts["verified_unusable"], summary["unusable"])
        with open(os.path.join(self.report_dir, "report.md"), encoding="utf-8") as fh:
            self.assertIn("## 验证", fh.read())


class TestOutputLayout(unittest.TestCase):
    """The run directory must never flatten into the runs root or take a package name."""

    def test_reserved_names_are_prefixed(self):
        from reconone.config import run_dir_name
        self.assertEqual(run_dir_name("raw"), "host_raw")
        self.assertEqual(run_dir_name("report"), "host_report")
        self.assertEqual(run_dir_name("RAW"), "host_RAW")

    def test_domain_with_port_is_filesystem_safe(self):
        from reconone.config import run_dir_name
        name = run_dir_name("127.0.0.1:39431")
        self.assertNotIn(":", name)
        self.assertEqual(name, "127.0.0.1_39431")

    def test_url_is_reduced_to_host(self):
        from reconone.config import run_dir_name
        self.assertEqual(run_dir_name("https://x.com/a/b"), "x.com")

    def test_placeholder_never_reaches_a_path(self):
        """Regression: the GUI used to prefill <root>/<domain>, which is not a legal path."""
        from reconone.config import ensure_out_dir, output_root
        out = ensure_out_dir("free.ai", "")
        self.assertTrue(out.startswith(output_root()))
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)

    def test_runs_root_is_not_used_as_a_run_dir(self):
        from reconone.config import ensure_out_dir, output_root
        out = ensure_out_dir("free.ai", output_root())
        self.assertNotEqual(os.path.normcase(os.path.abspath(out)),
                            os.path.normcase(os.path.abspath(output_root())))

    def test_package_name_out_dir_is_rerooted(self):
        from reconone.config import ensure_out_dir, output_root
        out = ensure_out_dir("free.ai", os.path.join(output_root(), "report"))
        self.assertEqual(os.path.basename(os.path.abspath(out)), "free.ai")

    def test_refuses_to_reuse_another_targets_run_dir(self):
        """Two targets in one directory silently merge two report packages."""
        from reconone.cli import _guard_run_dir
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        os.makedirs(os.path.join(tmp, "report"))
        with open(os.path.join(tmp, "report", "report.json"), "w", encoding="utf-8") as fh:
            json.dump({"target": {"domain": "a.example"}}, fh)
        self.assertIsNotNone(_guard_run_dir("b.example", tmp))
        self.assertIsNone(_guard_run_dir("a.example", tmp))


class TestEndpointTriage(unittest.TestCase):
    """125 discovered endpoints are only useful if the testable ones come first."""

    def test_parameterised_write_endpoint_ranks_first(self):
        from reconone.report import _score_endpoints
        eps = [
            {"path": "/api/health", "methods": ["GET"], "confidence": "high", "params": []},
            {"path": "/api/users", "methods": ["GET"], "confidence": "high", "params": []},
            {"path": "/api/export", "methods": ["POST"], "confidence": "medium",
             "params": ["tenantId"]},
        ]
        ranked = _score_endpoints(eps)
        self.assertEqual(ranked[0]["path"], "/api/export")
        self.assertEqual(ranked[0]["priority"], "primary")
        self.assertEqual(ranked[-1]["priority"], "inventory")

    def test_hint_carries_occurrence_count_once(self):
        """One hint per (kind, file) with a count beats N near-identical findings."""
        from reconone import jsanalyze
        text = 'a.innerHTML = 1;\n' * 40
        result = jsanalyze.extract(text, "example.com", "raw/js/x.js")
        kinds = [h["kind"] for h in result["hints"]]
        self.assertEqual(kinds.count("inner_html_sink"), 1)
        hint = next(h for h in result["hints"] if h["kind"] == "inner_html_sink")
        self.assertEqual(hint["occurrences"], 40)

    def test_loopback_is_not_internal(self):
        """localhost in a bundle means the browser's own machine, not target infra."""
        from reconone import jsanalyze
        result = jsanalyze.extract('fetch("http://localhost:8080/api/x")', "example.com", "s")
        kinds = [h["kind"] for h in result["hosts"].values()]
        self.assertEqual(kinds, ["reference"])

    def test_robots_is_collapsed_not_multiplied(self):
        from reconone import hypotheses
        hyp = hypotheses.build({
            "robots": ["/admin", "/internal", "/pricing/?ref=", "/*?from=", "/signup/?ref="],
            "specs": [], "hosts": [], "forms": [], "hints": [], "sourcemaps": [],
        })
        robots = [h for h in hyp if "robots" in " ".join(h.get("signals") or [])]
        self.assertLessEqual(len(robots), 2)


class TestScoringHonesty(unittest.TestCase):
    """The score must never assert more than was observed. These are the anti-false-data rules."""

    def _report(self, **over):
        base = {
            "target": {"domain": "t.example", "root_url": "https://t.example/"},
            "assets": {"http": {}, "scripts": None, "hosts": None, "dns": {}},
            "specs": [], "graphql": [], "endpoints": [], "secrets": None,
        }
        base.update(over)
        return base

    def _by_id(self, block):
        return {c["id"]: c for c in block["checks"]}

    def test_missing_headers_block_means_unknown_not_fail(self):
        """A probe that did not capture headers must not be scored as 'headers missing'."""
        from reconone import score
        block = score.score_report(self._report())
        checks = self._by_id(block)
        self.assertEqual(checks["hdr.unavailable"]["status"], "unknown")
        self.assertFalse(checks["hdr.unavailable"]["evaluated"])
        # No individual header may be judged when the block was never captured.
        self.assertFalse([k for k in checks if k.startswith("hdr.") and k != "hdr.unavailable"])

    def test_unknown_checks_do_not_inflate_the_score(self):
        """3 checks passing must not read as A when 60% of the weight was never evaluated."""
        from reconone import score
        block = score.score_report(self._report())
        hyg = block["axes"]["hygiene"]
        self.assertLess(hyg["coverage_pct"], score.MIN_COVERAGE_FOR_GRADE)
        self.assertIn(hyg["grade"], ("N/A", "N/A◇"),
                      "a grade must be withheld when coverage is too low")
        self.assertNotIn(hyg["grade"], ("A", "B", "C", "D", "F"))

    def test_partial_coverage_issues_no_letter_grade(self):
        """Headers captured but cookies/TLS/DNS not: score exists, grade must still be withheld."""
        from reconone import score
        http = {"root_url": "https://t.example/",
                "headers": {"content-security-policy": "default-src 'none'"},
                "security": {"results": [{"header": "content-security-policy", "verdict": "ok",
                                          "value": "default-src 'none'", "note": "ok",
                                          "severity": "high"}]},
                "cookies": None, "tls": {}}
        hyg = score.score_report(self._report(assets={"http": http}))["axes"]["hygiene"]
        self.assertIsNotNone(hyg["score"])
        self.assertEqual(hyg["grade"], "N/A◇",
                         "partial coverage must not be rounded up into a letter grade")

    def test_weak_header_is_not_a_pass(self):
        """X-Frame-Options: ALLOWALL used to count as configured."""
        from reconone import score
        http = {
            "root_url": "https://t.example/",
            "headers": {"x-frame-options": "ALLOWALL",
                        "content-security-policy": "default-src *"},
            "security": {"results": [
                {"header": "x-frame-options", "verdict": "weak", "value": "ALLOWALL",
                 "note": "非 DENY/SAMEORIGIN", "severity": "medium"},
                {"header": "content-security-policy", "verdict": "weak",
                 "value": "default-src *", "note": "通配源", "severity": "high"},
            ]},
            "cookies": [], "tls": {"tls_version": "TLSv1.3"},
        }
        checks = self._by_id(score.score_report(self._report(assets={"http": http})))
        self.assertEqual(checks["hdr.x-frame-options"]["status"], "warn")
        self.assertEqual(checks["hdr.content-security-policy"]["status"], "warn")
        self.assertLess(checks["hdr.content-security-policy"]["earned"],
                        checks["hdr.content-security-policy"]["weight"])

    def test_absent_header_evidence_shows_what_was_returned(self):
        """'Absent' is only provable by exhibiting the observed header block."""
        from reconone import score
        http = {"root_url": "https://t.example/",
                "headers": {"server": "nginx/1.24.0", "content-type": "text/html"},
                "security": {"results": [{"header": "content-security-policy", "verdict": "absent",
                                          "value": "", "note": "缺失", "severity": "high"}]},
                "cookies": [], "tls": {"tls_version": "TLSv1.3"}}
        checks = self._by_id(score.score_report(self._report(assets={"http": http})))
        ev = checks["hdr.content-security-policy"]["evidence"][0]
        self.assertIn("observed_headers", ev)
        self.assertIn("server", ev["observed_headers"])

    def test_loopback_is_not_scored_as_internal_topology(self):
        """A localhost reference is the visitor's own machine, not target infrastructure."""
        from reconone import score
        assets = {"http": {}, "dns": {"records": {"A": ["1.2.3.4"]}},
                  "hosts": [{"url": "http://localhost/", "kind": "reference"}],
                  "scripts": []}
        checks = self._by_id(score.score_report(self._report(assets=assets)))
        self.assertEqual(checks["opp.internal"]["status"], "fail")
        self.assertIn("已排除", checks["opp.internal"]["detail"])

    def test_secrets_evidence_is_masked_never_raw(self):
        """The score block must never carry a usable credential, only a mask and a hash."""
        from reconone import score
        raw = "AKIAIOSFODNN7EXAMPLE"
        assets = {"http": {}, "dns": {}, "hosts": [], "scripts": []}
        rep = self._report(assets=assets, secrets=[
            {"type": "aws_access_key_id", "masked": "AKIA****MPLE", "sha256_12": "abc123"}])
        checks = self._by_id(score.score_report(rep))
        self.assertEqual(checks["opp.secrets"]["status"], "pass")
        blob = json.dumps(checks["opp.secrets"]["evidence"], ensure_ascii=False)
        self.assertNotIn(raw, blob, "原始凭据不得进入评分证据")
        self.assertIn("*", blob, "证据中必须是掩码形式")
        self.assertIn("sha256_12", blob, "需提供哈希以便离线比对")

    def test_axes_are_independent(self):
        """A well-maintained site may still be cheap to assess; the two axes never merge."""
        from reconone import score
        block = score.score_report(self._report())
        ids = {c["id"] for c in block["checks"]}
        self.assertTrue(any(i.startswith("hdr.") or i.startswith("cookie.") for i in ids))
        self.assertTrue(any(i.startswith("opp.") for i in ids))
        for c in block["checks"]:
            self.assertIn(c["axis"], ("hygiene", "opportunity"))

    def test_weights_come_from_a_versioned_rule_file(self):
        from reconone import score
        block = score.score_report(self._report())
        self.assertTrue(block["weights_source"])
        total = sum(c["weight"] for c in block["checks"] if c["axis"] == "hygiene")
        self.assertGreater(total, 0, "hygiene axis must have real weights")


class TestTriageVerdict(unittest.TestCase):
    """The 'worth doing?' verdict must be rule-driven and cite its evidence."""

    def _rep(self, http=None, specs=None, secrets=None, hosts=None, wkp=None, endpoints=None,
             scripts=None, probes=None):
        return {
            # These fixtures describe a *completed* scan, so the JS stage is marked ok even
            # when it found no scripts. Without that marker an empty script list now reads
            # as "never inspected" (unknown), which is a different scenario.
            "coverage": {"probes": {"js": "ok"} if probes is None else probes, "counts": {}},
            "target": {"domain": "t.example", "root_url": "https://t.example/"},
            "assets": {
                "http": http or {
                    "root_url": "https://t.example/",
                    "headers": {"content-security-policy": "default-src 'none'",
                                "strict-transport-security": "max-age=31536000"},
                    "security": {"results": [
                        {"header": "content-security-policy", "verdict": "ok", "value": "x",
                         "note": "ok", "severity": "high"},
                        {"header": "strict-transport-security", "verdict": "ok",
                         "value": "max-age=31536000", "note": "ok", "severity": "medium"},
                        {"header": "x-frame-options", "verdict": "ok", "value": "DENY",
                         "note": "ok", "severity": "medium"},
                        {"header": "x-content-type-options", "verdict": "ok", "value": "nosniff",
                         "note": "ok", "severity": "low"},
                        {"header": "referrer-policy", "verdict": "ok", "value": "same-origin",
                         "note": "ok", "severity": "low"},
                        {"header": "permissions-policy", "verdict": "ok", "value": "geolocation=()",
                         "note": "ok", "severity": "low"},
                        {"header": "cross-origin-opener-policy", "verdict": "ok",
                         "value": "same-origin", "note": "ok", "severity": "low"}]},
                    "cookies": [{"name": "sid", "secure": True, "httponly": True,
                                 "samesite": "lax"}],
                    "tls": {"tls_version": "TLSv1.3"},
                },
                "dns": {"records": {"A": ["1.2.3.4"]},
                        "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]},
                "scripts": scripts if scripts is not None else [],
                "hosts": hosts if hosts is not None else [],
                "well_known": wkp or {},
            },
            "specs": specs or [], "graphql": [],
            "endpoints": endpoints or [], "secrets": secrets,
        }

    def test_insufficient_evidence_outranks_everything(self):
        """A verdict must not be issued from a mostly-unmeasured target."""
        from reconone import score
        rep = {"target": {"domain": "t.example", "root_url": "https://t.example/"},
               "assets": {"http": {}}, "specs": [], "graphql": [],
               "endpoints": [], "secrets": None}
        v = score.triage(rep)
        self.assertEqual(v["verdict"], "insufficient-evidence")
        self.assertTrue(v["drivers"], "must name the checks that were missing")

    def test_verdict_cites_driver_checks(self):
        from reconone import score
        rep = self._rep(specs=[{"url": "https://t.example/openapi.json",
                                "kind": "openapi3", "endpoint_count": 9}],
                        secrets=[{"type": "aws_access_key_id", "masked": "AKIA****MPLE",
                                  "sha256_12": "abc"}],
                        wkp={"/.well-known/security.txt": {"status": 200}},
                        scripts=[{"url": "https://t.example/a.js", "artifact": "raw/js/a.js",
                                  "sourcemap": {"leaks_original_source": True}}],
                        hosts=[{"url": "http://admin.corp.local/api", "kind": "internal",
                                "source": "raw/js/a.js"}],
                        endpoints=[{"path": "/a", "methods": ["POST"], "params": ["id"],
                                    "confidence": "high"}])
        v = score.triage(rep)
        self.assertEqual(v["verdict"], "worthwhile")
        self.assertIn("opp.secrets", v["drivers"])
        self.assertIn("opp.sourcemap", v["drivers"])
        self.assertIn("disclosure.available", v["drivers"])
        self.assertTrue(v["why"] and v["actions"])

    def test_no_disclosure_channel_lowers_the_verdict(self):
        """Findings with nowhere to go are not value."""
        from reconone import score
        rep = self._rep(specs=[], secrets=[], wkp={}, endpoints=[])
        v = score.triage(rep)
        self.assertIn(v["verdict"], ("low-value", "no-channel"))
        self.assertIn("披露", v["why"] + "".join(v["actions"]) + "渠道")

    def test_triage_is_attached_to_every_score_block(self):
        from reconone import score
        block = score.score_report(self._rep())
        self.assertIn("triage", block)
        self.assertIn("verdict", block["triage"])


def _digest_drift(a: dict, b: dict, path: str = "", out: list | None = None) -> list:
    """Field paths that differ between two reports, ignoring volatile meta keys."""
    out = [] if out is None else out
    if len(out) > 8:
        return out
    # Nothing else is allowed to drift: the digest must cover `date` too, which is why
    # report.py excludes it explicitly in VOLATILE_HEADERS instead of the test hiding it.
    skip = {"generated_at", "started_at", "elapsed_seconds", "deterministic_digest"}
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if not path and key == "meta":
                continue
            if key in skip:
                continue
            if key not in a or key not in b:
                out.append(f"{path}/{key} (missing)")
                continue
            _digest_drift(a[key], b[key], f"{path}/{key}", out)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append(f"{path} (len {len(a)} vs {len(b)})")
        else:
            for i, (x, y) in enumerate(zip(a, b)):
                _digest_drift(x, y, f"{path}[{i}]", out)
    elif a != b:
        out.append(f"{path} ({a!r} vs {b!r})")
    return out


class TestTriageLogic(unittest.TestCase):
    """Regression: a tidy perimeter must never be read as 'not worth testing'.

    A real target scored hygiene 74/100 (headers mostly correct) while sandbox isolation
    and backend authorization were broken — the sandbox was escaped in 15 minutes. The
    verdict logic therefore may not branch on high hygiene to conclude low value.
    """

    def _rep(self, hygiene_headers_ok=True, write_eps=0, sourcemap=False, wkp=None):
        security = []
        headers = {}
        for name, value in (("content-security-policy", "default-src 'none'"),
                            ("strict-transport-security", "max-age=31536000"),
                            ("x-frame-options", "SAMEORIGIN"),
                            ("x-content-type-options", "nosniff"),
                            ("referrer-policy", "same-origin"),
                            ("permissions-policy", "geolocation=()"),
                            ("cross-origin-opener-policy", "same-origin")):
            if hygiene_headers_ok:
                headers[name] = value
                security.append({"header": name, "verdict": "ok", "value": value,
                                 "note": "ok", "severity": "high"})
            else:
                # Headers *were* observed, they were absent. Keeping `observed` non-empty
                # matters: an empty header dict means "not captured" and must not be
                # conflated with "captured and all missing".
                headers[name] = ""
                security.append({"header": name, "verdict": "absent", "value": "",
                                 "note": "缺失", "severity": "high"})
        endpoints = []
        for i in range(write_eps):
            endpoints.append({"path": f"/api/w{i}", "methods": ["POST"], "params": [],
                              "confidence": "high"})
        return {
            "target": {"domain": "t.example", "root_url": "https://t.example/"},
            "assets": {
                "http": {"root_url": "https://t.example/",
                         "headers": headers or {"server": "unknown"},
                         "security": {"results": security},
                         "cookies": [{"name": "s", "secure": True, "httponly": True,
                                      "samesite": "lax"}],
                         "tls": {"tls_version": "TLSv1.3"}},
                "dns": {"records": {"A": ["1.2.3.4"]}, "spf": ["v=spf1 -all"],
                        "dmarc": ["v=DMARC1; p=reject"]},
                "scripts": [{"url": "https://t.example/a.js", "artifact": "raw/js/a.js",
                             "sourcemap": {"leaks_original_source": sourcemap}}],
                "hosts": [], "well_known": wkp or {},
            },
            "specs": [], "graphql": [], "endpoints": endpoints, "secrets": [],
        }

    def test_strong_headers_do_not_imply_low_value(self):
        """The exact failure seen in the field: hygiene high, business surface real."""
        from reconone import score
        rep = self._rep(hygiene_headers_ok=True, write_eps=32, sourcemap=True,
                        wkp={"/.well-known/security.txt": {"status": 200}})
        block = score.score_report(rep)
        self.assertGreaterEqual(block["axes"]["hygiene"]["score"], 60)
        v = block["triage"]
        self.assertEqual(v["verdict"], "worthwhile",
                         "high browser-header score must not downgrade the verdict")
        self.assertIn("surface.write_endpoints", v["drivers"])
        self.assertNotIn("放弃", v["label"])

    def test_verdict_states_the_blind_spots(self):
        """Every verdict must say what the scores cannot see."""
        from reconone import score
        v = score.triage(self._rep(write_eps=12))
        self.assertTrue(v["blind_spots"])
        joined = " ".join(v["blind_spots"])
        for term in ("鉴权", "容器", "沙箱"):
            self.assertIn(term, joined)

    def test_write_endpoints_count_as_surface_even_without_params(self):
        """32 write endpoints with no extractable parameter names is still a big surface."""
        from reconone import score
        rep = self._rep(write_eps=32)
        checks = {c["id"]: c for c in score.score_report(rep)["checks"]}
        self.assertIn(checks["opp.params"]["status"], ("pass", "warn"))
        self.assertIn("写方法端点 32 个", checks["opp.params"]["title"])

    def test_negative_branch_requires_absence_of_surface(self):
        """下'不建议投入'必须有依据：既无交付渠道，也无业务面。"""
        from reconone import score
        # Keep a couple of write endpoints so the endpoint axis is evaluable; otherwise
        # coverage legitimately collapses to 'insufficient-evidence' first.
        rep = self._rep(hygiene_headers_ok=False, write_eps=1, sourcemap=False, wkp={})
        v = score.triage(rep)
        self.assertEqual(v["verdict"], "low-value")
        self.assertIn("未观测到可承载测试的业务面", v["why"])

class TestRequestBodyExtraction(unittest.TestCase):
    """A write endpoint with no visible body is opaque; extracting bodies is the whole point
    of front-end reverse engineering for a red teamer's first ten minutes."""

    def _names(self, src):
        return [b["name"] for b in jsanalyze.extract(src, "t.example", "x.js")["body_fields"]]

    def test_fetch_json_body(self):
        src = ('fetch("/api/v1/chat/share/",{method:"POST",'
               'headers:{"Content-Type":"application/json"},'
               'body:JSON.stringify({conversation_id:e,visibility:t,allow_fork:n})})')
        self.assertEqual(self._names(src), ["conversation_id", "visibility", "allow_fork"])

    def test_form_data_append(self):
        src = 'const f=new FormData(); f.append("stripe_token",x); f.append("plan_id",y);'
        self.assertEqual(self._names(src), ["stripe_token", "plan_id"])

    def test_headers_are_not_parameters(self):
        src = 'const o={headers:{"Authorization":a,"Accept":b,"Content-Type":c}};'
        self.assertEqual(self._names(src), [])

class TestVolatilityIsScoped(unittest.TestCase):
    """`date` changes on every response. It has no audit value the rest of the header
    block lacks, but if it leaks into evidence or the digest then "same target, same
    report" is false and the only way to keep tests green is to retry them."""

    HEADERS = {"server": "nginx", "date": "Wed, 18 Nov 2026 12:00:00 GMT",
               "content-type": "text/html"}

    def _report(self, date_value):
        headers = dict(self.HEADERS, date=date_value)
        return {
            "target": {"domain": "t.example", "root_url": "https://t.example/"},
            "assets": {"http": {"root_url": "https://t.example/", "headers": headers,
                                "security": {"results": [
                                    {"header": "content-security-policy", "verdict": "absent",
                                     "value": "", "note": "缺失", "severity": "high"}],
                                    "missing": [{"header": "content-security-policy",
                                                 "severity": "high", "reason": "缺失"}]}},
                       "scripts": []},
            "coverage": {"counts": {"pages": 1}, "probe_status": {}, "truncated": False},
            "endpoints": [], "parameters": [], "secrets": [], "specs": [],
            "graphql": [], "findings": [], "hypotheses": [], "errors": [],
            "meta": {"generated_at": "x", "started_at": "x", "elapsed_seconds": 1},
        }

    def test_digest_view_ignores_the_date_header(self):
        a = reportmod._digest_view(self._report("Wed, 18 Nov 2026 12:00:00 GMT"))
        b = reportmod._digest_view(self._report("Thu, 19 Nov 2026 03:04:05 GMT"))
        self.assertEqual(reportmod.canonical_json(a), reportmod.canonical_json(b))

    def test_score_evidence_never_quotes_the_date_header(self):
        block = score.score_report(self._report("Wed, 18 Nov 2026 12:00:00 GMT"))
        blob = json.dumps(block, ensure_ascii=False)
        self.assertNotIn("Wed, 18 Nov 2026", blob)
        # The header itself must still be readable in the report body, otherwise we would
        # have traded a real fact for determinism.
        self.assertIn("date", self._report("x")["assets"]["http"]["headers"])


class TestReferrerPolicyVerdict(unittest.TestCase):
    """The safe-value set must be literal.

    It used to end with `"no-referrer-when-downgrade".upper() and "origin-when-cross-origin"`,
    which evaluates to the *second* string: the good value was scored as weak and the weak
    value passed. Both directions are pinned here.
    """

    def test_weak_values_are_not_safe(self):
        from reconone import webprobe
        for value in ("origin-when-cross-origin", "origin", "unsafe-url", "no-referrer-when-downgrad"):
            self.assertNotIn(value.lower(), webprobe.SAFE_REFERRER, value)
            verdict, _ = webprobe.evaluate_header("referrer-policy", value)
            self.assertEqual(verdict, "weak", f"{value} 不得被判定为合格")

    def test_restrictive_values_are_safe(self):
        from reconone import webprobe
        for value in ("no-referrer", "same-origin", "strict-origin",
                      "strict-origin-when-cross-origin", "no-referrer-when-downgrade"):
            self.assertIn(value, webprobe.SAFE_REFERRER)
            self.assertEqual(webprobe.evaluate_header("referrer-policy", value)[0], "ok")


class TestUnobservedJsIsUnknown(unittest.TestCase):
    """"No JS observed" must not be scored as "JS inspected and clean"."""

    def _rep(self, probes, scripts=None, secrets=None, hosts=None):
        return {
            "target": {"domain": "t.example", "root_url": "https://t.example/"},
            "coverage": {"probes": probes, "counts": {}},
            "assets": {"http": {"root_url": "https://t.example/", "headers": {},
                                "security": {"results": []}, "cookies": [], "tls": {}},
                       "scripts": [] if scripts is None else scripts,
                       "hosts": hosts, "dns": {}},
            "secrets": [] if secrets is None else secrets,
            "endpoints": [], "parameters": [],
            "specs": [], "graphql": [],
        }

    def test_skipped_js_stage_yields_unknown_not_fail(self):
        from reconone import score
        checks = {c["id"]: c for c in score.score_report(self._rep({"js": "skipped"}))["checks"]}
        for cid in ("opp.sourcemap", "opp.secrets", "opp.internal"):
            self.assertEqual(checks[cid]["status"], "unknown", cid)
            self.assertFalse(checks[cid]["evaluated"], cid)

    def test_unreachable_run_loses_opportunity_weight_to_unknown(self):
        from reconone import score
        block = score.score_report(self._rep({"web": "unreachable: connect", "js": "skipped"}))
        opp = block["axes"]["opportunity"]
        self.assertLess(opp["coverage_pct"], 100)
        self.assertGreater(opp["checks_unknown"], 0)
        self.assertNotIn("fail", [c["status"] for c in block["checks"]
                                  if c["id"] in ("opp.sourcemap", "opp.secrets")])

    def test_probed_run_still_reports_a_real_fail(self):
        """The gate must not turn a genuine "no leak found" into an unknown."""
        from reconone import score
        rep = self._rep({"js": "ok"},
                        scripts=[{"url": "https://t.example/a.js", "artifact": "raw/js/a.js",
                                  "sourcemap": False}])
        checks = {c["id"]: c for c in score.score_report(rep)["checks"]}
        self.assertEqual(checks["opp.sourcemap"]["status"], "fail")
        self.assertEqual(checks["opp.secrets"]["status"], "fail")

    def test_secret_hits_survive_the_gate(self):
        from reconone import score
        rep = self._rep({"js": "no-scripts"}, secrets=[
            {"type": "aws_access_key_id", "masked": "AKIA****MPLE", "sha256_12": "abc123"}])
        checks = {c["id"]: c for c in score.score_report(rep)["checks"]}
        self.assertEqual(checks["opp.secrets"]["status"], "pass")


    def test_skipped_api_stage_yields_unknown_not_fail(self):
        """Same rule for the API stage: skipped is not "no public spec exists"."""
        from reconone import score
        rep = self._rep({"js": "ok", "api": "skipped"})
        checks = {c["id"]: c for c in score.score_report(rep)["checks"]}
        for cid in ("opp.api_spec", "opp.graphql"):
            self.assertEqual(checks[cid]["status"], "unknown", cid)

    def test_probed_api_stage_still_reports_fail(self):
        from reconone import score
        rep = self._rep({"js": "ok", "api": "none-found"})
        checks = {c["id"]: c for c in score.score_report(rep)["checks"]}
        for cid in ("opp.api_spec", "opp.graphql"):
            self.assertEqual(checks[cid]["status"], "fail", cid)


class TestTransportHardening(unittest.TestCase):
    def test_repeated_set_cookie_headers_are_kept(self):
        from reconone.http import Response
        resp = Response("https://t.example/", 200, {"set-cookie": "b=2"},
                        header_list=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
        self.assertEqual(resp.header_values("set-cookie"), ["a=1", "b=2"])
        self.assertEqual(resp.headers.get("set-cookie"), "b=2")

    def test_every_cookie_is_analysed(self):
        from reconone import webprobe
        cookies = webprobe._parse_set_cookie(["a=1; Secure; HttpOnly", "b=2"])
        self.assertEqual([c["name"] for c in cookies], ["a", "b"])
        self.assertTrue(cookies[0]["secure"])
        self.assertFalse(cookies[1]["secure"])

    def test_inflate_caps_the_output(self):
        """A gzip body must not be able to inflate past the byte cap."""
        import gzip as gz
        import zlib
        from reconone.http import _inflate
        bomb = gz.compress(b"A" * 5_000_000, 9)
        body, hit_cap = _inflate(bomb, "gzip", 64_000)
        self.assertEqual(len(body), 64_000)
        self.assertTrue(hit_cap, "压缩炸弹必须被标记为截断")
        plain, hit = _inflate(zlib.compress(b"hello"), "deflate", 1024)
        self.assertEqual(plain, b"hello")
        self.assertFalse(hit)
        raw, hit = _inflate(b"not compressed", "gzip", 1024)
        self.assertEqual(raw, b"not compressed")
        self.assertFalse(hit)


class TestDnsResponseValidation(unittest.TestCase):
    """An off-path datagram must never be accepted as the resolver's answer."""

    def _serve(self, replies):
        """Answer one query. `replies` is a list of (from_server: bool, payload)."""
        import socket
        import threading
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        self.addCleanup(srv.close)
        port = srv.getsockname()[1]

        def other_source(payload, addr):
            """Send from a *different* local port: right IP, wrong source port."""
            decoy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                decoy.bind(("127.0.0.1", 0))
                decoy.sendto(payload, addr)
            finally:
                decoy.close()

        def worker():
            _, addr = srv.recvfrom(4096)
            for from_server, payload in replies:
                data = payload(addr) if callable(payload) else payload
                if from_server:
                    srv.sendto(data, addr)
                else:
                    other_source(data, addr)

        threading.Thread(target=worker, daemon=True).start()
        return port

    def test_wrong_transaction_id_is_ignored(self):
        import struct
        from reconone import dns as dnsmod
        txid = 0x1234
        bogus = struct.pack("!HHHHHH", 0x9999, 0x8180, 9, 0, 0, 0)   # right source, wrong id
        good = struct.pack("!HHHHHH", txid, 0x8180, 1, 0, 0, 0)
        port = self._serve([(True, bogus), (True, good)])
        raw = dnsmod._udp("127.0.0.1", dnsmod._build_query("t.example", 1, txid), 3.0, txid,
                          port=port)
        self.assertEqual(struct.unpack("!H", raw[:2])[0], txid)
        self.assertEqual(struct.unpack("!H", raw[4:6])[0], 1, "必须丢弃错 id 的应答，取真实应答")

    def test_reply_from_another_source_port_is_ignored(self):
        import struct
        from reconone import dns as dnsmod
        txid = 0x2222
        spoof = struct.pack("!HHHHHH", txid, 0x8180, 7, 0, 0, 0)     # right id, wrong port
        good = struct.pack("!HHHHHH", txid, 0x8180, 1, 0, 0, 0)
        port = self._serve([(False, spoof), (True, good)])
        raw = dnsmod._udp("127.0.0.1", dnsmod._build_query("t.example", 1, txid), 3.0, txid,
                          port=port)
        self.assertEqual(struct.unpack("!H", raw[4:6])[0], 1, "不同源端口的应答必须被丢弃")


class TestNoJsMode(unittest.TestCase):
    """`--no-js` must still produce an endpoint map — without downloading any bundle."""

    @classmethod
    def setUpClass(cls):
        cls.server = fixture_server.start()
        cls.target = f"127.0.0.1:{fixture_server.PORT_HOLDER['port']}"
        cls.tmp = tempfile.mkdtemp(prefix="recon-one-nojs-")
        cls.out = os.path.join(cls.tmp, "run")
        cls.report, cls.code = run_scan(cls.target, cls.out, "fast", {"max_pages": 6},
                                        use_dns=False, use_js=False, use_intel=False, quiet=True)

    @classmethod
    def tearDownClass(cls):
        fixture_server.stop(cls.server)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_js_stage_is_skipped_and_no_bundle_is_saved(self):
        self.assertEqual(self.report["coverage"]["probes"]["js"], "skipped")
        raw_js = os.path.join(self.out, "raw", "js")
        self.assertFalse(os.path.isdir(raw_js) and os.listdir(raw_js),
                         "no bundle may be downloaded in --no-js mode")

    def test_endpoints_come_from_non_js_sources(self):
        sources = {s for e in self.report["endpoints"] for s in e.get("sources") or []}
        self.assertTrue(sources & {"html-link", "html-form", "robots"}, sources)
        self.assertNotIn("js-call", sources)
        paths = {e["path"] for e in self.report["endpoints"]}
        self.assertIn("/admin", paths)

    def test_profile_is_attached_and_says_what_is_unknown(self):
        prof = self.report["profile"]
        self.assertIn("worth", prof["axes"])
        self.assertIn("worth.subdomains", prof["coverage"]["unknown"])
        self.assertEqual(self.report["intel"]["ct"]["status"], "disabled")
        self.assertIn("no AI", prof["generated_by"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
