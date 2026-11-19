"""Targeted content discovery: bounded candidates, a 404 baseline, and no invented hits."""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import discovery  # noqa: E402


class _Resp:
    def __init__(self, status=0, body=b"", error=None):
        self.status = status
        self.body = body
        self.error = error


class _Sess:
    def __init__(self, responses, exhausted=False):
        self.responses = responses
        self.calls: list[str] = []
        self.exhausted = exhausted
        self.deadline = None

    def request(self, url, method="GET", max_bytes=None):
        self.calls.append(url)
        return self.responses.get(url, _Resp(404, b"not found"))


_RULES = {
    "max_candidates": 20,
    "common": ["/health", "/admin/"],
    "tech": {"next.js": ["/_next/", "/api/"], "wordpress": ["/wp-admin/"]},
}


class TestCandidates(unittest.TestCase):
    def test_prefixes_are_derived_from_observed_paths(self):
        paths = ["/api/v1/users/{id}", "/api/v1/orders", "/{id}/hidden"]
        prefixes = discovery._prefixes(paths)
        self.assertIn("/api/", prefixes)
        self.assertIn("/api/v1/", prefixes)
        self.assertIn("/api/v1/users/", prefixes)
        self.assertFalse(any("{id}" in p for p in prefixes))

    def test_tech_paths_come_before_prefixes_and_dedupe(self):
        paths = ["/api/v1/users/{id}"]
        selected, dropped = discovery.candidates(
            paths, ["Next.js", "nginx"], "example.com", _RULES, 20)
        found = [item["path"] for item in selected]
        self.assertEqual(found[:2], ["/_next/", "/api/"])
        self.assertIn("/health", found)
        self.assertIn("/api/v1/", found)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(found), len(set(found)), "候选不能重复")

    def test_existing_relative_static_and_external_paths_are_skipped(self):
        paths = ["/api/", "/assets/app.js", "https://other.example/x", "/"]
        selected, _ = discovery.candidates(paths, [], "example.com", _RULES, 20)
        found = {item["path"] for item in selected}
        self.assertNotIn("/api/", found, "已有端点不应再花一次请求")
        self.assertFalse(any(p.endswith(".js") for p in found))
        self.assertFalse(any(p.startswith("/x") for p in found), "绝对 URL 不得被改写成目标路径")

    def test_cap_is_hard_and_dropped_is_counted(self):
        rules = {"max_candidates": 50, "common": [f"/p{i}" for i in range(10)], "tech": {}}
        selected, dropped = discovery.candidates([], [], "example.com", rules, 3)
        self.assertEqual(len(selected), 3)
        self.assertEqual(dropped, 7)

    def test_destructive_paths_are_not_candidates(self):
        rules = {"max_candidates": 50, "common": ["/logout", "/account/delete", "/health"],
                 "tech": {}}
        selected, _ = discovery.candidates([], [], "example.com", rules, 50)
        found = {item["path"] for item in selected}
        self.assertIn("/health", found)
        self.assertNotIn("/logout", found)
        self.assertNotIn("/account/delete", found)

    def test_baseline_path_is_stable_and_domain_specific(self):
        self.assertEqual(discovery.baseline_path("example.com"),
                         discovery.baseline_path("example.com"))
        self.assertNotEqual(discovery.baseline_path("example.com"),
                            discovery.baseline_path("other.example"))


class TestRun(unittest.TestCase):
    def _base(self, domain="example.com"):
        return "https://" + domain

    def _rules(self):
        return {"max_candidates": 10, "common": ["/api/", "/admin/", "/health"], "tech": {}}

    def test_baseline_404_separates_present_gated_and_absent(self):
        base = self._base()
        root_probe = base + discovery.baseline_path("example.com")
        api_probe = base + "/api/" + discovery.baseline_path("example.com").lstrip("/")
        responses = {
            root_probe: _Resp(404, b"not found"),
            api_probe: _Resp(404, b"not found"),
            base + "/api/": _Resp(200, b'{"ok":true}'),
            base + "/admin/": _Resp(401, b"login"),
            base + "/health": _Resp(404, b"not found"),
        }
        sess = _Sess(responses)
        block = discovery.run(sess, base, [], [], "example.com", 10, self._rules())
        self.assertEqual(block["status"], "ok")
        self.assertEqual(block["stats"]["probed"], 3)
        self.assertEqual(block["stats"]["present"], 1)
        self.assertEqual(block["stats"]["gated"], 1)
        self.assertEqual(block["stats"]["absent"], 1)
        labels = {row["path"]: row["label"] for row in block["rows"]}
        self.assertEqual(labels, {"/api/": "present", "/admin/": "gated", "/health": "absent"})
        self.assertEqual(block["stats"]["requests"], len(block["baselines"]) + 3)
        self.assertEqual(len(sess.calls), block["stats"]["requests"])

    def test_soft_404_baseline_does_not_invent_paths(self):
        base = self._base()
        root_probe = base + discovery.baseline_path("example.com")
        api_probe = base + "/api/" + discovery.baseline_path("example.com").lstrip("/")
        shell = b"<html><title>App shell</title><div id=app></div></html>"
        responses = {
            root_probe: _Resp(200, shell),
            api_probe: _Resp(200, shell),
            base + "/api/": _Resp(200, shell),
            base + "/admin/": _Resp(200, b"<html><title>Admin login</title>real</html>"),
            base + "/health": _Resp(200, shell),
        }
        block = discovery.run(_Sess(responses), base, [], [], "example.com", 10, self._rules())
        labels = {row["path"]: row["label"] for row in block["rows"]}
        self.assertEqual(labels["/api/"], "absent", "与基线相同的 SPA 壳不是新路径")
        self.assertEqual(labels["/health"], "absent")
        self.assertEqual(labels["/admin/"], "present")
        self.assertTrue(any(row["soft_404"] for row in block["rows"]))

    def test_an_api_catch_all_is_not_a_found_path(self):
        """A 200 generic body under `/api/` must not turn every prefix into a finding."""
        base = self._base()
        root_probe = base + discovery.baseline_path("example.com")
        api_probe = base + "/api/" + discovery.baseline_path("example.com").lstrip("/")
        generic = b'{"user":{"id":"1"}}'
        rules = {"max_candidates": 10, "common": ["/api/", "/api/v1/"], "tech": {}}
        responses = {
            root_probe: _Resp(404, b"not found"),
            api_probe: _Resp(200, generic),
            base + "/api/": _Resp(200, generic),
            base + "/api/v1/": _Resp(200, generic),
        }
        block = discovery.run(_Sess(responses), base, [], [], "example.com", 10, rules)
        labels = {row["path"]: row["label"] for row in block["rows"]}
        self.assertEqual(labels["/api/"], "present", "根基线 404，/api/ 是可区分的路径")
        self.assertEqual(labels["/api/v1/"], "absent", "同一前缀下的 200 泛型响应不是新路径")

    def test_a_blocked_prefix_marks_children_without_probing(self):
        base = self._base()
        root_probe = base + discovery.baseline_path("example.com")
        api_probe = base + "/api/" + discovery.baseline_path("example.com").lstrip("/")
        rules = {"max_candidates": 10, "common": ["/api/", "/api/v1/"], "tech": {}}
        sess = _Sess({
            root_probe: _Resp(404, b"not found"),
            api_probe: _Resp(401, b"login"),
            base + "/api/": _Resp(200, b"ok"),
        })
        block = discovery.run(sess, base, [], [], "example.com", 10, rules)
        labels = {row["path"]: row["label"] for row in block["rows"]}
        self.assertEqual(labels["/api/"], "present")
        self.assertEqual(labels["/api/v1/"], "error")
        self.assertEqual(block["stats"]["skipped_by_baseline"], 1)
        self.assertNotIn(base + "/api/v1/", sess.calls,
                         "前缀基线被拦截时不得继续探测其子路径")

    def test_blocked_baseline_probes_nothing(self):
        base = self._base()
        baseline = base + discovery.baseline_path("example.com")
        sess = _Sess({baseline: _Resp(401, b"login")})
        block = discovery.run(sess, base, [], [], "example.com", 10, self._rules())
        self.assertEqual(block["status"], "baseline-blocked")
        self.assertEqual(block["stats"]["probed"], 0)
        self.assertEqual(len(sess.calls), 1, "基线被拦截时不能继续探测候选")
        self.assertIn("401", block["reason"])

    def test_exhausted_budget_marks_truncated(self):
        base = self._base()
        baseline = base + discovery.baseline_path("example.com")
        block = discovery.run(_Sess({baseline: _Resp(404, b"x")}, exhausted=True),
                              base, [], [], "example.com", 10, self._rules())
        self.assertEqual(block["status"], "truncated")
        self.assertTrue(block["stats"]["truncated"])
        self.assertEqual(block["stats"]["probed"], 0)

    def test_endpoints_expose_only_positive_rows_without_authz_claim(self):
        base = self._base()
        baseline = base + discovery.baseline_path("example.com")
        responses = {
            baseline: _Resp(404, b"not found"),
            base + "/api/": _Resp(200, b'{"ok":true}'),
            base + "/admin/": _Resp(401, b"login"),
            base + "/health": _Resp(404, b"not found"),
        }
        block = discovery.run(_Sess(responses), base, [], [], "example.com", 10, self._rules())
        rows = discovery.endpoints(block)
        self.assertEqual({row["path"] for row in rows}, {"/api/", "/admin/"})
        self.assertTrue(all(row["discovered"] for row in rows))
        self.assertTrue(all("authz_open" not in row for row in rows),
                        "发现请求用的是本次身份，不能声称匿名开放")
        self.assertTrue(all(row["sources"] == ["content-discovery"] for row in rows))


if __name__ == "__main__":
    unittest.main()
