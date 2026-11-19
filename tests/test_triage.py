"""Target profile scoring: deterministic, auditable, and honest about the unknown."""
from __future__ import annotations

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import triage  # noqa: E402


def _intel(subdomains=True, archive=True):
    ct = ({"status": "ok", "source": "certspotter",
           "subdomains": [f"h{i}.example.com" for i in range(10)],
           "first_cert": "2018-01-01", "last_cert": "2025-01-01"}
          if subdomains else {"status": "unavailable", "source": "ct", "reason": "502"})
    arch = ({"status": "ok", "source": "wayback", "snapshots": 120, "first": "2017",
             "last": "2025", "paths": ["/admin/login", "/api/v1/users"],
             "sensitive_paths": ["/admin/login", "/api/v1/users", "/debug", "/staging",
                                 "/backup"]}
            if archive else {"status": "unavailable", "source": "wayback", "reason": "timeout"})
    return {"ct": ct, "archive": arch,
            "geo": {"status": "disabled", "source": "ip-api"},
            "cve": {"status": "disabled", "source": "nvd"}}


def _report(**over):
    endpoints = ([{"path": f"/api/v{i}/items", "methods": ["POST"], "params": ["id"]}
                  for i in range(9)]
                 + [{"path": "/login", "methods": ["GET"], "params": []}])
    base = {
        "target": {"domain": "example.com", "root_url": "https://example.com/"},
        "coverage": {"counts": {"endpoints_write": 9, "endpoints_testable": 9}, "probes": {}},
        "assets": {
            "http": {"headers": {"server": "nginx/1.24.0", "x-powered-by": "PHP/7.4.3"},
                     "security": {"results": [], "cookies": []},
                     "tls": {"tls_version": "TLSv1.3"}},
            "technology": [{"name": "PHP"}, {"name": "jQuery"}],
            "forms": [{"action": "/login", "inputs": [{"name": "password", "type": "password"}]}],
            "well_known": {"/.well-known/security.txt": {"status": 200}},
            "dns": {"records": {"A": ["1.2.3.4"], "MX": ["mx.example.com"]},
                    "spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"],
                    "resolvers": ["1.1.1.1"]},
        },
        "endpoints": endpoints,
        "parameters": [{"name": f"p{i}"} for i in range(9)],
        "specs": [{"url": "https://example.com/openapi.json", "endpoint_count": 9}],
        "graphql": [{"url": "https://example.com/graphql", "type_count": 4}],
        "secrets": [], "findings": [], "hypotheses": [],
        "score": {"axes": {"hygiene": {"score": 45.0}}},
    }
    base.update(over)
    return base


class TestProfileShape(unittest.TestCase):
    def test_axes_bands_and_provenance(self):
        prof = triage.build(_report(), _intel())
        self.assertIn("worth", prof["axes"])
        self.assertIn("hardness", prof["axes"])
        self.assertIsNotNone(prof["axes"]["worth"]["score"])
        self.assertIsNotNone(prof["axes"]["hardness"]["score"])
        self.assertIn(prof["success"]["band"], ("low", "moderate", "elevated", "high"))
        self.assertFalse(prof["success"]["is_probability"])
        self.assertIn("worth.subdomains", prof["mode_split"]["passive"])
        self.assertIn("hard.subdomain_sprawl", prof["mode_split"]["passive"])
        self.assertIn("hard.rate_limit", prof["coverage"]["unknown"])
        self.assertIn("no AI", prof["generated_by"])

    def test_weights_are_internal_and_consistent(self):
        prof = triage.build(_report(), _intel())
        for axis in ("worth", "hardness"):
            rel = [c for c in prof["checks"] if c["axis"] == axis]
            self.assertAlmostEqual(sum(c["weight"] for c in rel), prof["axes"][axis]["total_weight"])
        self.assertTrue(all(c["source"] for c in prof["checks"]))

    def test_same_input_same_output(self):
        a = triage.build(_report(), _intel())
        b = triage.build(copy.deepcopy(_report()), copy.deepcopy(_intel()))
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))


class TestUnknownHandling(unittest.TestCase):
    def test_unavailable_intel_becomes_unknown_not_fail(self):
        prof = triage.build(_report(), _intel(subdomains=False, archive=False))
        by_id = {c["id"]: c for c in prof["checks"]}
        for cid in ("worth.subdomains", "worth.archive_sensitive", "hard.subdomain_sprawl"):
            self.assertEqual(by_id[cid]["status"], "unknown", cid)
            self.assertFalse(by_id[cid]["evaluated"], cid)
        self.assertLess(prof["axes"]["worth"]["coverage_pct"], 100)

    def test_low_coverage_withholds_the_index(self):
        thin = _report()
        thin["assets"] = {"http": {"headers": {}}, "technology": [], "forms": [],
                          "well_known": {}, "dns": {}}
        thin["endpoints"] = []
        thin["parameters"] = []
        thin["specs"] = []
        thin["graphql"] = []
        thin["coverage"] = {"counts": {}, "probes": {}}
        thin["score"] = {"axes": {"hygiene": {"score": None}}}
        prof = triage.build(thin, _intel(subdomains=False, archive=False))
        self.assertLess(prof["coverage"]["combined_pct"], triage.MIN_COVERAGE)
        self.assertIsNone(prof["success"]["index"])
        self.assertEqual(prof["success"]["band"], "unknown")


class TestSignals(unittest.TestCase):
    def test_waf_and_versions_raise_hardness(self):
        easy = triage.build(_report(), _intel())
        hard_rep = _report()
        hard_rep["assets"]["http"]["headers"] = {
            "server": "cloudflare", "cf-ray": "8a1b2c3d4e5f", "x-powered-by": "nextjs"}
        harder = triage.build(hard_rep, _intel())
        self.assertGreater(harder["axes"]["hardness"]["score"], easy["axes"]["hardness"]["score"])
        by_id = {c["id"]: c for c in harder["checks"]}
        self.assertEqual(by_id["hard.waf"]["status"], "pass")
        self.assertEqual(by_id["hard.version_hidden"]["status"], "pass")

    def test_more_surface_raises_worth(self):
        small = _report(endpoints=[{"path": "/a", "methods": ["GET"], "params": []}],
                        specs=[], graphql=[], parameters=[],
                        coverage={"counts": {"endpoints_write": 0}, "probes": {}})
        big = _report()
        self.assertGreater(triage.build(big, _intel())["axes"]["worth"]["score"],
                           triage.build(small, _intel())["axes"]["worth"]["score"])

    def test_site_type_and_dimensions_are_reported(self):
        intel = _intel()
        intel["site_type"] = {"status": "ok", "primary": "ecommerce", "candidates": []}
        prof = triage.build(_report(), intel)
        self.assertEqual(prof["dimensions"]["site_type"]["primary"], "ecommerce")
        self.assertEqual(prof["dimensions"]["subdomains"]["count"], 10)
        self.assertEqual(prof["dimensions"]["history"]["snapshots"], 120)
        self.assertEqual(prof["dimensions"]["dns"]["records"]["A"], 1)



class TestActiveProbeWiring(unittest.TestCase):
    """Active evidence must move the score, and the weight mix must be inspectable."""

    def test_live_surface_and_blocking_are_scored(self):
        report = _report(meta={"probe_stats": {"requests": 40, "blocked": 12,
                                               "blocked_pct": 30.0, "throttled": 3}})
        report["coverage"]["probes"] = {"crawl": "ok", "js": "ok"}
        for endpoint in report["endpoints"]:
            endpoint["sources"] = ["js-call"]
        prof = triage.build(report, _intel())
        by_id = {c["id"]: c for c in prof["checks"]}
        self.assertEqual(by_id["worth.live_surface"]["status"], "pass")
        self.assertEqual(by_id["hard.active_blocking"]["status"], "pass")
        self.assertIn("worth.live_surface", prof["mode_split"]["active"])
        self.assertIn("hard.active_blocking", prof["mode_split"]["active"])
        self.assertEqual(by_id["hard.active_blocking"]["mode"], "active")
        self.assertEqual(by_id["hard.active_blocking"]["evidence"][0]["throttled"], 3)

    def test_skipped_crawl_makes_the_active_check_unknown_not_fail(self):
        report = _report()
        report["coverage"]["probes"] = {"crawl": "skipped", "js": "skipped"}
        prof = triage.build(report, _intel())
        by_id = {c["id"]: c for c in prof["checks"]}
        self.assertEqual(by_id["worth.live_surface"]["status"], "unknown")
        self.assertFalse(by_id["worth.live_surface"]["evaluated"])

    def test_weight_mix_is_reported_and_active_carries_the_majority(self):
        report = _report(meta={"probe_stats": {"requests": 40, "blocked": 0,
                                               "blocked_pct": 0.0}})
        report["coverage"]["probes"] = {"crawl": "ok", "js": "ok"}
        prof = triage.build(report, _intel())
        weights = prof["weights"]
        self.assertAlmostEqual(weights["active"] + weights["passive"], weights["total"])
        self.assertGreater(weights["active"], weights["passive"],
                           "主动项必须占多数，否则「提高准确度权重」没有落地")
        self.assertGreater(weights["observed_share_pct"], 0)
        self.assertLessEqual(weights["observed_share_pct"], 100)



class TestBet(unittest.TestCase):
    """Threshold A: is there a parameterised endpoint that answers without credentials?"""

    def _report(self, **over):
        base = {
            "target": {"domain": "app.example.com"},
            "meta": {"session": {"enabled": False}},
            "coverage": {"complete": True, "truncated": False},
            "verification": {"enabled": True,
                             "summary": {"identity_model": "single", "probed": 1}},
            "endpoints": [],
            "assets": {"subdomains": []},
            "intel": {"ct": {"status": "ok", "subdomains": []}},
        }
        base.update(over)
        return base

    @staticmethod
    def _endpoint(path="/api/v1/orders", **over):
        # `authz_open=True` mirrors what annotate() stamps for a 2xx/3xx anonymous response;
        # "usable" alone means "the path exists" and is not a bet hit.
        entry = {"path": path, "methods": ["GET"], "params": [{"name": "id"}],
                 "verified": "usable", "authz_open": True}
        entry.update(over)
        return entry

    def test_anonymous_parameterised_endpoint_is_worth_the_bet(self):
        bet = triage.bet(self._report(endpoints=[self._endpoint()]))
        self.assertEqual(bet["verdict"], "worth")
        self.assertEqual(bet["criteria"][0]["status"], "hit")
        self.assertEqual(bet["counts"]["anonymous_open"], 1)
        self.assertEqual(bet["threshold"], "A")

    def test_confidence_grows_with_the_number_of_hits(self):
        one = triage.bet(self._report(endpoints=[self._endpoint("/a")]))
        two = triage.bet(self._report(endpoints=[self._endpoint("/a"), self._endpoint("/b")]))
        self.assertEqual(one["confidence"], "medium")
        self.assertEqual(two["confidence"], "high")

    def test_gated_under_dual_identity_is_not_exposure(self):
        report = self._report(
            meta={"session": {"enabled": True}},
            verification={"enabled": True, "summary": {"identity_model": "dual", "probed": 1}},
            endpoints=[self._endpoint(authz_open=False)],
            assets={"subdomains": [{"host": "h.example.com", "probed": True}]})
        bet = triage.bet(report)
        self.assertEqual(bet["criteria"][0]["status"], "miss")
        self.assertEqual(bet["counts"]["not_open"], 1)
        self.assertEqual(bet["verdict"], "not_worth")

    def test_single_identity_401_is_not_anonymous_open(self):
        """Existence (usable) must not be enough: a 401 is evidence of a gate, not of access."""
        bet = triage.bet(self._report(endpoints=[self._endpoint(authz_open=False)]))
        self.assertEqual(bet["criteria"][0]["status"], "miss")
        self.assertEqual(bet["counts"]["not_open"], 1)
        self.assertEqual(bet["counts"]["anonymous_open"], 0)
        self.assertEqual(bet["verdict"], "not_worth")

    def test_dual_identity_identical_answers_are_not_anonymous_open(self):
        """`same` means both identities see the same shell; it is not a content difference."""
        report = self._report(
            meta={"session": {"enabled": True}},
            verification={"enabled": True, "summary": {"identity_model": "dual", "probed": 1}},
            endpoints=[self._endpoint(authz_open=False,
                                      authz={"label": "same", "anon_status": 200})])
        bet = triage.bet(report)
        self.assertEqual(bet["criteria"][0]["status"], "miss")
        self.assertEqual(bet["verdict"], "not_worth")

    def test_an_unverified_parameterised_endpoint_blocks_a_negative(self):
        """One skipped parameterised endpoint is a possible hit; the verdict must be withheld."""
        report = self._report(
            meta={"session": {"enabled": True}},
            verification={"enabled": True, "summary": {"identity_model": "dual", "probed": 1}},
            endpoints=[self._endpoint("/a", authz_open=False),
                       self._endpoint("/b", verified="skipped")])
        bet = triage.bet(report)
        self.assertEqual(bet["criteria"][0]["status"], "unknown")
        self.assertEqual(bet["verdict"], "withheld")
        self.assertIn("未验证", "；".join(bet["unknowns"]))

    def test_a_host_with_a_port_is_not_an_ip(self):
        """`example.com:8443` has a subdomain dimension; only a real IP literal does not."""
        report = self._report(
            target={"domain": "example.com:8443"},
            assets={"subdomains": [{"host": "admin.example.com", "probed": False}]},
            intel={"ct": {"status": "ok", "subdomains": ["admin.example.com"]}})
        bet = triage.bet(report)
        self.assertEqual(bet["criteria"][1]["status"], "unknown")
        self.assertNotIn("IP 目标", bet["criteria"][1]["detail"])
        self.assertIn("子域面未评估", "；".join(bet["unknowns"]))

    def test_anonymous_open_under_dual_identity_is_a_hit(self):
        report = self._report(
            meta={"session": {"enabled": True}},
            verification={"enabled": True, "summary": {"identity_model": "dual", "probed": 1}},
            endpoints=[self._endpoint(authz_open=True, authz={"anon_status": 200})])
        bet = triage.bet(report)
        self.assertEqual(bet["verdict"], "worth")
        self.assertEqual(bet["evidence"][0]["anon_status"], 200)

    def test_disabled_verification_withholds_instead_of_denying(self):
        bet = triage.bet(self._report(verification={"enabled": False, "summary": {}},
                                      endpoints=[self._endpoint(verified=None)]))
        self.assertEqual(bet["criteria"][0]["status"], "unknown")
        self.assertEqual(bet["verdict"], "withheld")
        self.assertIn("withheld", bet["note"])

    def test_unprobed_subdomains_cannot_block_a_negative(self):
        """Criterion 2 may only promote: an unprobed subdomain half must not force `withheld`."""
        bet = triage.bet(self._report(assets={"subdomains": [{"host": "a.example.com",
                                                              "probed": False}]},
                                      intel={"ct": {"status": "ok",
                                                    "subdomains": ["a.example.com"]}}))
        self.assertEqual(bet["criteria"][1]["status"], "unknown")
        self.assertIn("子域面未评估", "；".join(bet["unknowns"]))
        self.assertEqual(bet["verdict"], "not_worth",
                         "判据一已明确未命中，缺子域不能变成 withheld")

    def test_a_pure_static_site_is_not_worth(self):
        """The falsification case: nothing parameterised, nothing gated, CT found no subdomains."""
        bet = triage.bet(self._report(endpoints=[],
                                      verification={"enabled": True,
                                                    "summary": {"identity_model": "single",
                                                                "probed": 0}}))
        self.assertEqual(bet["verdict"], "not_worth")
        self.assertEqual([c["status"] for c in bet["criteria"]], ["miss", "miss"])
        self.assertEqual(bet["unknowns"], [])

    def test_a_thin_scan_refuses_to_say_not_worth(self):
        bet = triage.bet(self._report(endpoints=[], coverage={"complete": False,
                                                             "truncated": True}))
        self.assertEqual(bet["verdict"], "withheld")
        self.assertIn("扫描被截断", "；".join(bet["unknowns"]))

    def test_an_ip_target_has_no_subdomain_dimension(self):
        bet = triage.bet(self._report(target={"domain": "127.0.0.1"}))
        self.assertEqual(bet["criteria"][1]["status"], "miss")
        self.assertEqual(bet["verdict"], "not_worth")

    def test_kill_criteria_are_always_stated(self):
        for endpoints in ([self._endpoint()], []):
            bet = triage.bet(self._report(endpoints=endpoints))
            self.assertGreaterEqual(len(bet["kill_criteria"]), 2)
            self.assertTrue(bet["definition"].startswith("A："))

    def test_bet_is_a_pure_function_of_the_report(self):
        report = self._report(endpoints=[self._endpoint()])
        first = json.dumps(triage.bet(copy.deepcopy(report)), sort_keys=True)
        second = json.dumps(triage.bet(copy.deepcopy(report)), sort_keys=True)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main(verbosity=2)
