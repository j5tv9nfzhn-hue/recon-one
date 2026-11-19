"""Unknown surface: rank what could change the bet, never invent a probability."""
from __future__ import annotations

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import uncertainty  # noqa: E402


def _report(**over):
    base = {
        "target": {"domain": "example.com", "status": 200},
        "meta": {"limits": {"discovery_max": 80}},
        "coverage": {"probes": {"js": "ok"}, "counts": {}, "truncated": False},
        "verification": {"enabled": True,
                         "summary": {"identity_model": "single", "probed": 1}},
        "endpoints": [],
        "assets": {"subdomains": []},
        "intel": {"ct": {"status": "ok"}, "archive": {"status": "ok"}},
        "discovery": {"enabled": True, "status": "ok", "stats": {}},
        "bet": {"verdict": "withheld", "confidence": "low"},
    }
    base.update(over)
    return base


def _bet(verdict="withheld", **over):
    base = {"verdict": verdict, "confidence": "low"}
    base.update(over)
    return base


class TestUncertainty(unittest.TestCase):
    def test_an_unverified_parameterised_endpoint_is_the_top_upgrade_path(self):
        endpoint = {"path": "/api/orders", "methods": ["GET"], "params": ["id"]}
        report = _report(endpoints=[endpoint])
        block = uncertainty.build(report, _bet("withheld"))
        self.assertTrue(block["next_actions"])
        top = block["next_actions"][0]
        self.assertEqual(top["id"], "verification.parameterised_unverified")
        self.assertEqual(top["impact"], "high")
        self.assertEqual(top["cost_requests"], 1, "单身份每端点一次 HEAD/GET")
        self.assertIn("worth", top["could_change_verdict_to"])
        self.assertTrue(any(flip["to"] == "worth" for flip in block["verdict_flips"]))
        self.assertTrue(any(flip["to"] == "not_worth" for flip in block["verdict_flips"]))

    def test_dual_identity_prices_verification_at_two_requests(self):
        endpoint = {"path": "/api/orders", "methods": ["GET"], "params": ["id"]}
        report = _report(
            endpoints=[endpoint],
            verification={"enabled": True,
                          "summary": {"identity_model": "dual", "probed": 1}})
        block = uncertainty.build(report, _bet("withheld"))
        top = block["next_actions"][0]
        self.assertEqual(top["cost_requests"], 2)

    def test_unprobed_subdomain_is_an_upgrade_path_from_not_worth(self):
        report = _report(
            assets={"subdomains": [{"host": "admin.example.com", "probed": False}]},
            bet={"verdict": "not_worth", "confidence": "medium"})
        block = uncertainty.build(report, _bet("not_worth"))
        item = next(i for i in block["unknowns"] if i["id"] == "subdomains.unprobed")
        self.assertEqual(item["impact"], "high")
        self.assertEqual(item["cost_requests"], 1)
        flip = next(f for f in block["verdict_flips"] if f["to"] == "worth")
        self.assertIn("subdomains.unprobed", flip["unknowns"])

    def test_verification_disabled_is_high_impact_and_can_go_either_way(self):
        endpoint = {"path": "/api/orders", "methods": ["GET"], "params": ["id"]}
        report = _report(
            endpoints=[endpoint],
            verification={"enabled": False, "summary": {}})
        block = uncertainty.build(report, _bet("withheld"))
        item = next(i for i in block["unknowns"] if i["id"] == "verification.disabled")
        self.assertEqual(item["impact"], "high")
        self.assertEqual(sorted(item["could_change_verdict_to"]), ["not_worth", "worth"])
        self.assertFalse(block["is_probability"])
        self.assertNotIn("probability", json.dumps(block["facts"]).lower())

    def test_worth_keeps_a_confirmation_path_back(self):
        endpoint = {"path": "/api/orders", "methods": ["GET"], "params": ["id"],
                    "verified": "usable", "authz_open": True}
        report = _report(endpoints=[endpoint])
        block = uncertainty.build(report, _bet("worth"))
        confirm = next(i for i in block["unknowns"] if i["id"] == "confirm.hit")
        self.assertEqual(confirm["impact"], "high")
        flip = next(f for f in block["verdict_flips"] if f["to"] == "not_worth")
        self.assertIn("confirm.hit", flip["unknowns"])

    def test_facts_measure_coverage_not_vulnerability(self):
        endpoints = [
            {"path": "/api/a", "methods": ["GET"], "params": ["id"],
             "verified": "usable", "authz_open": True},
            {"path": "/api/b", "methods": ["GET"], "params": ["q"]},
        ]
        report = _report(
            endpoints=endpoints,
            assets={"subdomains": [{"host": "a.example.com", "probed": True},
                                   {"host": "b.example.com", "probed": False}]},
        )
        block = uncertainty.build(report, _bet("withheld"))
        facts = block["facts"]
        self.assertEqual(facts["parameterised_checked_pct"], 50.0)
        self.assertEqual(facts["subdomains_checked_pct"], 50.0)
        self.assertFalse(block["is_probability"])
        self.assertIn("不是漏洞概率", " ".join(block["notes"]))

    def test_same_report_same_block(self):
        report = _report(endpoints=[{"path": "/api/a", "methods": ["GET"],
                                     "params": ["id"]}])
        first = json.dumps(uncertainty.build(copy.deepcopy(report), _bet()), sort_keys=True)
        second = json.dumps(uncertainty.build(copy.deepcopy(report), _bet()), sort_keys=True)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
