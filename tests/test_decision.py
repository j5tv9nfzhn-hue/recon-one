"""The canonical decision composes the evidence layers; it is not a fourth score."""
from __future__ import annotations

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import decision  # noqa: E402


def _report(surface="worth", channel=False, unknowns=None, confidence="high",
            worth=42.0, hardness=61.0, coverage=80.0):
    unknowns = unknowns or []
    actions = [u for u in unknowns if u.get("count")]
    return {
        "target": {"domain": "example.com", "status": 200},
        "bet": {
            "verdict": surface, "confidence": confidence,
            "counts": {"anonymous_open": 2 if surface == "worth" else 0},
            "criteria": [
                {"rule": "anonymous_parameterized",
                 "status": "hit" if surface == "worth" else "miss",
                 "detail": "2 个带参数端点无需凭据即可访问",
                 "endpoints": ["/api/a", "/api/b"]},
                {"rule": "live_subdomain_nonpublic",
                 "status": "miss", "detail": "CT 已查且未发现子域"},
            ],
        },
        "profile": {
            "axes": {"worth": {"score": worth, "coverage_pct": 80.0},
                     "hardness": {"score": hardness, "coverage_pct": 80.0}},
            "coverage": {"combined_pct": coverage},
        },
        "uncertainty": {
            "facts": {"parameterised_answered": 2, "parameterised_total": 2},
            "unknowns": unknowns,
            "next_actions": actions[:5],
            "verdict_flips": [{"from": surface, "to": "worth", "condition": "补观测",
                               "unknowns": [u["id"] for u in actions],
                               "cost_requests": sum(u.get("cost_requests", 0)
                                                    for u in actions)}],
        },
        "assets": {"well_known": {
            "/.well-known/security.txt": {"status": 200 if channel else 404},
        }},
    }


class TestDecision(unittest.TestCase):
    def test_worth_without_a_channel_is_not_a_clean_go(self):
        block = decision.build(_report("worth", channel=False))
        self.assertEqual(block["verdict"], "worth")
        self.assertEqual(block["headline"]["code"], "worth_no_channel")
        self.assertIn("交付出口", block["headline"]["label"])
        self.assertFalse(block["is_probability"])

    def test_worth_with_channel_is_the_go_state(self):
        block = decision.build(_report("worth", channel=True))
        self.assertEqual(block["headline"]["code"], "worth")
        self.assertIn("值得打", block["headline"]["label"])

    def test_not_worth_with_an_upgrade_path_says_so(self):
        upgrade = {"id": "subdomains.unprobed", "kind": "subdomains", "impact": "high",
                   "count": 1, "cost_requests": 1,
                   "could_change_verdict_to": ["worth"]}
        block = decision.build(_report("not_worth", channel=True, unknowns=[upgrade]))
        self.assertEqual(block["headline"]["code"], "not_worth_open")
        self.assertIn("可升级项", block["headline"]["label"])
        self.assertEqual(block["confidence"], "medium",
                         "高影响未知存在时，不得保持 high 置信度")

    def test_withheld_is_a_collect_decision(self):
        block = decision.build(_report("withheld", channel=True))
        self.assertEqual(block["headline"]["code"], "collect")
        self.assertIn("先补证据", block["headline"]["label"])

    def test_factors_cover_surface_value_resistance_unknown_and_delivery(self):
        block = decision.build(_report("worth", channel=True))
        ids = {factor["id"] for factor in block["factors"]}
        self.assertEqual(ids, {
            "anonymous_parameterized", "live_subdomain_nonpublic",
            "business_value_proxy", "resistance", "unknown_surface", "deliverability",
        })
        self.assertTrue(all(f["status"] for f in block["factors"]))
        self.assertEqual(block["facts"]["deliverability"], "present")

    def test_confidence_only_goes_down_when_a_high_impact_unknown_exists(self):
        confirm_only = {"id": "confirm.hit", "kind": "confirm", "impact": "high",
                        "count": 1, "cost_requests": 1,
                        "could_change_verdict_to": ["not_worth"]}
        block = decision.build(_report("worth", channel=True, unknowns=[confirm_only]))
        self.assertEqual(block["confidence"], "high",
                         "确认动作不是未测面，不能把 worth 的置信度压低")
        open_gap = {"id": "verification.parameterised_unverified",
                    "kind": "verification", "impact": "high", "count": 2,
                    "cost_requests": 2, "could_change_verdict_to": ["worth"]}
        lowered = decision.build(_report("withheld", channel=True, confidence="medium",
                                         unknowns=[open_gap]))
        self.assertEqual(lowered["confidence"], "low")

    def test_same_report_same_decision(self):
        report = _report("worth", channel=True)
        first = json.dumps(decision.build(copy.deepcopy(report)), sort_keys=True)
        second = json.dumps(decision.build(copy.deepcopy(report)), sort_keys=True)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
