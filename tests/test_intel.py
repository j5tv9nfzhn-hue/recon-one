"""Passive intel providers. Every test injects a fake fetcher: nothing touches the network."""
from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import intel  # noqa: E402

# The behaviour under test is "tries twice", not "sleeps"; keep the suite fast.
intel.RETRY_DELAY = 0


def _certspotter():
    return [
        {"dns_names": ["*.example.com", "www.example.com", "api.example.com", "other.test"],
         "not_before": "2019-05-01T00:00:00Z", "not_after": "2020-05-01T00:00:00Z",
         "revoked": False},
        {"dns_names": ["admin.example.com", "example.com"],
         "not_before": "2024-01-02T00:00:00Z", "not_after": "2025-01-02T00:00:00Z",
         "revoked": True},
    ]


def _cdx():
    return [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20190301120000", "https://example.com/admin/login", "200", "text/html"],
        ["20210101120000", "https://example.com/api/v1/users", "200", "application/json"],
        ["20230101120000", "https://cdn.example.com/logo.png", "200", "image/png"],
        ["20230101120000", "https://other.test/x", "200", "text/html"],
    ]


class TestCertificateTransparency(unittest.TestCase):
    def test_keeps_only_the_target_zone(self):
        result = intel.ct_subdomains("example.com", fetch=lambda url: _certspotter())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["subdomains"], ["admin.example.com", "api.example.com",
                                                "www.example.com"])
        self.assertEqual(result["certs"], 2)
        self.assertEqual(result["first_cert"], "2019-05-01T00:00:00Z")
        self.assertEqual(result["last_cert"], "2024-01-02T00:00:00Z")
        self.assertTrue(result["passive"])

    def test_falls_back_to_crt_sh_when_certspotter_fails(self):
        def fetch(url):
            if "certspotter" in url:
                raise urllib.error.URLError("502 from certspotter")
            return [{"name_value": "a.example.com\n*.b.example.com\nmd5:deadbeef",
                     "not_before": "2020-01-01", "not_after": "2021-01-01"}]

        result = intel.ct_subdomains("example.com", fetch=fetch)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["source"], "crt.sh")
        self.assertEqual(result["subdomains"], ["a.example.com", "b.example.com"])

    def test_reports_unavailable_without_raising(self):
        def fetch(url):
            raise TimeoutError("no route")

        result = intel.ct_subdomains("example.com", fetch=fetch)
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("certspotter", result["reason"])
        self.assertIn("crt.sh", result["reason"])


class TestArchive(unittest.TestCase):
    def test_parses_paths_and_flags_sensitive_ones(self):
        result = intel.wayback("example.com", fetch=lambda url: _cdx())
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["snapshots"], 4)
        self.assertEqual(result["first"], "20190301120000")
        self.assertEqual(result["last"], "20230101120000")
        self.assertIn("/admin/login", result["sensitive_paths"])
        self.assertIn("/api/v1/users", result["sensitive_paths"])
        self.assertIn("cdn.example.com", result["hosts"])
        self.assertNotIn("other.test", result["hosts"])

    def test_empty_archive_is_empty_not_an_error(self):
        result = intel.wayback("example.com", fetch=lambda url: [])
        self.assertEqual(result["status"], "empty")
        self.assertEqual(result["snapshots"], 0)


class TestOptionalProviders(unittest.TestCase):
    def test_geo_is_disabled_by_default(self):
        result = intel.geoip("1.2.3.4", fetch=lambda url: {"status": "success"})
        self.assertEqual(result["status"], "disabled")

    def test_geo_parses_when_enabled(self):
        payload = {"status": "success", "query": "1.2.3.4", "country": "Netherlands",
                   "regionName": "Noord-Holland", "city": "Amsterdam",
                   "isp": "Example ISP", "org": "Example Org", "as": "AS1234 Example"}
        result = intel.geoip("1.2.3.4", fetch=lambda url: payload, enabled=True)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["country"], "Netherlands")
        self.assertEqual(result["asn"], "AS1234 Example")

    def test_cve_is_disabled_by_default(self):
        result = intel.cve_hints(["nginx/1.24.0"], fetch=lambda url: {})
        self.assertEqual(result["status"], "disabled")

    def test_cve_parses_hits(self):
        cve = {"id": "CVE-2024-0001",
               "descriptions": [{"value": "something in nginx"}],
               "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]}}
        payload = {"vulnerabilities": [{"cve": cve}]}
        result = intel.cve_hints(["nginx/1.24.0"], fetch=lambda url: payload, enabled=True)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["hits"][0]["id"], "CVE-2024-0001")
        self.assertEqual(result["hits"][0]["score"], "7.5")
        self.assertEqual(result["checked"], ["nginx/1.24.0"])

    def test_cve_without_a_version_is_not_queried(self):
        result = intel.cve_hints([], fetch=lambda url: {}, enabled=True)
        self.assertEqual(result["status"], "empty")


class TestSiteType(unittest.TestCase):
    def test_rules_pick_the_dominant_category(self):
        result = intel.classify_site(
            tech=[{"name": "Shopify"}, {"name": "React"}], title="Spring sale",
            paths=["/cart", "/checkout"], headers={})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["primary"], "ecommerce")
        self.assertTrue(any(e.startswith("tech:shopify") for e in result["candidates"][0]["evidence"]))

    def test_unknown_when_nothing_matches(self):
        result = intel.classify_site(tech=[], title="Hello", paths=["/"], headers={})
        self.assertEqual(result["primary"], "unknown")
        self.assertEqual(result["status"], "empty")


class TestGather(unittest.TestCase):
    def test_gather_folds_every_failure_into_status(self):
        def fetch(url):
            raise urllib.error.URLError("offline")

        result = intel.gather("example.com", fetch=fetch)
        for key in ("ct", "archive", "geo", "cve"):
            self.assertIn(result[key]["status"], ("unavailable", "disabled"), key)
        self.assertEqual(result["ct"]["status"], "unavailable")
        self.assertEqual(result["geo"]["status"], "disabled")
        self.assertTrue(result["passive"])




class TestRetry(unittest.TestCase):
    """A 502 in bursts is these indexes' normal failure mode, so one retry is required."""

    def test_transient_failure_is_retried_then_used(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if len(calls) == 1:
                raise urllib.error.URLError("502 from certspotter")
            return _certspotter()

        result = intel.ct_subdomains("example.com", fetch=fetch)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(calls), 2, "第一次失败后必须重试一次")
        self.assertEqual(result["subdomains"], ["admin.example.com", "api.example.com",
                                                "www.example.com"])

    def test_wayback_retries_once_before_giving_up(self):
        calls = []

        def fetch(url):
            calls.append(url)
            if len(calls) == 1:
                raise TimeoutError("read timed out")
            return _cdx()

        result = intel.wayback("example.com", fetch=fetch)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["snapshots"], 4)

    def test_a_dead_provider_is_tried_exactly_twice(self):
        calls = []

        def fetch(url):
            calls.append(url)
            raise TimeoutError("no route")

        result = intel.wayback("example.com", fetch=fetch)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(len(calls), intel.RETRY_ATTEMPTS)


class TestSubdomainsBecomeAssets(unittest.TestCase):
    """CT hosts must land in the report as assets, not stay a bare count."""

    def test_ct_hosts_are_listed_as_unprobed_assets(self):
        from reconone import report as reportmod

        assets = reportmod._subdomain_assets({"ct": {
            "status": "ok", "source": "crt.sh",
            "subdomains": ["a.example.com", "b.example.com"],
            "first_cert": "2020-01-01", "last_cert": "2025-01-01"}})
        self.assertEqual([a["host"] for a in assets], ["a.example.com", "b.example.com"])
        self.assertEqual(assets[0]["url"], "https://a.example.com/")
        self.assertEqual(assets[0]["source"], "crt.sh")
        self.assertTrue(assets[0]["passive"])
        self.assertFalse(assets[0]["probed"], "CT 只证明签发过证书，不等于本次扫描过")

    def test_no_assets_when_ct_did_not_answer(self):
        from reconone import report as reportmod

        for status in ("unavailable", "disabled", "empty", ""):
            self.assertEqual(reportmod._subdomain_assets({"ct": {"status": status}}), [], status)
        self.assertEqual(reportmod._subdomain_assets(None), [])


class TestDigestHygiene(unittest.TestCase):
    def test_run_telemetry_is_excluded_from_the_digest(self):
        """`probe_stats` / `deps` describe our run, not the target: two scans of an unchanged
        site must digest the same even when the request count differs."""
        from reconone import report as reportmod

        base = {"target": {"domain": "x.example"},
                "meta": {"generated_at": "", "probe_stats": {"requests": 10, "blocked": 0},
                         "deps": {"httpx": "0.28.1"}}}
        other = {"target": {"domain": "x.example"},
                 "meta": {"generated_at": "", "probe_stats": {"requests": 99, "blocked": 7},
                          "deps": {"httpx": "0.29.0"}}}
        self.assertEqual(json.dumps(reportmod._digest_view(base), sort_keys=True),
                         json.dumps(reportmod._digest_view(other), sort_keys=True))

if __name__ == "__main__":
    unittest.main(verbosity=2)
