"""The dependency floor: `doctor` must prove the tool can run, not just import.

These tests are deliberately about *behaviour*: a broken check has to be reported as a
failure with its exception text, never raised into the caller, and the CLI has to translate
that into exit code 4 so a wrapper script can refuse to start a scan.
"""
from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconone import cli, doctor  # noqa: E402


class TestDoctor(unittest.TestCase):
    def test_every_check_passes_in_this_environment(self):
        result = doctor.run()
        self.assertTrue(result["ok"], [c for c in result["checks"] if not c["ok"]])
        ids = [c["id"] for c in result["checks"]]
        for expected in ("deps.python", "deps.httpx", "deps.anyio", "deps.dns", "deps.ssl"):
            self.assertIn(expected, ids)
        # A check that passes with an empty detail tells the operator nothing.
        self.assertTrue(all(c["detail"] for c in result["checks"]))
        self.assertIn("no network", result["generated_by"])

    def test_versions_come_from_installed_metadata(self):
        versions = doctor.versions()
        self.assertTrue(versions["python"])
        self.assertTrue(versions["httpx"], versions)
        self.assertTrue(versions["anyio"], versions)
        self.assertTrue(versions["ssl"])

    def test_a_broken_check_is_reported_and_not_raised(self):
        original = doctor.CHECKS

        def boom() -> str:
            raise RuntimeError("ssl module has no verify mode")

        doctor.CHECKS = original + (("deps.broken", "故意失败", boom),)
        try:
            result = doctor.run()
        finally:
            doctor.CHECKS = original
        self.assertFalse(result["ok"])
        bad = next(c for c in result["checks"] if c["id"] == "deps.broken")
        self.assertFalse(bad["ok"])
        self.assertIn("ssl module has no verify mode", bad["detail"])
        self.assertIn("deps.broken", doctor.summary(result))

    def test_summary_names_the_versions_when_everything_passes(self):
        text = doctor.summary(doctor.run())
        self.assertIn("httpx", text)
        self.assertIn("anyio", text)

    def test_cli_exits_zero_when_healthy_and_four_when_broken(self):
        self.assertEqual(cli.cmd_doctor(SimpleNamespace(json=True)), 0)
        original = doctor.run
        doctor.run = lambda: {"ok": False, "versions": {}, "checks": [
            {"id": "deps.httpx", "title": "httpx", "ok": False, "detail": "missing"}]}
        try:
            self.assertEqual(cli.cmd_doctor(SimpleNamespace(json=True)), 4)
        finally:
            doctor.run = original


if __name__ == "__main__":
    unittest.main()
