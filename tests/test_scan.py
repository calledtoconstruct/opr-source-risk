#!/usr/bin/env python3
"""Fixture tests for opr-source-risk (TDD)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from opr_source_risk.scan import scan_dir  # noqa: E402


class ScanFixtures(unittest.TestCase):
    def test_listen_all_fires_on_bind_all_interfaces(self) -> None:
        report = scan_dir(ROOT / "testdata" / "listen-all", ref="test", pkgname="fixture")
        facets = {f["facet"] for f in report["findings"]}
        self.assertIn("net.listen-all", facets)
        hit = next(f for f in report["findings"] if f["facet"] == "net.listen-all")
        self.assertIn("0.0.0.0", hit["evidence"])

    def test_clean_tree_has_no_findings(self) -> None:
        report = scan_dir(ROOT / "testdata" / "clean", ref="test", pkgname="fixture")
        self.assertEqual(report["findings"], [])
        statuses = {c["id"]: c["status"] for c in report["checks_run"]}
        self.assertIn(statuses.get("net.listen-all"), {"ok", "skipped"})

    def test_sudoers_nopasswd_fires(self) -> None:
        report = scan_dir(ROOT / "testdata" / "sudoers", ref="test", pkgname="fixture")
        facets = {f["facet"] for f in report["findings"]}
        self.assertIn("priv.sudoers-or-polkit", facets)

    def test_secret_pem_fires(self) -> None:
        report = scan_dir(ROOT / "testdata" / "secrets", ref="test", pkgname="fixture")
        facets = {f["facet"] for f in report["findings"]}
        self.assertIn("secret.in-tree", facets)

    def test_docs_listen_is_ignored(self) -> None:
        report = scan_dir(ROOT / "testdata" / "docs-only-listen", ref="test", pkgname="fixture")
        facets = {f["facet"] for f in report["findings"]}
        self.assertNotIn("net.listen-all", facets)

    def test_report_is_schema_v1(self) -> None:
        report = scan_dir(ROOT / "testdata" / "clean", ref="v1", pkgname="demo")
        self.assertEqual(report["schema"], 1)
        self.assertEqual(report["pkgname"], "demo")
        self.assertEqual(report["ref"], "v1")
        json.dumps(report)

    def test_python_ast_bind_is_ast_confidence(self) -> None:
        report = scan_dir(ROOT / "testdata" / "listen-all", ref="test", pkgname="fixture")
        hit = next(f for f in report["findings"] if f["facet"] == "net.listen-all")
        self.assertEqual(hit["confidence"], "ast")

    def test_systemd_listen_stream_is_config(self) -> None:
        report = scan_dir(ROOT / "testdata" / "systemd-listen", ref="test", pkgname="fixture")
        hit = next(f for f in report["findings"] if f["facet"] == "net.listen-all")
        self.assertEqual(hit["confidence"], "config")
        self.assertIn("ListenStream", hit["evidence"])

    def test_compose_published_port_is_config(self) -> None:
        report = scan_dir(ROOT / "testdata" / "compose-ports", ref="test", pkgname="fixture")
        hit = next(f for f in report["findings"] if f["facet"] == "net.listen-all")
        self.assertEqual(hit["confidence"], "config")

    def test_privileged_port_fires(self) -> None:
        report = scan_dir(ROOT / "testdata" / "privileged-port", ref="test", pkgname="fixture")
        facets = {f["facet"] for f in report["findings"]}
        self.assertIn("net.listen-privileged-port", facets)

    def test_chmod_777_fires(self) -> None:
        report = scan_dir(ROOT / "testdata" / "chmod-777", ref="test", pkgname="fixture")
        facets = {f["facet"] for f in report["findings"]}
        self.assertIn("fs.world-writable", facets)

    def test_curl_pipe_sh_fires(self) -> None:
        report = scan_dir(ROOT / "testdata" / "curl-pipe", ref="test", pkgname="fixture")
        facets = {f["facet"] for f in report["findings"]}
        self.assertIn("install.curl-pipe-shell", facets)


if __name__ == "__main__":
    unittest.main()
