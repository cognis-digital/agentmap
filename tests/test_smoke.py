"""Smoke tests for agentmap. Standard library only, no network."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentmap import TOOL_NAME, TOOL_VERSION, build_graph, scan
from agentmap.cli import main

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(REPO_ROOT, "demos", "01-basic")


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "agentmap")
        self.assertTrue(TOOL_VERSION)


class TestDemoGraph(unittest.TestCase):
    def test_demo_builds_graph_and_flags_unauth(self):
        graph = build_graph(DEMO)
        self.assertGreaterEqual(len(graph.nodes_of("agent")), 2)
        self.assertGreaterEqual(len(graph.nodes_of("mcp_server")), 3)
        self.assertTrue(graph.edges)
        # at least one unauthenticated link is flagged
        rules = {f.rule for f in graph.findings}
        self.assertIn("link.unauthenticated", rules)
        # shadow AI is detected
        self.assertIn("shadow.undeclared_endpoint", rules)
        self.assertTrue(graph.failed)

    def test_scan_returns_dict(self):
        d = scan(DEMO)
        self.assertEqual(d["tool"], "agentmap")
        self.assertIn("summary", d)
        self.assertGreater(d["summary"]["unauthenticated_links"], 0)


class TestCli(unittest.TestCase):
    def test_demo_fails_and_json(self):
        proc = subprocess.run(
            [sys.executable, "-m", "agentmap", "map", DEMO, "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["failed"])
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("link.unauthenticated", rules)

    def test_formats_render(self):
        for fmt in ("table", "json", "mermaid", "sarif"):
            rc = main(["map", DEMO, "--format", fmt])
            self.assertIn(rc, (0, 1), fmt)

    def test_missing_path_exits_2(self):
        self.assertEqual(main(["map", "/no/such/dir"]), 2)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
