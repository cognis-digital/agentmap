"""Hardening tests: error paths, edge cases, and bad-input handling."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentmap.core import (
    ConfigError,
    build_graph,
    parse_env_file,
    scan,
    _env_refs,
    _read_json,
)
from agentmap.mcp_server import _run_scan


def _scratch(files: dict) -> str:
    """Create a temp dir populated with {name: obj-or-str} and return path."""
    d = tempfile.mkdtemp()
    for name, content in files.items():
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            if isinstance(content, str):
                fh.write(content)
            else:
                json.dump(content, fh)
    return d


# ---------------------------------------------------------------------------
# File I/O error paths
# ---------------------------------------------------------------------------

class TestMissingAndBadFiles(unittest.TestCase):
    def test_build_graph_nonexistent_path_raises_config_error(self):
        with self.assertRaises(ConfigError) as ctx:
            build_graph("/no/such/path/xyz_agentmap")
        self.assertIn("not found", str(ctx.exception))

    def test_read_json_missing_file_raises_config_error(self):
        with self.assertRaises(ConfigError) as ctx:
            _read_json("/no/such/file.json")
        self.assertIn("cannot read", str(ctx.exception))

    def test_read_json_malformed_raises_config_error(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "bad.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("{not valid json,,}")
        with self.assertRaises(ConfigError) as ctx:
            _read_json(p)
        self.assertIn("invalid JSON", str(ctx.exception))

    def test_read_json_empty_file_raises_config_error(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "empty.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("")
        with self.assertRaises(ConfigError) as ctx:
            _read_json(p)
        self.assertIn("empty file", str(ctx.exception))

    def test_parse_env_file_missing_raises_config_error(self):
        with self.assertRaises(ConfigError) as ctx:
            parse_env_file("/no/such/.env")
        self.assertIn("cannot read env file", str(ctx.exception))


# ---------------------------------------------------------------------------
# Malformed config files — build_graph must NOT crash, must emit parse_error
# ---------------------------------------------------------------------------

class TestMalformedSourceFiles(unittest.TestCase):
    def test_malformed_mcp_json_produces_parse_error_finding(self):
        d = _scratch({"mcp.json": "{oops}"})
        # Should not raise; should return a graph with a parse_error finding
        g = build_graph(d)
        rules = {f.rule for f in g.findings}
        self.assertIn("source.parse_error", rules)

    def test_mcp_json_with_array_root_produces_parse_error_finding(self):
        # mcp.json whose top-level is a list (not an object) must be flagged
        d = _scratch({"mcp.json": [{"mcpServers": {}}]})
        g = build_graph(d)
        rules = {f.rule for f in g.findings}
        self.assertIn("source.parse_error", rules)

    def test_malformed_agents_json_produces_parse_error_finding(self):
        d = _scratch({"agents.json": "not json at all {"})
        g = build_graph(d)
        rules = {f.rule for f in g.findings}
        self.assertIn("source.parse_error", rules)

    def test_malformed_observations_json_produces_parse_error_finding(self):
        d = _scratch({"observations.json": "!!!"})
        g = build_graph(d)
        rules = {f.rule for f in g.findings}
        self.assertIn("source.parse_error", rules)

    def test_malformed_file_does_not_prevent_other_sources_from_loading(self):
        """A broken mcp.json must not suppress a valid agents.json."""
        d = _scratch({
            "mcp.json": "{bad",
            "agents.json": {"agents": [{"name": "alpha"}]},
        })
        g = build_graph(d)
        # The agent from agents.json must still appear
        self.assertIn("agent:alpha", g.nodes)

    def test_empty_directory_returns_empty_graph(self):
        d = tempfile.mkdtemp()
        g = build_graph(d)
        self.assertEqual(len(g.nodes), 0)
        self.assertEqual(len(g.edges), 0)
        self.assertEqual(len(g.findings), 0)


# ---------------------------------------------------------------------------
# CLI --out to an unwritable path exits 2
# ---------------------------------------------------------------------------

class TestCliOutputFile(unittest.TestCase):
    def test_bad_out_path_exits_2(self):
        from agentmap.cli import main
        demo = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "demos", "01-basic",
        )
        rc = main(["map", demo, "--out", "/no/such/dir/output.txt"])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# MCP server _run_scan input validation
# ---------------------------------------------------------------------------

class TestMcpServerInputValidation(unittest.TestCase):
    def test_missing_path_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _run_scan({})
        self.assertIn("missing", str(ctx.exception).lower())

    def test_none_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            _run_scan({"path": None})

    def test_empty_string_path_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _run_scan({"path": "   "})
        self.assertIn("non-empty", str(ctx.exception))

    def test_non_string_path_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _run_scan({"path": 42})
        self.assertIn("string", str(ctx.exception))


# ---------------------------------------------------------------------------
# Edge cases: empty collections, zero findings
# ---------------------------------------------------------------------------

class TestEdgeCases(unittest.TestCase):
    def test_empty_mcp_servers_object_produces_no_crash(self):
        d = _scratch({"mcp.json": {"mcpServers": {}}})
        g = build_graph(d)
        # No nodes from an empty server map
        self.assertEqual(len(g.nodes_of("mcp_server")), 0)

    def test_env_refs_on_non_string_values(self):
        # Should handle numbers, None, booleans without crashing
        refs = _env_refs(None)
        self.assertEqual(refs, [])
        refs = _env_refs(42)
        self.assertEqual(refs, [])
        refs = _env_refs(True)
        self.assertEqual(refs, [])

    def test_graph_risk_score_with_no_findings_is_zero(self):
        d = tempfile.mkdtemp()
        g = build_graph(d)
        self.assertEqual(g.risk_score, 0)

    def test_agents_with_no_name_are_skipped_cleanly(self):
        """Agents lacking a 'name'/'id' key must be silently skipped."""
        d = _scratch({"agents.json": {"agents": [
            {},
            {"role": "worker"},        # no name
            {"name": "named_agent"},   # valid
        ]}})
        g = build_graph(d)
        self.assertIn("agent:named_agent", g.nodes)
        # The two nameless entries must not create phantom nodes
        self.assertEqual(len(g.nodes_of("agent")), 1)

    def test_scan_returns_dict_on_empty_dir(self):
        d = tempfile.mkdtemp()
        result = scan(d)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["tool"], "agentmap")
        self.assertEqual(result["summary"]["agents"], 0)


if __name__ == "__main__":
    unittest.main()
