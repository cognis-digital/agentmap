"""agentmap MCP server — exposes the mapper as an MCP capability.

Preferred path: if the Cognis suite runtime (`cognis_core.mcp`) is importable,
build the server through it so it shares the suite's transport/auth wiring.

Fallback path: a dependency-free, stdlib-only JSON-RPC 2.0 stdio server that
implements just enough of the Model Context Protocol (initialize, tools/list,
tools/call) to be driven by Claude Desktop / Cursor / Cognis.Studio without
any third-party packages.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

from agentmap.core import TOOL_NAME, TOOL_VERSION, scan

_DESCRIPTION = (
    "Map agent-to-agent / agent-to-MCP communications and flag shadow AI "
    "(unauthenticated, unmonitored, or undeclared links)."
)

_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": "Directory or file holding mcp.json / agent "
                           "configs / .env / observations.json to map.",
        }
    },
    "required": ["path"],
    "additionalProperties": False,
}


def _run_scan(arguments: Dict[str, Any]) -> Dict[str, Any]:
    path = arguments.get("path")
    if path is None:
        raise ValueError("missing required argument: path")
    if not isinstance(path, str):
        raise ValueError(
            f"'path' must be a string, got {type(path).__name__}"
        )
    path = path.strip()
    if not path:
        raise ValueError("'path' must be a non-empty string")
    return scan(path)


def _build_via_cognis_core():
    """Return a runnable server via the suite runtime, or None if absent."""
    try:
        from cognis_core.mcp import build_mcp_server  # type: ignore
    except Exception:
        return None
    return build_mcp_server(
        tool_name=TOOL_NAME,
        description=_DESCRIPTION,
        scan_fn=scan,
    )


# --------------------------------------------------------------------------
# Stdlib-only JSON-RPC stdio fallback
# --------------------------------------------------------------------------

def _handle(method: str, params: Dict[str, Any]) -> Any:
    if method == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "capabilities": {"tools": {}},
        }
    if method in ("tools/list", "listTools"):
        return {"tools": [{
            "name": "map",
            "description": _DESCRIPTION,
            "inputSchema": _INPUT_SCHEMA,
        }]}
    if method in ("tools/call", "callTool"):
        name = params.get("name")
        if name != "map":
            raise ValueError(f"unknown tool: {name}")
        result = _run_scan(params.get("arguments") or {})
        return {"content": [{
            "type": "text",
            "text": json.dumps(result, indent=2),
        }]}
    raise ValueError(f"unknown method: {method}")


def _serve_stdio() -> int:
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(req, dict):
                continue
            rid = req.get("id")
            try:
                result = _handle(req.get("method", ""), req.get("params") or {})
                resp = {"jsonrpc": "2.0", "id": rid, "result": result}
            except Exception as exc:  # noqa: BLE001
                resp = {"jsonrpc": "2.0", "id": rid,
                        "error": {"code": -32603, "message": str(exc)}}
            if rid is not None:
                try:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
                except OSError:
                    # Broken pipe or closed stdout — stop serving.
                    break
    except KeyboardInterrupt:
        pass
    return 0


def run_mcp_server() -> int:
    server = _build_via_cognis_core()
    if server is not None:
        return server() or 0
    return _serve_stdio()


if __name__ == "__main__":
    raise SystemExit(run_mcp_server())
