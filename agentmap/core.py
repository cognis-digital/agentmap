"""Core graph + shadow-AI engine for agentmap.

agentmap discovers the agent-to-agent / agent-to-MCP communication topology
from a directory of local configuration sources, normalizes the heterogeneous
formats into a single typed graph, and applies a rule set that surfaces
"shadow AI" — links that are UNAUTHENTICATED or UNMONITORED (no logging), and
nodes/edges that nothing in the declared inventory accounts for.

Inputs it understands (all parsed locally, no network):

  * mcp.json / *.mcp.json / *-mcp.json
        The de-facto MCP client config (Claude Desktop / Cursor / Cline style):
            {"mcpServers": {"<name>": {"command": ..., "url": ..., "env": ...}}}
        Each server becomes an MCP-server node; each agent that references it
        (or an implicit "host" agent) gets an edge to it.

  * agent config files (agents.json, *.agent.json, agents/*.json)
        A list (or object) of agents, each optionally declaring the servers /
        peer agents it talks to and whether those calls are authed / logged.

  * an env file (.env / agentmap.env)
        Scanned for credentials. A server whose auth depends on an env var
        that is MISSING from the env file is flagged as effectively
        unauthenticated.

  * an optional connections / observations JSON (connections.json,
    observations.json)
        Empirically observed edges (e.g. captured from telemetry). Any
        observed edge whose endpoints are NOT in the declared inventory is
        flagged as shadow AI — an agent or server nobody declared.

The output is a single Graph object that can be rendered to JSON, a Mermaid
diagram, or a table summary.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "agentmap"
TOOL_VERSION = "0.1.0"

# Severity ordering, highest first. Used for sorting + exit-code policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Node kinds in the graph.
KIND_AGENT = "agent"
KIND_MCP = "mcp_server"
KIND_TOOL = "tool"

# Env-var reference patterns, e.g. ${TOKEN}, $TOKEN, %TOKEN%, {{TOKEN}}.
_ENV_REF_RE = re.compile(
    r"(?:\$\{(\w+)\}|\$(\w+)|%(\w+)%|\{\{\s*(\w+)\s*\}\})"
)

# Keys whose presence on a server/edge indicates an auth mechanism.
_AUTH_KEYS = (
    "auth", "authorization", "token", "api_key", "apikey", "apiKey",
    "bearer", "headers", "oauth", "credentials", "key", "secret",
)

# Keys whose presence indicates logging / monitoring of a link.
_LOG_KEYS = (
    "logging", "log", "audit", "monitor", "monitored", "telemetry",
    "observability", "trace", "tracing",
)

# Header names that carry auth material.
_AUTH_HEADER_RE = re.compile(
    r"(?i)\b(authorization|x-api-key|api-key|x-auth-token|bearer)\b"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Node:
    id: str
    kind: str
    label: str = ""
    attrs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Edge:
    src: str
    dst: str
    # "uses" (agent->server), "exposes" (server->tool), "a2a" (agent->agent)
    relation: str = "uses"
    authenticated: bool = False
    monitored: bool = False
    transport: str = ""
    source: str = ""           # which config file this edge came from
    observed: bool = False     # came from observations rather than declaration
    attrs: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.src}->{self.dst}:{self.relation}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        return d


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Graph:
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: List[Edge] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)

    # -- mutation helpers --------------------------------------------------
    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is None:
            self.nodes[node.id] = node
            return node
        # merge attrs; keep first non-empty label
        if not existing.label and node.label:
            existing.label = node.label
        existing.attrs.update({k: v for k, v in node.attrs.items()
                               if k not in existing.attrs})
        return existing

    def add_edge(self, edge: Edge) -> Edge:
        for e in self.edges:
            if e.id == edge.id:
                # merge: an edge is authed/monitored if ANY source says so
                e.authenticated = e.authenticated or edge.authenticated
                e.monitored = e.monitored or edge.monitored
                e.transport = e.transport or edge.transport
                e.observed = e.observed and edge.observed
                e.attrs.update(edge.attrs)
                return e
        self.edges.append(edge)
        return edge

    # -- queries -----------------------------------------------------------
    def nodes_of(self, kind: str) -> List[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def risk_score(self) -> int:
        """0-100; higher = more exposed. Mirrors the suite's scoring shape."""
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        penalty = sum(weights[f.severity] for f in self.findings)
        return min(100, penalty)

    @property
    def failed(self) -> bool:
        c = self.counts
        return c["critical"] > 0 or c["high"] > 0

    @property
    def summary(self) -> Dict[str, int]:
        unauth = sum(1 for e in self.edges if not e.authenticated)
        unmon = sum(1 for e in self.edges if not e.monitored)
        shadow = sum(1 for e in self.edges if e.observed)
        return {
            "agents": len(self.nodes_of(KIND_AGENT)),
            "mcp_servers": len(self.nodes_of(KIND_MCP)),
            "tools": len(self.nodes_of(KIND_TOOL)),
            "edges": len(self.edges),
            "unauthenticated_links": unauth,
            "unmonitored_links": unmon,
            "shadow_links": shadow,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "sources": self.sources,
            "summary": self.summary,
            "risk_score": self.risk_score,
            "failed": self.failed,
            "counts": self.counts,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "findings": [f.to_dict() for f in self.findings],
        }


class ConfigError(ValueError):
    """Raised when a config source cannot be parsed."""


# ---------------------------------------------------------------------------
# Source discovery + parsing
# ---------------------------------------------------------------------------

def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc


def parse_env_file(path: str) -> Dict[str, str]:
    """Parse a dotenv-style file into a dict. Tolerant of comments/blanks."""
    out: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k:
                out[k] = v
    return out


def _env_refs(value: Any) -> List[str]:
    """Extract env-var names referenced anywhere inside a JSON value."""
    found: List[str] = []
    if isinstance(value, str):
        for m in _ENV_REF_RE.finditer(value):
            name = next(g for g in m.groups() if g)
            found.append(name)
    elif isinstance(value, dict):
        for v in value.values():
            found.extend(_env_refs(v))
    elif isinstance(value, list):
        for v in value:
            found.extend(_env_refs(v))
    return found


def _looks_authed(blob: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Does this server/edge config carry an auth mechanism?

    Returns (authed, env_refs_used_for_auth).
    """
    env_refs: List[str] = []
    authed = False
    for key, val in blob.items():
        lk = key.lower()
        if lk in (k.lower() for k in _AUTH_KEYS):
            # headers must actually contain an auth header to count
            if lk == "headers" and isinstance(val, dict):
                if any(_AUTH_HEADER_RE.search(str(h)) for h in val):
                    authed = True
                    env_refs.extend(_env_refs(val))
            elif val:
                authed = True
                env_refs.extend(_env_refs(val))
    # env block holding a *_TOKEN / *_KEY also implies auth
    env_block = blob.get("env")
    if isinstance(env_block, dict):
        for k, v in env_block.items():
            if re.search(r"(?i)(token|key|secret|auth|password)", k) and v:
                authed = True
                env_refs.extend(_env_refs(v))
                env_refs.append(k)
    return authed, env_refs


def _looks_monitored(blob: Dict[str, Any]) -> bool:
    for key, val in blob.items():
        if key.lower() in (k.lower() for k in _LOG_KEYS):
            # explicit false disables it
            if val is False:
                return False
            if val:
                return True
    return False


def _transport_of(blob: Dict[str, Any]) -> str:
    if blob.get("command"):
        return "stdio"
    url = blob.get("url") or blob.get("endpoint") or blob.get("baseUrl")
    if url:
        u = str(url).lower()
        if "sse" in u:
            return "sse"
        return "http"
    t = blob.get("transport") or blob.get("type")
    return str(t).lower() if t else ""


def discover_sources(root: str) -> Dict[str, List[str]]:
    """Classify the files under `root` into the source buckets we understand."""
    buckets: Dict[str, List[str]] = {
        "mcp": [], "agents": [], "env": [], "observations": [],
    }
    if os.path.isfile(root):
        files = [root]
        base = os.path.dirname(root) or "."
    else:
        files = []
        base = root
        for dirpath, _dirs, names in os.walk(root):
            for n in names:
                files.append(os.path.join(dirpath, n))

    for path in files:
        name = os.path.basename(path).lower()
        if name in (".env", "agentmap.env") or name.endswith(".env"):
            buckets["env"].append(path)
        elif name in ("connections.json", "observations.json") \
                or name.endswith(".observations.json"):
            buckets["observations"].append(path)
        elif name == "mcp.json" or name.endswith(".mcp.json") \
                or name.endswith("-mcp.json") or "mcpservers" in name:
            buckets["mcp"].append(path)
        elif name in ("agents.json",) or name.endswith(".agent.json") \
                or name.endswith(".agents.json") \
                or (name.endswith(".json") and "agent" in name):
            buckets["agents"].append(path)
        elif name.endswith(".json"):
            # peek to decide
            try:
                data = _read_json(path)
            except (ConfigError, OSError):
                continue
            if isinstance(data, dict) and "mcpServers" in data:
                buckets["mcp"].append(path)
            elif isinstance(data, dict) and "agents" in data:
                buckets["agents"].append(path)
            elif isinstance(data, list) and data \
                    and isinstance(data[0], dict) and "from" in data[0]:
                buckets["observations"].append(path)
    _ = base
    return buckets


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def _ingest_mcp(path: str, data: Any, graph: Graph,
                env: Dict[str, str]) -> None:
    servers = {}
    if isinstance(data, dict):
        servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        raise ConfigError(f"{path}: mcpServers must be an object")

    # A host agent owns every server declared in a client config.
    host_id = "agent:host"
    graph.add_node(Node(host_id, KIND_AGENT, "host (mcp client)",
                        {"implicit": True}))

    for sname, sconf in servers.items():
        if not isinstance(sconf, dict):
            sconf = {}
        sid = f"mcp:{sname}"
        transport = _transport_of(sconf)
        authed, env_refs = _looks_authed(sconf)
        # if auth depends on env vars, they must actually be present
        missing = [r for r in env_refs if r not in env and r not in os.environ]
        effective_auth = authed and not missing
        monitored = _looks_monitored(sconf)
        graph.add_node(Node(sid, KIND_MCP, sname, {
            "transport": transport,
            "command": sconf.get("command"),
            "url": sconf.get("url") or sconf.get("endpoint"),
            # Cache the server's own posture so agent->server links can
            # inherit it when the agent config doesn't override.
            "server_auth": effective_auth,
            "server_monitored": monitored,
        }))

        edge = Edge(host_id, sid, relation="uses",
                    authenticated=effective_auth, monitored=monitored,
                    transport=transport, source=os.path.basename(path),
                    attrs={"declared_auth": authed,
                           "missing_env": missing})
        graph.add_edge(edge)

        # tools the server exposes
        tools = sconf.get("tools")
        if isinstance(tools, list):
            for t in tools:
                tname = t.get("name") if isinstance(t, dict) else str(t)
                if not tname:
                    continue
                tid = f"tool:{sname}.{tname}"
                graph.add_node(Node(tid, KIND_TOOL, tname,
                                    {"server": sname}))
                graph.add_edge(Edge(sid, tid, relation="exposes",
                                    authenticated=effective_auth,
                                    monitored=monitored,
                                    source=os.path.basename(path)))


def _ingest_agents(path: str, data: Any, graph: Graph,
                   env: Dict[str, str]) -> None:
    if isinstance(data, dict):
        agents = data.get("agents", data)
    else:
        agents = data
    if isinstance(agents, dict):
        agents = [dict(v, name=v.get("name", k)) if isinstance(v, dict)
                  else {"name": k} for k, v in agents.items()]
    if not isinstance(agents, list):
        raise ConfigError(f"{path}: expected a list/map of agents")

    for a in agents:
        if not isinstance(a, dict):
            continue
        aname = a.get("name") or a.get("id")
        if not aname:
            continue
        aid = f"agent:{aname}"
        graph.add_node(Node(aid, KIND_AGENT, str(aname), {
            "model": a.get("model"),
            "role": a.get("role"),
        }))

        agent_monitored = _looks_monitored(a)

        # agent -> MCP servers
        uses = a.get("uses") or a.get("servers") or a.get("mcp") or []
        if isinstance(uses, dict):
            uses = [dict(v, name=v.get("name", k)) for k, v in uses.items()]
        if isinstance(uses, str):
            uses = [uses]
        for u in uses:
            if isinstance(u, str):
                target, uconf = u, {}
            elif isinstance(u, dict):
                target = u.get("name") or u.get("server") or u.get("id")
                uconf = u
            else:
                continue
            if not target:
                continue
            sid = f"mcp:{target}"
            server = graph.nodes.get(sid)
            graph.add_node(Node(sid, KIND_MCP, str(target), {}))
            authed, refs = _looks_authed(uconf)
            missing = [r for r in refs if r not in env and r not in os.environ]
            # If the agent doesn't declare its own auth/logging on this link,
            # inherit the server's declared posture (from mcp.json).
            srv_auth = bool(server.attrs.get("server_auth")) if server else False
            srv_mon = bool(server.attrs.get("server_monitored")) if server else False
            link_auth = (authed and not missing) or srv_auth
            link_mon = _looks_monitored(uconf) or agent_monitored or srv_mon
            graph.add_edge(Edge(
                aid, sid, relation="uses",
                authenticated=link_auth,
                monitored=link_mon,
                source=os.path.basename(path),
                attrs={"missing_env": missing},
            ))

        # agent -> agent (A2A)
        peers = a.get("peers") or a.get("talks_to") or a.get("a2a") or []
        if isinstance(peers, str):
            peers = [peers]
        for p in peers:
            if isinstance(p, str):
                target, pconf = p, {}
            elif isinstance(p, dict):
                target = p.get("name") or p.get("id")
                pconf = p
            else:
                continue
            if not target:
                continue
            pid = f"agent:{target}"
            graph.add_node(Node(pid, KIND_AGENT, str(target), {}))
            authed, refs = _looks_authed(pconf)
            missing = [r for r in refs if r not in env and r not in os.environ]
            graph.add_edge(Edge(
                aid, pid, relation="a2a",
                authenticated=authed and not missing,
                monitored=_looks_monitored(pconf) or agent_monitored,
                source=os.path.basename(path),
                attrs={"missing_env": missing},
            ))


def _ingest_observations(path: str, data: Any, graph: Graph) -> None:
    if isinstance(data, dict):
        obs = data.get("connections") or data.get("observations") or []
    else:
        obs = data
    if not isinstance(obs, list):
        raise ConfigError(f"{path}: observations must be a list")

    for o in obs:
        if not isinstance(o, dict):
            continue
        src = o.get("from") or o.get("src") or o.get("source")
        dst = o.get("to") or o.get("dst") or o.get("target")
        if not src or not dst:
            continue
        # Heuristic: a dst that names a known mcp server is an mcp edge.
        src_id = _resolve_observed_id(src, graph, KIND_AGENT)
        # decide dst kind
        if f"mcp:{dst}" in graph.nodes or o.get("kind") == "mcp_server":
            dst_id = f"mcp:{dst}"
            kind = KIND_MCP
            relation = "uses"
        else:
            dst_id = _resolve_observed_id(dst, graph, KIND_AGENT)
            kind = KIND_AGENT
            relation = "a2a"

        if src_id not in graph.nodes:
            graph.add_node(Node(src_id, KIND_AGENT, src,
                                {"observed_only": True}))
        if dst_id not in graph.nodes:
            graph.add_node(Node(dst_id, kind, dst, {"observed_only": True}))

        graph.add_edge(Edge(
            src_id, dst_id, relation=relation,
            authenticated=bool(o.get("authenticated", o.get("auth", False))),
            monitored=bool(o.get("monitored", o.get("logged", False))),
            transport=str(o.get("transport", "")),
            source=os.path.basename(path),
            observed=True,
        ))


def _resolve_observed_id(name: str, graph: Graph, default_kind: str) -> str:
    for prefix in ("agent:", "mcp:", "tool:"):
        if f"{prefix}{name}" in graph.nodes:
            return f"{prefix}{name}"
    return f"agent:{name}" if default_kind == KIND_AGENT else f"mcp:{name}"


# ---------------------------------------------------------------------------
# Rules: flag shadow AI
# ---------------------------------------------------------------------------

def _apply_rules(graph: Graph) -> None:
    findings = graph.findings

    declared_node_ids = {nid for nid, n in graph.nodes.items()
                         if not n.attrs.get("observed_only")}

    for e in graph.edges:
        src = graph.nodes.get(e.src)
        dst = graph.nodes.get(e.dst)
        link = f"{src.label if src else e.src} -> {dst.label if dst else e.dst}"
        loc = e.id

        # Shadow AI: observed edge touching an undeclared endpoint.
        if e.observed:
            undeclared = [nid for nid in (e.src, e.dst)
                          if nid not in declared_node_ids]
            if undeclared:
                names = ", ".join(graph.nodes[n].label for n in undeclared)
                findings.append(Finding(
                    "shadow.undeclared_endpoint", "critical",
                    f"Observed link {link} touches undeclared node(s): "
                    f"{names}. This is shadow AI — traffic to an agent/server "
                    "that appears in no configuration inventory.",
                    loc,
                    "Inventory the endpoint and bring it under managed config, "
                    "or block the connection.",
                ))
            else:
                findings.append(Finding(
                    "shadow.undeclared_link", "high",
                    f"Observed link {link} is not present in any declared "
                    "config — an unsanctioned channel between known nodes.",
                    loc,
                    "Add the link to the declared topology or remove it.",
                ))

        # Unauthenticated link.
        if not e.authenticated and e.relation in ("uses", "a2a"):
            missing = e.attrs.get("missing_env") or []
            if missing:
                findings.append(Finding(
                    "link.auth_env_missing", "high",
                    f"Link {link} declares auth via env var(s) {missing} that "
                    "are absent from the env file — effectively "
                    "UNAUTHENTICATED.",
                    loc,
                    "Provide the credential in the env file / secret store.",
                ))
            else:
                sev = "high" if e.relation == "uses" else "medium"
                findings.append(Finding(
                    "link.unauthenticated", sev,
                    f"Link {link} is UNAUTHENTICATED — any caller reaching it "
                    "can invoke it.",
                    loc,
                    "Require a bearer token / OAuth / mTLS on this channel.",
                ))

        # Unmonitored link (no logging).
        if not e.monitored and e.relation in ("uses", "a2a"):
            findings.append(Finding(
                "link.unmonitored", "medium",
                f"Link {link} is UNMONITORED — calls are not logged or "
                "audited, so misuse would be invisible.",
                loc,
                "Enable request/response logging or route via an audited "
                "gateway (see Cognis agentlog).",
            ))

    # Orphan MCP servers: declared but no agent uses them.
    used_servers = {e.dst for e in graph.edges if e.relation == "uses"}
    for s in graph.nodes_of(KIND_MCP):
        if s.id not in used_servers and not s.attrs.get("observed_only"):
            findings.append(Finding(
                "graph.orphan_server", "low",
                f"MCP server '{s.label}' is declared but no agent references "
                "it — dead capability widening the attack surface.",
                s.id,
                "Remove unused MCP server entries.",
            ))

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_graph(root: str) -> Graph:
    """Discover sources under `root`, build the graph, and apply rules."""
    if not os.path.exists(root):
        raise ConfigError(f"path not found: {root}")
    graph = Graph()
    buckets = discover_sources(root)

    env: Dict[str, str] = {}
    for p in buckets["env"]:
        try:
            env.update(parse_env_file(p))
            graph.sources.append(os.path.basename(p))
        except OSError:
            continue

    for p in buckets["mcp"]:
        data = _read_json(p)
        _ingest_mcp(p, data, graph, env)
        graph.sources.append(os.path.basename(p))

    for p in buckets["agents"]:
        data = _read_json(p)
        _ingest_agents(p, data, graph, env)
        graph.sources.append(os.path.basename(p))

    # observations last, so node inventory is fully populated for shadow checks
    for p in buckets["observations"]:
        data = _read_json(p)
        _ingest_observations(p, data, graph)
        graph.sources.append(os.path.basename(p))

    _apply_rules(graph)
    return graph


def scan(root: str) -> Dict[str, Any]:
    """Suite-standard entrypoint: build the graph and return its dict form."""
    return build_graph(root).to_dict()


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def to_mermaid(graph: Graph) -> str:
    """Render the graph as a Mermaid flowchart; risky links are styled."""
    lines: List[str] = ["flowchart LR"]
    shapes = {KIND_AGENT: ("([", "])"), KIND_MCP: ("[[", "]]"),
              KIND_TOOL: ("(", ")")}

    def nid(node_id: str) -> str:
        return re.sub(r"[^A-Za-z0-9_]", "_", node_id)

    # subgraph by kind for readability
    for kind, title in ((KIND_AGENT, "Agents"), (KIND_MCP, "MCP Servers"),
                        (KIND_TOOL, "Tools")):
        members = graph.nodes_of(kind)
        if not members:
            continue
        lines.append(f"  subgraph {title}")
        for n in members:
            o, c = shapes[kind]
            label = n.label.replace('"', "'")
            if n.attrs.get("observed_only"):
                label = "SHADOW: " + label
            lines.append(f'    {nid(n.id)}{o}"{label}"{c}')
        lines.append("  end")

    danger_edges: List[int] = []
    for i, e in enumerate(graph.edges):
        flags = []
        if not e.authenticated:
            flags.append("no-auth")
        if not e.monitored:
            flags.append("no-log")
        if e.observed:
            flags.append("shadow")
        arrow = "-.->" if e.observed else "-->"
        label = e.relation + (f" [{','.join(flags)}]" if flags else "")
        lines.append(f"  {nid(e.src)} {arrow}|{label}| {nid(e.dst)}")
        if flags:
            danger_edges.append(i)

    for i in danger_edges:
        lines.append(
            f"  linkStyle {i} stroke:#d62728,stroke-width:2px")
    return "\n".join(lines)


_SEV_LABEL = {
    "critical": "CRIT", "high": "HIGH", "medium": "MED ",
    "low": "LOW ", "info": "INFO",
}


def to_table(graph: Graph) -> str:
    s = graph.summary
    lines: List[str] = []
    lines.append(f"agentmap — agent / MCP communication map")
    lines.append("sources: " + (", ".join(graph.sources) or "(none)"))
    lines.append("=" * 72)
    lines.append(
        f"agents={s['agents']}  mcp_servers={s['mcp_servers']}  "
        f"tools={s['tools']}  edges={s['edges']}")
    lines.append(
        f"unauthenticated={s['unauthenticated_links']}  "
        f"unmonitored={s['unmonitored_links']}  shadow={s['shadow_links']}")
    lines.append("-" * 72)
    lines.append("LINKS")
    for e in graph.edges:
        src = graph.nodes.get(e.src)
        dst = graph.nodes.get(e.dst)
        a = "auth" if e.authenticated else "NO-AUTH"
        m = "log" if e.monitored else "NO-LOG"
        sh = " SHADOW" if e.observed else ""
        sl = src.label if src else e.src
        dl = dst.label if dst else e.dst
        lines.append(
            f"  {sl} --{e.relation}--> {dl}  [{a}/{m}{sh}]"
            + (f"  {e.transport}" if e.transport else ""))
    lines.append("-" * 72)
    lines.append("FINDINGS")
    if not graph.findings:
        lines.append("  none — topology is fully authenticated, monitored, "
                     "and declared.")
    for f in graph.findings:
        label = _SEV_LABEL.get(f.severity, f.severity.upper())
        lines.append(f"  [{label}] {f.rule}")
        lines.append(f"          {f.message}")
        if f.remediation:
            lines.append(f"          fix: {f.remediation}")
    c = graph.counts
    lines.append("-" * 72)
    lines.append(
        f"risk_score={graph.risk_score}/100  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']} info={c['info']}")
    lines.append("RESULT: " + ("FLAGGED" if graph.failed else "CLEAN"))
    return "\n".join(lines)


def to_sarif(graph: Graph) -> Dict[str, Any]:
    """Minimal SARIF 2.1.0 doc so findings drop into code-scanning panes."""
    sev_map = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}
    rules_seen: Dict[str, Dict[str, Any]] = {}
    results = []
    for f in graph.findings:
        rules_seen.setdefault(f.rule, {
            "id": f.rule,
            "name": f.rule,
            "shortDescription": {"text": f.rule},
        })
        results.append({
            "ruleId": f.rule,
            "level": sev_map.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "agentmap://graph"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f.location or f.rule}],
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/agentmap",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }
