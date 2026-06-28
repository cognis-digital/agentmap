# agentmap — discover & map agent-to-agent / MCP communications, flag shadow AI

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-agentmap.svg)](https://pypi.org/project/cognis-agentmap/)
[![CI](https://github.com/cognis-digital/agentmap/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/agentmap/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Map the agent-to-agent and agent-to-MCP communication graph and surface "shadow AI".**

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ agentmap-emit --version
agentmap 0.1.0
```

```console
$ agentmap-emit --help
usage: agentmap [-h] [--version] {map} ...

Map agent-to-agent / agent-to-MCP communications and flag shadow AI
(unauthenticated / unmonitored / undeclared links).

positional arguments:
  {map}
    map       Discover config sources under a path and map the graph.

options:
  -h, --help  show this help message and exit
  --version   show program's version number and exit
```

> Blocks above are real `agentmap` output — reproduce them from a clone.

<!-- cognis:example:end -->

## Usage — step by step

1. **Install** the mapper:
   ```bash
   pip install cognis-agentmap
   ```
2. **Map a project** — point `map` at a directory (or single file) holding `mcp.json`, agent configs, `.env`, or `observations.json`. It discovers config sources and builds the communication graph:
   ```bash
   agentmap map demos/01-basic
   ```
3. **Filter findings** by severity while you triage. `--min-severity` controls what is reported:
   ```bash
   agentmap map demos/01-basic --min-severity low
   ```
4. **Read the output** in the format you need. `--format` accepts `table` (default), `json`, `mermaid`, or `sarif`; `--out` writes to a file:
   ```bash
   agentmap map demos/01-basic --format mermaid --out graph.mmd   # paste into any Mermaid renderer
   agentmap map demos/01-basic --format json --out graph.json
   ```
5. **Automate in CI** — `--fail-on` exits non-zero when a finding at or above the threshold appears (default `high`):
   ```yaml
   - run: pip install cognis-agentmap
   - run: agentmap map . --format sarif --out agentmap.sarif --fail-on high
   ```

## Why

LLM agents quietly accumulate MCP servers, peer agents, and tools. Most of
those links are configured ad-hoc: some are authenticated, many are not, and
almost none are logged. `agentmap` reads the config you already have on disk —
`mcp.json`, agent config files, your `.env`, and (optionally) an observations
capture — normalizes them into one typed graph of **agents ↔ MCP servers ↔
tools**, then flags every link that is **unauthenticated**, **unmonitored**, or
**undeclared** (shadow AI). Stdlib only, scriptable, CI-friendly, self-hostable.

## Install

```bash
pip install cognis-agentmap
# or, from this repo:
pip install -e ".[dev]"
```

## Quick start

```bash
agentmap --version
agentmap map demos/01-basic                      # human-readable map + findings
agentmap map demos/01-basic --format json        # machine-readable graph
agentmap map demos/01-basic --format mermaid      # paste into any Mermaid renderer
agentmap map demos/01-basic --format sarif --out r.sarif
agentmap map demos/01-basic --fail-on high        # CI gate on high+ findings
python -m agentmap.mcp_server                      # expose as an MCP server
```

## What it reads

| Source | Pattern | Contributes |
|--------|---------|-------------|
| MCP client config | `mcp.json`, `*.mcp.json`, `*-mcp.json`, any JSON with `mcpServers` | MCP-server + tool nodes, host→server edges |
| Agent config | `agents.json`, `*.agent.json`, JSON with `agents` | agent nodes, agent→server (`uses`) + agent→agent (`a2a`) edges |
| Env file | `.env`, `*.env` | credential presence; a server whose auth depends on a **missing** env var is treated as unauthenticated |
| Observations | `connections.json` / `observations.json` | empirically observed edges; any endpoint not in the declared inventory = **shadow AI** |

## What it flags

- `link.unauthenticated` — a link no credential protects.
- `link.auth_env_missing` — auth references an env var that is absent → effectively unauthenticated.
- `link.unmonitored` — no logging/audit on the link; misuse would be invisible.
- `shadow.undeclared_endpoint` (critical) — observed traffic to an agent/server in **no** config inventory.
- `shadow.undeclared_link` — an observed channel between known nodes that nothing declared.
- `graph.orphan_server` — a declared MCP server nothing references.

## Output formats

- **Table** (default) — human-readable terminal summary of nodes, links, and findings.
- **JSON** — full graph (`nodes`, `edges`, `findings`, `summary`, `risk_score`).
- **Mermaid** — a flowchart with risky links styled red.
- **SARIF** — drops into GitHub code-scanning / IDE problem panes.

## Built-in demo scenario

[`demos/01-basic/`](demos/01-basic/SCENARIO.md) — a mixed estate (3 MCP servers,
2 agents, an `.env`, and a telemetry capture). It maps cleanly except for one
**unauthenticated** MCP server (`weather`) and a **shadow** agent
(`rogue-scraper`) seen in observations but declared nowhere.

## How it fits the Cognis Neural Suite

`agentmap` is one tool in the [Cognis Neural Suite](https://github.com/cognis-digital).
Every tool ships an MCP server, so [Cognis.Studio](https://cognis.studio) agents
can call them as scoped capabilities.

**Sibling tools in `ai-security`:** [`mcpharden`](https://github.com/cognis-digital/mcpharden), [`agentlog`](https://github.com/cognis-digital/agentlog), [`guardpost`](https://github.com/cognis-digital/guardpost), [`aegis`](https://github.com/cognis-digital/aegis), [`promptmirror`](https://github.com/cognis-digital/promptmirror)

## Contributing

PRs, new detections, and demo scenarios are welcome under the collaboration-pull model. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Interoperability

`agentmap` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `agentmap`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
