# agentmap — discover & map agent-to-agent / MCP communications, flag shadow AI

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![install](https://img.shields.io/badge/install-git%2B%20%C2%B7%20pipx%20%C2%B7%20uv-6b46c1.svg)](#install--every-way-every-platform)
[![CI](https://github.com/cognis-digital/agentmap/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/agentmap/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**Map the agent-to-agent and agent-to-MCP communication graph and surface "shadow AI".**

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

<!-- cognis:layman:start -->
## What is this?

agentmap is a command-line tool that reads the configuration files on your computer — the same files that tell AI assistants which tools and services they are allowed to connect to — and draws you a map of every connection. It then flags any connection that is unprotected (no password or token required) or hidden (an AI is talking to something that was never officially set up), which are the kinds of gaps that could let a bad actor slip in unnoticed. It is built for security teams, developers, and IT administrators who want to see exactly what their AI systems are doing and catch "shadow AI" before it becomes a problem. The tool runs entirely on your own machine with no account or internet connection required.
<!-- cognis:layman:end -->

## Why

LLM agents quietly accumulate MCP servers, peer agents, and tools. Most of
those links are configured ad-hoc: some are authenticated, many are not, and
almost none are logged. `agentmap` reads the config you already have on disk —
`mcp.json`, agent config files, your `.env`, and (optionally) an observations
capture — normalizes them into one typed graph of **agents ↔ MCP servers ↔
tools**, then flags every link that is **unauthenticated**, **unmonitored**, or
**undeclared** (shadow AI). Stdlib only, scriptable, CI-friendly, self-hostable.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** AI & ML  ·  **JTF MERIDIAN division:** ATHENA-PRIME · SAGE

**Topics:** `cognis` `ai` `llm` `machine-learning` `mcp` `agent-security`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

<!-- cognis:install:start -->
## Install

`agentmap` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/agentmap/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/agentmap/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/agentmap.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/agentmap.git"  # uv
pip install "git+https://github.com/cognis-digital/agentmap.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/agentmap.git
cd agentmap && pip install .
```

Then run:
```sh
agentmap --help
```
<!-- cognis:install:end -->

## Install

```bash
pip install "git+https://github.com/cognis-digital/agentmap.git"
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

<a name="verification"></a>
## Verification

[![tests](https://img.shields.io/badge/tests-22%20passing-2ea44f.svg)](AUDIT.md)

Every push is verified end-to-end. Latest audit (2026-06-13):

```text
tests        : 22 passed, 0 failed, 0 errored
compile      : all modules parse
cli          : C:\Python314\python.exe: No module named https
package      : https
```

<details><summary>CLI surface (<code>--help</code>)</summary>

```text
C:\Python314\python.exe: No module named https
```
</details>

Full machine-readable results: [`AUDIT.md`](AUDIT.md) · regenerate with `python -m https --help` + `pytest -q`.

<div align="right"><a href="#top">↑ back to top</a></div>


## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and identities you own or are explicitly authorized in writing to test, and in compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
