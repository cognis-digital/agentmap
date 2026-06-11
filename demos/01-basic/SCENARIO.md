# Demo 01 — Mapping a mixed agent / MCP estate and catching shadow AI

This scenario points `agentmap` at a directory holding a realistic but
deliberately leaky set of config sources:

| File                | What it declares                                            |
|---------------------|-------------------------------------------------------------|
| `mcp.json`          | 3 MCP servers: `github`, `weather`, `internal-notes`        |
| `agents.json`       | 2 agents (`planner`, `researcher`), their A2A + MCP links   |
| `.env`              | The credentials the configs reference                       |
| `observations.json` | Empirically observed connections (telemetry capture)        |

## Run it

```bash
python -m agentmap map demos/01-basic
# machine-readable graph:
python -m agentmap map demos/01-basic --format json
# the diagram (paste into any Mermaid renderer):
python -m agentmap map demos/01-basic --format mermaid
# CI gate on high+ findings:
python -m agentmap map demos/01-basic --fail-on high
```

## What it should catch

- **One UNAUTHENTICATED link** — `researcher --uses--> weather`. The `weather`
  MCP server declares no `auth`/`token`/`headers` at all, while `github`
  (env `GITHUB_TOKEN`) and `internal-notes` (bearer `NOTES_TOKEN`) resolve as
  authenticated because those env vars are present in `.env`.
  Rule: `link.unauthenticated`.

- **Shadow AI** — the observations show `rogue-scraper --uses--> weather`, but
  `rogue-scraper` appears in *no* declared config. It is surfaced as an
  undeclared endpoint (`shadow.undeclared_endpoint`, critical).

- **Unmonitored links** — any link without logging is flagged
  (`link.unmonitored`).

Because critical/high findings are present, the process exits non-zero,
failing any CI gate that wraps it.
