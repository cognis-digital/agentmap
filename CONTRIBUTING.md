# Contributing to agentmap

Thanks for helping improve agentmap, part of the Cognis Neural Suite.

## Collaboration-pull model

By submitting a contribution you agree to the inbound = outbound terms in the
[Cognis Open Collaboration License (COCL) v1.0](LICENSE), including the
relicensing grant in Section 4. This is what enables the dual-licensing model.

## Dev setup

```bash
pip install -e ".[dev]"
python -m unittest discover -s tests -q   # or: python -m pytest -q
python -m agentmap map demos/01-basic
```

The tool is **standard library only** — no third-party runtime dependencies.
Please keep it that way; a PR that adds a runtime dependency will be asked to
remove it.

## What makes a good PR

- A new detection rule should come with a test in `tests/test_deep.py` and, where
  it helps, a demo scenario under `demos/`.
- New config-source parsers must be tolerant of malformed input (raise
  `ConfigError`, never crash).
- Keep findings actionable: every `Finding` needs a clear `message` and a
  concrete `remediation`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.
