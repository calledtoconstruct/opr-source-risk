# opr-source-risk

Linux CLI that scans a **git ref** (or a local tree) for *behavioral* risks:
listen-on-all-interfaces, passwordless sudo, secrets in tree, and more.

This is **not** a CVE scanner. OPR’s OSV ingest lives in omarchy-pkgs.
This tool answers: “what does this source at this release appear to *do*?”

Findings are heuristic or config-based. Fail-open by default (`--fail-on never`).

## Scan

```bash
python3 -m opr_source_risk scan --dir /path/to/tree --ref v1.2.3 --pkgname example
python3 -m opr_source_risk scan --git https://github.com/org/app.git --ref v1.2.3
python3 -m opr_source_risk checks list
```

Host CLI: `bin/opr-source-risk` (`scan --dir` / `scan --git`, `checks list`).
Checks are subprocesses; the host does not embed detectors.

Python `bind()` uses the stdlib AST (`confidence: ast`). systemd, nginx, and
Compose ports are parsed as config. Go/C still use regex until a tree-sitter
pack is added. tree-sitter is not a dependency yet.

## Add a check

Drop a directory under `checks/` with `manifest.toml` and an executable `run`
that reads JSON on stdin and writes JSON on stdout. No host change.

See `docs/checks.md` and the plan in the Grok session; LLM refine is a later
pack (`--llm` off by default).

## Tests

```bash
python3 tests/test_scan.py
```
