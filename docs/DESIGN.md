# Design (v1)

Deterministic Linux CLI. Checks are executables + `manifest.toml` so a new
risk does not require a host refactor.

v1 techniques: Python stdlib AST for `bind()`, systemd/nginx/Compose
parsers (`confidence: config`), regex for Go/C. tree-sitter and
optional LLM refine (`confidence: llm`, evidence must be a substring of the
file) are later packs. LLM is off by default; never the only detector.

Not in this repo: OSV/CVE ingest (omarchy-pkgs), pacman transaction rollup,
runtime nmap.

Default fail-open. `--fail-on high` for CI that wants a gate.
