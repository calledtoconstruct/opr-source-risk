# Guiding principles: calledtoconstruct/opr-source-risk

## Purpose and scope
A Linux CLI that scans a git ref or local tree for behavioral risks (listening on all interfaces, passwordless sudo, secrets and similar). Not a CVE scanner.

## Stack and layout
Python package `opr_source_risk/`, host CLI `bin/opr-source-risk`, pluggable checks under `checks/` (each with `manifest.toml` and an executable `run` speaking JSON on stdin/stdout), fixtures in `testdata/`, tests in `tests/test_scan.py`, docs in `docs/`.

## Commands
| Check | Command | Evidence |
|---|---|---|
| Run | `python3 -m opr_source_risk scan --dir <tree> --ref <ref>`; `python3 -m opr_source_risk checks list` | README.md |
| Build / type-check | None configured | - |
| Tests | `python3 tests/test_scan.py` | README.md |
| CI | None | repository tree |

Commands marked as not written down come from the build files, not from project docs; confirm them before relying on them.

## Before every push
Before every push: run the build and type-check/lint that exist here, plus only the tests for the files or feature you changed (team rule, ideas #14 note 6797). Do not run the full suite locally as a routine gate; this repository has no CI that runs the full suite, so run the full suite only when the change is broad, and say in the PR that CI coverage is missing. Merge needs a positive review. Explain any new failure your change caused. Never weaken a valid test to make it pass, and never invent a command this file does not list.

## Project rules
- New detectors are new folders under `checks/`; the host does not embed detectors and needs no change to add one.
- Every check gets a fixture under `testdata/` that it should flag, and the clean fixture must stay clean.
- Findings are heuristic and fail-open by default (`--fail-on never`); do not change that default silently.
- LLM refinement stays off by default (`--llm`).

## What to avoid
- Committing to the default branch; work on a branch and open a pull request.
- Deleting files, branches or history, or changing repository settings.
- Adding tooling, CI or dependencies that the change does not need.
- Rules copied from other projects (file-size limits, clocks, quotas) that this repository never adopted.

## Delivery and safety
- No release automation.

## Open questions
- No CI; `tests/test_scan.py` is the only suite and runs locally.

## Sources
Read from the `master` branch on 2026-11-08 ET: `README.md`, `docs/checks.md`, repository tree.

## Instruction updates
Check `guiding-principles.version` at the start of each turn and when you enter this project; reload this file when the version changes. Change this file, its version and date, and `PRINCIPLES_HISTORY.md` in the same commit. Team-wide role instructions are versioned separately in the team-process repository.
