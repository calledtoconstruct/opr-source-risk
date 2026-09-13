"""Shared stdin/stdout wrapper for bundled Python checks."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

from opr_source_risk.detect import Finding


def emit_per_file(check_id: str, detect: Callable[[str, str], list[Finding]]) -> None:
    payload = json.load(sys.stdin)
    root = Path(payload["root"])
    findings: list[Finding] = []
    for rel in payload.get("files") or []:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(detect(text, rel))
    json.dump({"check_id": check_id, "status": "ok", "findings": findings}, sys.stdout)


def emit_tree(check_id: str, detect: Callable[[dict[str, str]], list[Finding]]) -> None:
    payload = json.load(sys.stdin)
    root = Path(payload["root"])
    files: dict[str, str] = {}
    for rel in payload.get("files") or []:
        path = root / rel
        try:
            files[rel] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    findings = detect(files)
    json.dump({"check_id": check_id, "status": "ok", "findings": findings}, sys.stdout)
