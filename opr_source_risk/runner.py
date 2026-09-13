from __future__ import annotations

import json
import os
import subprocess
import tomllib
from pathlib import Path
from typing import Any


def load_checks(checks_dir: Path) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if not checks_dir.is_dir():
        return found
    for manifest in sorted(checks_dir.glob("*/manifest.toml")):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        run = manifest.parent / "run"
        if not os.access(run, os.X_OK):
            continue
        data["_dir"] = str(manifest.parent)
        data["_run"] = str(run)
        found.append(data)
    return found


def run_check(
    check: dict[str, Any],
    *,
    root: Path,
    ref: str,
    commit: str,
    pkgname: str,
    files: list[dict],
) -> dict[str, Any]:
    allowed = set(check.get("needs_class") or ["source", "config"])
    if check.get("include_tests"):
        allowed.add("test")
    selected = [f["path"] for f in files if f["class"] in allowed]

    payload = {
        "root": str(root),
        "ref": ref,
        "commit": commit,
        "pkgname": pkgname,
        "files": selected,
    }
    timeout = int(check.get("timeout_sec") or 30)
    try:
        proc = subprocess.run(
            [check["_run"]],
            input=json.dumps(payload).encode(),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"check_id": check["id"], "status": "error", "findings": [], "error": "timeout"}
    if proc.returncode != 0:
        return {
            "check_id": check["id"],
            "status": "error",
            "findings": [],
            "error": proc.stderr.decode(errors="replace")[:2000],
        }
    try:
        out = json.loads(proc.stdout.decode())
    except json.JSONDecodeError:
        return {"check_id": check["id"], "status": "error", "findings": [], "error": "invalid json"}
    out.setdefault("check_id", check["id"])
    out.setdefault("status", "ok")
    out.setdefault("findings", [])
    if not selected and out["status"] == "ok" and not out["findings"]:
        out["status"] = "skipped"
    return out
