from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from opr_source_risk import __version__
from opr_source_risk.classify import inventory
from opr_source_risk.runner import load_checks, run_check

DEFAULT_CHECKS = Path(__file__).resolve().parent.parent / "checks"


def _git_commit(root: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except OSError:
        pass
    return ""


def scan_dir(
    root: Path,
    *,
    ref: str,
    pkgname: str = "",
    checks_dir: Path | None = None,
    source: str = "",
) -> dict[str, Any]:
    root = root.resolve()
    files = inventory(root)
    checks = load_checks(checks_dir or DEFAULT_CHECKS)
    findings: list[dict] = []
    checks_run: list[dict] = []
    seen: set[tuple] = set()
    commit = _git_commit(root)
    for check in checks:
        result = run_check(
            check, root=root, ref=ref, commit=commit, pkgname=pkgname, files=files
        )
        checks_run.append(
            {
                "id": result.get("check_id", check.get("id")),
                "status": result.get("status", "error"),
            }
        )
        for finding in result.get("findings") or []:
            finding.setdefault("facet", check.get("facet") or check.get("id"))
            key = (
                finding.get("facet"),
                finding.get("path"),
                finding.get("line"),
                finding.get("evidence"),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return {
        "schema": 1,
        "pkgname": pkgname,
        "source": source,
        "ref": ref,
        "commit": commit,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scanner": f"opr-source-risk/{__version__}",
        "findings": findings,
        "checks_run": checks_run,
    }


def checkout_git(url: str, ref: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet", str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", url], check=True)
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth=1", "--quiet", "origin", ref],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "--quiet", "FETCH_HEAD"],
        check=True,
    )
