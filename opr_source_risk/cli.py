from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from opr_source_risk.scan import checkout_git, scan_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="opr-source-risk",
        description="Scan a git ref for behavioral risks (listen, privilege, secrets). Not a CVE scanner.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a tree or git ref")
    scan.add_argument("--dir", type=Path, dest="dir")
    scan.add_argument("--git")
    scan.add_argument("--ref", default="HEAD")
    scan.add_argument("--pkgname", default="")
    scan.add_argument("--out", type=Path)
    scan.add_argument("--checks-dir", type=Path)
    scan.add_argument("--fail-on", choices=["never", "high", "medium", "low"], default="never")

    listed = sub.add_parser("checks", help="list bundled checks")
    listed.add_argument("checks_cmd", nargs="?", default="list")
    listed.add_argument("--checks-dir", type=Path)

    args = parser.parse_args(argv)
    if args.cmd == "checks":
        from opr_source_risk.runner import load_checks
        from opr_source_risk.scan import DEFAULT_CHECKS

        for c in load_checks(args.checks_dir or DEFAULT_CHECKS):
            print(f"{c['id']}\t{c.get('facet', '')}\t{c.get('summary', '')}")
        return 0

    if bool(args.dir) == bool(args.git):
        parser.error("scan requires exactly one of --dir or --git")

    if args.git:
        tmp = Path(tempfile.mkdtemp(prefix="opr-source-risk-"))
        checkout_git(args.git, args.ref, tmp)
        root = tmp
        source = args.git
    else:
        root = args.dir
        source = ""

    report = scan_dir(
        root,
        ref=args.ref,
        pkgname=args.pkgname,
        checks_dir=args.checks_dir,
        source=source,
    )
    text = json.dumps(report, indent=2) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    if args.fail_on != "never":
        order = {"low": 1, "medium": 2, "high": 3}
        threshold = order[args.fail_on]
        for f in report["findings"]:
            if order.get(f.get("severity", "info"), 0) >= threshold:
                return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
