#!/usr/bin/env python3
"""Audit Kubernetes RBAC manifests for over-privileged grants.

Usage:
    python3 run.py <manifest.yaml> [more.yaml ...] [--json]

Exit codes: 2 = usage error / unreadable manifest,
            1 = at least one high or critical finding,
            0 = no high or critical findings.
"""

import argparse
import sys

from rbac.loader import load_manifests
from rbac.checks import check_manifests
from rbac.bindings import check_effective
from rbac.report import summarize, render_text, render_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifests", nargs="+",
                        help="RBAC manifest YAML file(s)")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    args = parser.parse_args(argv)

    all_findings = []
    all_docs = []
    for path in args.manifests:
        try:
            docs = load_manifests(path)
        except (OSError, ValueError) as exc:
            print(f"error: cannot load {path}: {exc}", file=sys.stderr)
            return 2
        all_docs.extend(docs)
        all_findings.extend(check_manifests(docs))
    all_findings.extend(check_effective(all_docs))

    source = ", ".join(args.manifests)
    if args.json:
        print(render_json(source, all_findings))
    else:
        print(render_text(source, all_findings))

    counts = summarize(all_findings)
    return 1 if (counts["CRITICAL"] or counts["HIGH"]) else 0


if __name__ == "__main__":
    sys.exit(main())
