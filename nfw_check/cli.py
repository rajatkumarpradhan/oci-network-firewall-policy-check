"""python -m nfw_check.cli EXPORT"""

from __future__ import annotations

import argparse
import sys

from .model import ExportError, load_export
from .rules import exit_code, run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="network-firewall-policy-check",
        description="Audit an offline export of OCI Network Firewall policies for pass-through and hygiene gaps.",
    )
    p.add_argument("export", help="path to the JSON export")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policies, firewalls = load_export(args.export)
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = run_all(policies, firewalls)
    n_rules = sum(len(p.rules) for p in policies)
    print(
        f"Network firewall policy audit - {len(policies)} policy(ies), {len(firewalls)} firewall(s), "
        f"{n_rules} rule(s), {len(findings)} finding(s)"
    )
    for x in findings:
        print(f"[{x.severity:6s}] {x.rule} policy={x.policy}")
        print(f"         {x.detail}")
    code = exit_code(findings)
    print({0: "RESULT: clean", 1: "RESULT: warnings only", 2: "RESULT: HIGH findings present"}[code])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
