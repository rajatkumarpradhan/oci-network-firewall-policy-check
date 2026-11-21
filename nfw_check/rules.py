"""NFW001-NFW004 rules."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # HIGH | MEDIUM | LOW
    policy: str
    detail: str


def rule_any_any_allow(policies: tuple, firewalls: tuple) -> list:
    """NFW001 HIGH: ALLOW rule matching any source to any destination."""
    del firewalls
    out = []
    for p in policies:
        for r in p.rules:
            if r.action == "ALLOW" and r.is_any_any():
                out.append(
                    Finding("NFW001", "HIGH", p.name,
                            f"rule {r.name!r} allows any source to any destination (empty criteria match "
                            f"'any' per OCI docs); for that traffic the firewall is a pass-through - "
                            f"confirm this broad allow is intended")
                )
    return out


def rule_no_rules(policies: tuple, firewalls: tuple) -> list:
    """NFW002 MEDIUM: policy with zero security rules (firewall denies all)."""
    del firewalls
    return [
        Finding("NFW002", "MEDIUM", p.name,
                "policy has zero security rules; per OCI docs a firewall using it denies all traffic - "
                "rarely the intent")
        for p in policies if not p.rules
    ]


def rule_idps_without_logging(policies: tuple, firewalls: tuple) -> list:
    """NFW003 MEDIUM: IDPS rules present but logging not recorded."""
    del firewalls
    return [
        Finding("NFW003", "MEDIUM", p.name,
                "policy has intrusion detection/prevention rule(s) but logging is not recorded; per OCI "
                "docs IDPS requires logging, so alerts/blocks leave no trail as far as this export records")
        for p in policies if any(r.action == "IDPS" for r in p.rules) and not p.logging
    ]


def rule_unreferenced(policies: tuple, firewalls: tuple) -> list:
    """NFW004 LOW: policy referenced by no firewall in the export."""
    referenced = set(firewalls)
    return [
        Finding("NFW004", "LOW", p.name,
                "no firewall in this export references the policy; defined but unused as recorded")
        for p in policies if p.name not in referenced
    ]


ALL_RULES = (
    rule_any_any_allow,
    rule_no_rules,
    rule_idps_without_logging,
    rule_unreferenced,
)

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all(policies: tuple, firewalls: tuple) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(policies, firewalls))
    findings.sort(key=lambda x: (_SEVERITY_RANK[x.severity], x.rule, x.policy))
    return findings


def exit_code(findings: list) -> int:
    if any(f.severity == "HIGH" for f in findings):
        return 2
    if findings:
        return 1
    return 0
