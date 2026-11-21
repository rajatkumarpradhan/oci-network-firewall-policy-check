"""Data model + export loading for the network firewall policy audit."""

from __future__ import annotations

import json
from dataclasses import dataclass


class ExportError(ValueError):
    """Raised when an export file is malformed."""


ACTIONS = ("ALLOW", "DROP", "REJECT", "IDPS")
ANY_TOKENS = ("any", "0.0.0.0/0", "::/0")


def is_any(addresses: tuple) -> bool:
    """Empty criteria means 'any' per the OCI docs; explicit wildcards count too."""
    if not addresses:
        return True
    return any(a.strip().lower() in ANY_TOKENS for a in addresses)


@dataclass(frozen=True)
class Rule:
    name: str
    action: str          # ALLOW | DROP | REJECT | IDPS
    source: tuple = ()
    destination: tuple = ()

    def is_any_any(self) -> bool:
        return is_any(self.source) and is_any(self.destination)


@dataclass(frozen=True)
class Policy:
    name: str
    logging: bool
    rules: tuple = ()
    description: str = ""


def load_export(path: str) -> tuple:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ExportError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("policies"), list):
        raise ExportError(f"{path}: top level must be an object with a 'policies' list")
    policies = []
    for i, p in enumerate(raw["policies"]):
        where = f"policies[{i}]"
        if "name" not in p:
            raise ExportError(f"{where}: missing required field 'name'")
        rules = []
        for j, r in enumerate(p.get("rules", [])):
            rwhere = f"{where}.rules[{j}]"
            for req in ("name", "action"):
                if req not in r:
                    raise ExportError(f"{rwhere}: missing required field {req!r}")
            action = r["action"].upper()
            if action not in ACTIONS:
                raise ExportError(f"{rwhere}.action: unknown action {r['action']!r} (expected one of {ACTIONS})")
            rules.append(Rule(
                name=r["name"],
                action=action,
                source=tuple(r.get("source", [])),
                destination=tuple(r.get("destination", [])),
            ))
        policies.append(Policy(
            name=p["name"],
            logging=bool(p.get("logging", False)),
            rules=tuple(rules),
            description=p.get("description", "") or "",
        ))
    firewalls = []
    for k, f in enumerate(raw.get("firewalls", [])):
        fwhere = f"firewalls[{k}]"
        if "policy" not in f:
            raise ExportError(f"{fwhere}: missing required field 'policy'")
        firewalls.append(f["policy"])
    return tuple(policies), tuple(firewalls)
