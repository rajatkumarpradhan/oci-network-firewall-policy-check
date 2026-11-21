# oci-network-firewall-policy-check

**Category: custom portfolio tool.** The OOTB built-in-services project in this pair is
`oci-ootb-functions-config-check`.

## The problem

An OCI Network Firewall only inspects what its **policy** says. Per the OCI docs: rules are
evaluated top to bottom and the first match wins, an empty match condition means **any**,
and a policy with no rules makes the attached firewall **deny all traffic**. A policy can
therefore look "deployed" while it passes everything through, blocks everything, or runs
intrusion prevention with no logging to show for it. This tool audits an offline JSON
export of policies and flags the gaps worth a human review.

## The rules

| Rule | Severity | Fires when |
| ---- | -------- | ---------- |
| NFW001 | HIGH | An `ALLOW` rule matches **any source to any destination** (empty criteria = "any" per the docs) - for that traffic the firewall is a pass-through. Review flag: broad allow rules can be intentional; confirm. |
| NFW002 | MEDIUM | A policy contains **zero security rules** - per the docs a firewall using it denies all traffic, which is rarely the intent. |
| NFW003 | MEDIUM | A policy has **intrusion detection/prevention rules but no logging recorded** - the docs state IDPS requires logging, so alerts/blocks would leave no trail as far as the export records. |
| NFW004 | LOW | A policy is **referenced by no firewall** in the export - defined but unused as recorded. |

Exit code: `2` on any HIGH, `1` on MEDIUM/LOW only, `0` when clean.

## Run it

```bash
python -m nfw_check.cli samples/policies_messy.json   # exits 2, all 4 rules fire
python -m nfw_check.cli samples/policies_clean.json   # exits 0
python -m unittest discover -s tests -v               # 17 tests, stdlib only
```

## Honest limits

- **Offline audit**: the JSON export is synthetic; nothing calls the OCI API.
- Findings describe what the export records and are review prompts, not verdicts - an
  any-any ALLOW can be a deliberate design; NFW004 says nothing about firewalls missing
  from the export.
- Rule semantics (first match wins, empty = any, no rules = deny all, IDPS requires
  logging) are from the OCI Network Firewall docs as of Nov 2026; verify current behavior
  before acting.
- Rule ordering interplay (a broad allow shadowing later rules) is out of scope.
- No live tenancy was touched.

## Project status

Built as a daily portfolio project. 17 unit tests, green locally and in CI. Free tier only;
no live cloud calls, no spend.
