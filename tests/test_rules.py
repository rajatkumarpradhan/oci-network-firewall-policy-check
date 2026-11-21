import unittest

from nfw_check.model import Policy, Rule
from nfw_check.rules import (
    exit_code,
    rule_any_any_allow,
    rule_idps_without_logging,
    rule_no_rules,
    rule_unreferenced,
    run_all,
)


def rule(name="r", action="ALLOW", source=("10.0.0.0/16",), destination=("10.1.0.0/16",)):
    return Rule(name=name, action=action, source=tuple(source), destination=tuple(destination))


def policy(name="p", logging=True, rules=(rule(),), description="d"):
    return Policy(name=name, logging=logging, rules=tuple(rules), description=description)


class TestNfw001(unittest.TestCase):
    def test_fires_empty_criteria(self):
        out = rule_any_any_allow((policy(rules=(rule(source=(), destination=()),)),), ())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "HIGH")

    def test_fires_explicit_wildcard(self):
        out = rule_any_any_allow((policy(rules=(rule(source=("0.0.0.0/0",), destination=("any",)),)),), ())
        self.assertEqual(len(out), 1)

    def test_quiet_scoped_allow(self):
        self.assertEqual(rule_any_any_allow((policy(),), ()), [])

    def test_quiet_drop_any_any(self):
        self.assertEqual(rule_any_any_allow((policy(rules=(rule(action="DROP", source=(), destination=()),)),), ()), [])


class TestNfw002(unittest.TestCase):
    def test_fires_no_rules(self):
        out = rule_no_rules((policy(rules=()),), ())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "MEDIUM")

    def test_quiet_with_rules(self):
        self.assertEqual(rule_no_rules((policy(),), ()), [])


class TestNfw003(unittest.TestCase):
    def test_fires_idps_no_logging(self):
        out = rule_idps_without_logging((policy(logging=False, rules=(rule(action="IDPS"),)),), ())
        self.assertEqual(len(out), 1)

    def test_quiet_idps_with_logging(self):
        self.assertEqual(rule_idps_without_logging((policy(rules=(rule(action="IDPS"),)),), ()), [])

    def test_quiet_allow_no_logging(self):
        self.assertEqual(rule_idps_without_logging((policy(logging=False),), ()), [])


class TestNfw004(unittest.TestCase):
    def test_fires_unreferenced(self):
        out = rule_unreferenced((policy(name="lonely"),), ())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "LOW")

    def test_quiet_referenced(self):
        self.assertEqual(rule_unreferenced((policy(name="used"),), ("used",)), [])


class TestAggregation(unittest.TestCase):
    def test_exit_2_on_high(self):
        self.assertEqual(exit_code(run_all((policy(rules=(rule(source=(), destination=()),)),), ())), 2)

    def test_exit_1_medium_only(self):
        self.assertEqual(exit_code(run_all((policy(rules=(), name="x"),), ("x",))), 1)

    def test_exit_0_clean(self):
        self.assertEqual(exit_code(run_all((policy(name="x"),), ("x",))), 0)


if __name__ == "__main__":
    unittest.main()
