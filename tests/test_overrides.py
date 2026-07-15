import unittest

from wafd.models import Rule
from wafd.overrides import CatalogueOverrides
from wafd.probes import Probe


class CatalogueOverrideTests(unittest.TestCase):
    def test_capture_round_trip_and_apply(self):
        rules = [Rule("one", "One", "g1", 1, enabled=False),
                 Rule("two", "Two", "g2", 1, enabled=True)]
        probes = [Probe("x", [], [], "probe", "Probe", enabled=False)]
        restored = CatalogueOverrides.from_json(
            CatalogueOverrides.capture(rules, probes).to_json())

        fresh_rules = [Rule("one", "One", "g1", 1), Rule("two", "Two", "g2", 1)]
        fresh_probes = [Probe("x", [], [], "probe", "Probe")]
        restored.apply(fresh_rules, fresh_probes)

        self.assertFalse(fresh_rules[0].enabled)
        self.assertTrue(fresh_rules[1].enabled)
        self.assertFalse(fresh_probes[0].enabled)

    def test_unknown_ids_are_ignored(self):
        overrides = CatalogueOverrides({"removed-rule": False}, {"removed-probe": False})
        rule = Rule("current", "Current", "g", 1)
        probe = Probe("x", [], [], "current", "Current")
        overrides.apply([rule], [probe])
        self.assertTrue(rule.enabled)
        self.assertTrue(probe.enabled)

    def test_invalid_schema_and_non_boolean_values_are_rejected(self):
        with self.assertRaises(ValueError):
            CatalogueOverrides.from_json('{"schema_version":2,"rules":{},"probes":{}}')
        with self.assertRaises(ValueError):
            CatalogueOverrides.from_json(
                '{"schema_version":1,"rules":{"rule":"false"},"probes":{}}')


if __name__ == "__main__":
    unittest.main()
