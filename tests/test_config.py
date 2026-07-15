import unittest

from wafd.config import Configuration


class ConfigurationTests(unittest.TestCase):
    def test_round_trip(self):
        original = Configuration(.75, False, 8, False, "selected")
        restored = Configuration.from_json(original.to_json())
        self.assertEqual(restored.threshold, .75)
        self.assertFalse(restored.in_scope_only)
        self.assertEqual(restored.max_probes, 8)
        self.assertFalse(restored.enabled)
        self.assertEqual(restored.non_get_target, "selected")

    def test_bounds_are_enforced(self):
        with self.assertRaises(ValueError):
            Configuration(1.1)
        self.assertEqual(Configuration(max_probes=100).max_probes, 20)

    def test_non_get_target_is_restricted(self):
        with self.assertRaises(ValueError):
            Configuration(non_get_target="arbitrary")


if __name__ == "__main__":
    unittest.main()
