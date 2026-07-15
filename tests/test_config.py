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
        self.assertEqual(Configuration(max_probes=5000).max_probes, 1000)

    def test_active_probes_are_unlimited_by_default(self):
        self.assertIsNone(Configuration().max_probes)
        self.assertIsNone(Configuration.from_json(Configuration().to_json()).max_probes)

    def test_non_get_target_is_restricted(self):
        with self.assertRaises(ValueError):
            Configuration(non_get_target="arbitrary")

    def test_size_thresholds_round_trip_and_are_bounded(self):
        original = Configuration(body_test_threshold=4096, header_test_threshold=2048,
                                 header_count_test_threshold=32, inspection_boundary=3072,
                                 size_hard_max=16384)
        restored = Configuration.from_json(original.to_json())
        self.assertEqual(restored.body_test_threshold, 4096)
        self.assertEqual(restored.header_count_test_threshold, 32)
        self.assertEqual(restored.inspection_boundary, 3072)
        with self.assertRaises(ValueError):
            Configuration(body_test_threshold=20000, size_hard_max=10000)
        with self.assertRaises(ValueError):
            Configuration(inspection_boundary=10000, size_hard_max=10000)


if __name__ == "__main__":
    unittest.main()
