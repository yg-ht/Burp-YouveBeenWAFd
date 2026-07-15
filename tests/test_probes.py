import unittest

from wafd.probes import ProbePlanner


class ProbePlannerTests(unittest.TestCase):
    def test_safe_methods_are_bounded(self):
        probes = ProbePlanner(3).plan("GET", "query")
        self.assertEqual(len(probes), 3)
        self.assertIn("<script>alert(1)</script>", probes)
        self.assertIn("' OR '1'='1", probes)

    def test_non_idempotent_methods_are_disabled_by_default(self):
        self.assertEqual(ProbePlanner().plan("POST", "query"), [])

    def test_sensitive_insertion_points_are_skipped(self):
        self.assertEqual(ProbePlanner().plan("GET", "Cookie"), [])


if __name__ == "__main__":
    unittest.main()
