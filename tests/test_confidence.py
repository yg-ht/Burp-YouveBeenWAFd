import unittest

from wafd.confidence import ConfidenceEngine
from wafd.models import Evidence, Rule


class ConfidenceTests(unittest.TestCase):
    def setUp(self):
        self.rules = [
            Rule("a", "A", "headers", 30),
            Rule("b", "B", "status", 30),
            Rule("c", "C", "body", 40),
        ]

    def test_independent_groups_are_weighted(self):
        engine = ConfidenceEngine(self.rules)
        score, products = engine.score([Evidence("a", "https://x", "header")])
        self.assertAlmostEqual(score, 0.3)
        self.assertEqual(products, {})

    def test_same_group_is_counted_once(self):
        engine = ConfidenceEngine(self.rules + [Rule("a2", "A2", "headers", 20)])
        score, _ = engine.score([Evidence("a", "https://x", "one"), Evidence("a2", "https://x", "two")])
        self.assertAlmostEqual(score, 0.3)

    def test_threshold_is_inclusive(self):
        engine = ConfidenceEngine(self.rules)
        self.assertTrue(engine.has_waf([Evidence("a", "https://x", "a"), Evidence("b", "https://x", "b")]))

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            ConfidenceEngine(self.rules, 1.1)


if __name__ == "__main__":
    unittest.main()
