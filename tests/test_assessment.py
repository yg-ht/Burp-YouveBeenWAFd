import unittest

from wafd.assessment import AssessmentStore
from wafd.models import Evidence, Rule


class AssessmentTests(unittest.TestCase):
    def test_default_detail_is_present_before_evidence(self):
        store = AssessmentStore([Rule("r", "Rule", "g", 10)])
        detail = store.detail("https://example.test:443")
        self.assertIn("No WAF indicators detected", detail)
        self.assertIn("Evidence IDs: []", detail)

    def test_detail_promotes_at_threshold_and_lists_evidence(self):
        rules = [Rule("a", "A", "a", 60), Rule("b", "B", "b", 40)]
        store = AssessmentStore(rules)
        store.observe("https://x", [Evidence("a", "https://x", "header", "cloudflare")])
        detail = store.detail("https://x")
        self.assertIn("WAF suspected", detail)
        self.assertIn("cloudflare", detail)
        self.assertIn("Evidence IDs: [\"a\"]", detail)


if __name__ == "__main__":
    unittest.main()
