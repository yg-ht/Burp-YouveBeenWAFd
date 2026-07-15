import unittest

from wafd.detector import ResponseDetector
from wafd.rules import RuleCatalogue


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"h","name":"Header","evidence_group":"header","weight":20,'
            '"tags":["cloudflare","product"],"matcher":{"kind":"header","name":"Server","contains":"cloudflare"}},'
            '{"id":"s","name":"Status","evidence_group":"status","weight":10,'
            '"matcher":{"kind":"status","values":[403]}}]}')

    def test_matches_headers_case_insensitively(self):
        evidence = ResponseDetector(self.catalogue).detect(
            "https://example.test:443", {"status": 200, "headers": {"SERVER": "cloudflare"}, "body": ""})
        self.assertEqual([item.rule_id for item in evidence], ["h"])
        self.assertEqual(evidence[0].product, "cloudflare")

    def test_matches_status_and_deduplicates_rule_output(self):
        detector = ResponseDetector(self.catalogue)
        response = {"status": 403, "headers": {}, "body": ""}
        self.assertEqual(len(detector.detect("https://x", response)), 1)


if __name__ == "__main__":
    unittest.main()
