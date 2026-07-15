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

    def test_status_transition_is_stronger_than_standalone_status(self):
        catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"transition","name":"Transition","evidence_group":"behaviour","weight":35,'
            '"matcher":{"kind":"status_transition","blocked":[403]}}]}')
        detector = ResponseDetector(catalogue)
        evidence = detector.detect("https://x", {"status": 403, "headers": {}, "body": "blocked"},
                                   "active", {"status": 200, "headers": {}, "body": "normal"})
        self.assertEqual(evidence[0].rule_id, "transition")

    def test_body_similarity_rule_detects_challenge_replacement(self):
        catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"body","name":"Body","evidence_group":"behaviour","weight":20,'
            '"matcher":{"kind":"body_similarity_drop","below":0.5}}]}')
        evidence = ResponseDetector(catalogue).detect(
            "https://x", {"status": 403, "headers": {}, "body": "captcha challenge page"},
            "active", {"status": 200, "headers": {}, "body": "normal application response with content"})
        self.assertEqual(evidence[0].rule_id, "body")

    def test_cloudflare_challenge_header_is_high_confidence_action_evidence(self):
        catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"cf","name":"CF challenge","evidence_group":"action","weight":100,'
            '"tags":["cloudflare","product","challenge"],'
            '"matcher":{"kind":"strong_header","name":"cf-mitigated","contains":"challenge"}}]}')
        evidence = ResponseDetector(catalogue).detect(
            "https://x", {"status": 403, "headers": {"cf-mitigated": "challenge"}, "body": "challenge"})
        self.assertEqual(evidence[0].product, "cloudflare")
        self.assertEqual(evidence[0].action, "challenge")

    def test_azure_requires_edge_header_and_block_body(self):
        catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"azure","name":"Azure","evidence_group":"action","weight":85,'
            '"tags":["azure-waf","product","block"],"matcher":{"kind":"header_body",'
            '"header":"x-azure-ref","body_terms":["the request is blocked"]}}]}')
        detector = ResponseDetector(catalogue)
        response = {"status": 403, "headers": {"x-azure-ref": "ref"}, "body": "The request is blocked."}
        self.assertEqual(detector.detect("https://x", response)[0].action, "block")

    def test_cookie_delta_and_body_hash_change_are_behavioural(self):
        catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"cookie","name":"Cookie","evidence_group":"cookie","weight":10,'
            '"matcher":{"kind":"cookie_delta"}},'
            '{"id":"hash","name":"Hash","evidence_group":"hash","weight":10,'
            '"matcher":{"kind":"body_hash_change"}}]}')
        baseline = {"status": 200, "headers": {}, "cookies": [], "body_hash": "a", "body": "normal"}
        response = {"status": 200, "headers": {}, "cookies": ["challenge"], "body_hash": "b", "body": "challenge"}
        ids = [item.rule_id for item in ResponseDetector(catalogue).detect("https://x", response, baseline=baseline)]
        self.assertEqual(ids, ["cookie", "hash"])

    def test_crs_identifier_and_concealed_status_are_recognised(self):
        catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"crs","name":"CRS","evidence_group":"crs","weight":100,'
            '"tags":["modsecurity","product","block"],"matcher":{"kind":"body_regex","pattern":"949110"}},'
            '{"id":"conceal","name":"Conceal","evidence_group":"conceal","weight":18,'
            '"matcher":{"kind":"status_transition","blocked":[404,502]}}]}')
        detector = ResponseDetector(catalogue)
        crs = detector.detect("https://x", {"status": 403, "headers": {}, "body": "id 949110"})
        conceal = detector.detect("https://x", {"status": 404, "headers": {}, "body": "not found"},
                                  baseline={"status": 200, "headers": {}, "body": "ok"})
        self.assertEqual(crs[0].product, "modsecurity")
        self.assertEqual(conceal[0].rule_id, "conceal")


if __name__ == "__main__":
    unittest.main()
