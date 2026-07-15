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

    def test_cookie_value_rotation_is_detected_without_cookie_values(self):
        catalogue = RuleCatalogue.from_json('{"rules": ['
            '{"id":"cookie-value","name":"Cookie value","evidence_group":"cookie-value",'
            '"weight":10,"matcher":{"kind":"cookie_value_delta"}}]}')
        baseline = {"status": 200, "headers": {}, "cookie_fingerprints": {"session": "a"}}
        response = {"status": 200, "headers": {}, "cookie_fingerprints": {"session": "b"}}
        evidence = ResponseDetector(catalogue).detect("https://x", response, baseline=baseline)
        self.assertEqual(evidence[0].detail, "probe rotated response cookies: session")

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

    def test_challenge_status_requires_transition(self):
        catalogue = RuleCatalogue.from_json('{"rules": [{"id":"challenge","name":"Challenge",'
            '"evidence_group":"challenge","weight":20,"matcher":{"kind":"challenge_transition",'
            '"statuses":[403],"terms":["challenge"]}}]}')
        detector = ResponseDetector(catalogue)
        evidence = detector.detect("https://x", {"status": 403, "headers": {}, "body": "same"},
                                   baseline={"status": 403, "headers": {}, "body": "same"})
        self.assertEqual(evidence, [])

    def test_zero_weight_active_outcome_records_probe_identity(self):
        catalogue = RuleCatalogue.from_json('{"rules": [{"id":"outcome","name":"Outcome",'
            '"evidence_group":"audit","weight":0,"matcher":{"kind":"active_outcome"}}]}')
        evidence = ResponseDetector(catalogue).detect(
            "https://x", {"status": 403, "headers": {}, "body": "blocked"},
            "active", {"status": 200, "headers": {}, "body": "ordinary"},
            "matrix.sqli.boolean.query", "malformed-request")
        self.assertEqual(evidence[0].detail, "control HTTP 200; probe HTTP 403")
        self.assertEqual(evidence[0].characteristic, "matrix.sqli.boolean.query")
        self.assertEqual(evidence[0].classification, "malformed-request")

    def test_request_policy_transition_covers_size_and_header_failures(self):
        catalogue = RuleCatalogue.from_json('{"rules": [{"id":"policy","name":"Policy",'
            '"evidence_group":"policy","weight":16,"matcher":{"kind":"status_transition",'
            '"blocked":[400,403,413,431,502]}}]}')
        detector = ResponseDetector(catalogue)
        for status in (400, 403, 413, 431, 502):
            evidence = detector.detect(
                "https://x", {"status": status, "headers": {}, "body": "rejected"},
                "active", {"status": 200, "headers": {}, "body": "ordinary"})
            self.assertEqual(evidence[0].rule_id, "policy")


if __name__ == "__main__":
    unittest.main()
