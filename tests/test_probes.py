import unittest

from wafd.probes import ProbeCatalogue, ProbePlanner


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

    def test_catalogue_is_external_and_provider_filterable(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"cf","name":"CF","value":"x","providers":["cloudflare"]},'
            '{"id":"aws","name":"AWS","value":"y","providers":["aws-waf"]}]}')
        planner = ProbePlanner(3, catalogue=catalogue)
        self.assertEqual(planner.plan("GET", "query", ["aws-waf"]), ["y"])

    def test_duplicate_probe_ids_are_rejected(self):
        with self.assertRaises(ValueError):
            ProbeCatalogue.from_json('{"schema_version":1,"probes":['
                '{"id":"x","value":"1"},{"id":"x","value":"2"}]}')

    def test_repetition_is_bounded_and_catalogue_driven(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"sequence","value":"x","repeat":5}]}')
        self.assertEqual(ProbePlanner(4, catalogue=catalogue).plan("GET", "query"),
                         ["x", "x", "x", "x"])

    def test_probe_method_allowlist_is_enforced(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"post","value":"x","safe_methods":["POST"]}]}')
        self.assertEqual(ProbePlanner(3, catalogue=catalogue).plan("GET", "query"), [])

    def test_bundled_provider_profiles_include_safety_metadata(self):
        catalogue = ProbeCatalogue.bundled()
        profiles = dict((probe.probe_id, probe) for probe in catalogue.probes)
        self.assertIn("aws.challenge-profile", profiles)
        self.assertTrue(profiles["azure.gateway-size-profile"].enabled)
        self.assertEqual(profiles["f5.support-id-profile"].profile["expected_body_terms"][1], "support id")


if __name__ == "__main__":
    unittest.main()
