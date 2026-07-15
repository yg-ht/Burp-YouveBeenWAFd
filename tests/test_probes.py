import unittest

from wafd.probes import ProbeCatalogue, ProbePlanner


class ProbePlannerTests(unittest.TestCase):
    def test_safe_methods_are_bounded(self):
        probes = ProbePlanner(3).plan("GET", "query")
        self.assertEqual(len(probes), 3)
        self.assertIn("<script>alert(1)</script>", probes)
        self.assertIn("' OR '1'='1", probes)

    def test_constructed_outgoing_methods_use_each_probe_allowlist(self):
        probes = ProbePlanner().plan_entries("POST", "query")
        self.assertTrue(probes)
        self.assertTrue(all(
            str(probe.profile.get("method", "POST")).upper() in probe.safe_methods
            for probe in probes))

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

    def test_complete_entry_plan_honours_repetition(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"sequence","value":"x","repeat":3}]}')
        entries = ProbePlanner(catalogue=catalogue).plan_entries("GET", "query")
        self.assertEqual([probe.probe_id for probe in entries],
                         ["sequence", "sequence", "sequence"])

    def test_default_plan_returns_every_eligible_probe(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"one","value":"1"},{"id":"two","value":"2"}]}')
        self.assertEqual(ProbePlanner(catalogue=catalogue).plan("GET", "query"),
                         ["1", "2"])

    def test_zero_limit_sends_no_probes(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"one","value":"1"}]}')
        self.assertEqual(ProbePlanner(0, catalogue=catalogue).plan("GET", "query"), [])

    def test_probe_method_allowlist_is_enforced(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"post","value":"x","safe_methods":["POST"]}]}')
        self.assertEqual(ProbePlanner(3, catalogue=catalogue).plan("GET", "query"), [])

    def test_constructed_method_must_be_explicitly_allowed(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"put","value":"x","safe_methods":["POST"],'
            '"profile":{"method":"PUT","placement":"raw_body"}}]}')
        self.assertEqual(ProbePlanner(catalogue=catalogue).plan_entries("GET", "query"), [])

    def test_constructed_method_is_independent_of_triggering_request(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":1,"probes":['
            '{"id":"put","value":"x","safe_methods":["PUT"],'
            '"profile":{"method":"PUT","placement":"raw_body"}}]}')
        entries = ProbePlanner(catalogue=catalogue).plan_entries("GET", "query")
        self.assertEqual([probe.probe_id for probe in entries], ["put"])

    def test_bundled_provider_profiles_include_safety_metadata(self):
        catalogue = ProbeCatalogue.bundled()
        profiles = dict((probe.probe_id, probe) for probe in catalogue.probes)
        self.assertIn("aws.challenge-profile", profiles)
        self.assertTrue(profiles["azure.gateway-size-profile"].enabled)
        self.assertEqual(profiles["f5.support-id-profile"].profile["expected_body_terms"][1], "support id")

    def test_version_two_matrix_expands_values_and_placements(self):
        catalogue = ProbeCatalogue.from_json('{"schema_version":2,"matrices":[{'
            '"id":"sql","name":"SQL","providers":["generic"],'
            '"values":[{"id":"boolean","value":"1 OR 1=1"}],'
            '"placements":[{"id":"query","placement":"query","safe_methods":["GET"]},'
            '{"id":"json","placement":"json","safe_methods":["POST"]}]}]}')
        self.assertEqual([probe.probe_id for probe in catalogue.probes],
                         ["sql.boolean.query", "sql.boolean.json"])
        self.assertEqual(catalogue.probes[1].profile["placement"], "json")
        self.assertEqual(catalogue.probes[1].safe_methods, ("POST",))


if __name__ == "__main__":
    unittest.main()
