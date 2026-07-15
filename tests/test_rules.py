import json
import unittest

from wafd.rules import RuleCatalogue


class RuleCatalogueTests(unittest.TestCase):
    def test_loads_and_validates_rules(self):
        catalogue = RuleCatalogue.from_json(json.dumps({"rules": [{
            "id": "r1", "name": "Rule", "evidence_group": "g", "weight": 10
        }]}))
        self.assertEqual(catalogue.enabled()[0].rule_id, "r1")

    def test_duplicate_ids_are_rejected(self):
        document = {"rules": [{"id": "r", "name": "1", "evidence_group": "g", "weight": 1},
                               {"id": "r", "name": "2", "evidence_group": "g", "weight": 1}]}
        with self.assertRaises(ValueError):
            RuleCatalogue.from_json(json.dumps(document))

    def test_catalogue_rejects_out_of_range_weight(self):
        document = {"rules": [{"id": "r", "name": "1", "evidence_group": "g", "weight": 101}]}
        with self.assertRaises(ValueError):
            RuleCatalogue.from_json(json.dumps(document))


if __name__ == "__main__":
    unittest.main()
