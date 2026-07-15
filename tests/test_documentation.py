import json
import os
import re
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))


def _read(relative_path):
    with open(os.path.join(ROOT, relative_path), "r") as source:
        return source.read()


class DocumentationConsistencyTests(unittest.TestCase):
    def test_documented_catalogue_counts_match_bundled_data(self):
        rules = json.loads(_read("data/default_rules.json"))["rules"]
        probes = json.loads(_read("data/probes.json"))
        matrix_count = sum(len(matrix["values"]) * len(matrix["placements"])
                           for matrix in probes["matrices"])
        concrete_count = len(probes["probes"]) + matrix_count
        documentation = "\n".join([
            _read("README.md"),
            _read("docs/configuration.md"),
            _read("docs/rules-and-probes.md"),
        ])

        self.assertIn("%d" % len(rules), documentation)
        self.assertIn("%d" % len(probes["probes"]), documentation)
        self.assertIn("%d" % len(probes["matrices"]), documentation)
        self.assertIn("%d" % concrete_count, documentation)

    def test_local_markdown_links_resolve(self):
        markdown_paths = ["README.md"] + [
            os.path.join("docs", filename) for filename in os.listdir(os.path.join(ROOT, "docs"))
            if filename.endswith(".md")
        ]
        for markdown_path in markdown_paths:
            directory = os.path.dirname(os.path.join(ROOT, markdown_path))
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", _read(markdown_path)):
                if target.startswith(("http://", "https://", "#")):
                    continue
                local_target = target.split("#", 1)[0]
                self.assertTrue(
                    os.path.exists(os.path.normpath(os.path.join(directory, local_target))),
                    "%s contains unresolved link %s" % (markdown_path, target))


if __name__ == "__main__":
    unittest.main()
