"""Cross-runtime regression coverage for Jython Unicode text boundaries."""

import ast
import json
from pathlib import Path
import unittest
from unittest import mock

import wafd.config as config_module
import wafd.overrides as overrides_module
import wafd.probes as probes_module
import wafd.rules as rules_module
from wafd.config import Configuration
from wafd.fingerprint import build_fingerprint
from wafd.overrides import CatalogueOverrides
from wafd.probes import ProbeCatalogue, ProbePlanner
from wafd.request_builder import ProbeRequestBuilder
from wafd.rules import RuleCatalogue


class JythonUnicode(object):
    """Model Python 2 ``unicode`` as distinct from CPython 3 ``str``."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

    def __len__(self):
        return len(self.value)

    def __hash__(self):
        # Python 2 strings and Unicode strings with the same text use
        # compatible hashes, allowing ordinary string dictionary lookups.
        return hash(self.value)

    def __eq__(self, other):
        if isinstance(other, JythonUnicode):
            other = other.value
        return self.value == other

    def __ne__(self, other):
        return not self == other


def _as_jython_json(value):
    """Recursively convert decoded JSON text into Jython-style Unicode."""
    if isinstance(value, str):
        return JythonUnicode(value)
    if isinstance(value, list):
        return [_as_jython_json(item) for item in value]
    if isinstance(value, dict):
        return dict((_as_jython_json(key), _as_jython_json(item))
                    for key, item in value.items())
    return value


class JythonJsonCompatibilityTests(unittest.TestCase):
    """Exercise every runtime consumer of JSON-decoded text."""

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(__file__).resolve().parents[1]

    def test_complete_probe_catalogue_accepts_jython_unicode(self):
        document = json.loads((self.project_root / "data" / "probes.json").read_text())
        decoded = _as_jython_json(document)

        with mock.patch.object(probes_module.json, "loads", return_value=decoded):
            with mock.patch.object(
                    probes_module, "string_types", (str, JythonUnicode)):
                catalogue = ProbeCatalogue.from_json("ignored")

        self.assertEqual(213, len(catalogue.probes))
        self.assertTrue(ProbePlanner(catalogue=catalogue).plan_entries("GET", "query"))

    def test_complete_rule_catalogue_accepts_jython_unicode(self):
        document = json.loads(
            (self.project_root / "data" / "default_rules.json").read_text())
        decoded = _as_jython_json(document)

        with mock.patch.object(rules_module.json, "loads", return_value=decoded):
            with mock.patch.object(
                    rules_module, "string_types", (str, JythonUnicode)):
                catalogue = RuleCatalogue.from_json("ignored")

        self.assertEqual(41, len(catalogue.rules))

    def test_saved_configuration_accepts_jython_unicode(self):
        document = _as_jython_json(json.loads(Configuration().to_json()))

        with mock.patch.object(config_module.json, "loads", return_value=document):
            configuration = Configuration.from_json("ignored")

        self.assertEqual("root", configuration.non_get_target)

    def test_catalogue_overrides_accept_jython_unicode_identifiers(self):
        document = _as_jython_json({
            "schema_version": 1,
            "rules": {"rule-id": False},
            "probes": {"probe-id": True},
        })

        with mock.patch.object(overrides_module.json, "loads", return_value=document):
            with mock.patch.object(
                    overrides_module, "string_types", (str, JythonUnicode)):
                overrides = CatalogueOverrides.from_json("ignored")

        self.assertFalse(overrides.rules["rule-id"])
        self.assertTrue(overrides.probes["probe-id"])

    def test_json_consumers_do_not_validate_text_as_str_only(self):
        # A direct ``isinstance(value, str)`` silently rejects Python 2
        # ``unicode``.  Keep every persisted or bundled JSON consumer on the
        # shared-runtime string alias used by its module.
        source_paths = [
            self.project_root / "wafd" / name
            for name in ("config.py", "overrides.py", "probes.py", "rules.py")
        ]
        failures = []
        for source_path in source_paths:
            tree = ast.parse(source_path.read_text(), filename=str(source_path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                    continue
                if node.func.id != "isinstance" or len(node.args) < 2:
                    continue
                checked_type = node.args[1]
                if isinstance(checked_type, ast.Name) and checked_type.id == "str":
                    failures.append(
                        "%s:%s validates JSON text as str only"
                        % (source_path.relative_to(self.project_root), node.lineno)
                    )

        self.assertEqual([], failures, "\n".join(failures))


class JythonNetworkTextCompatibilityTests(unittest.TestCase):
    """Protect non-ASCII request and response text at the Burp boundary."""

    def test_request_builder_preserves_and_encodes_unicode_probe_text(self):
        builder = ProbeRequestBuilder()
        headers = ["GET /search HTTP/1.1", "Host: example.test"]

        query = builder.build(
            headers, "", {"placement": "query", "parameter": "value"}, "café")
        xml = builder.build(
            headers, "", {"placement": "xml", "method": "POST"}, "café")

        self.assertIn("value=caf%C3%A9", query.headers[0])
        self.assertIn("café", xml.body)

    def test_fingerprint_hashes_unicode_body_as_utf8(self):
        fingerprint = build_fingerprint(
            403, {"X-WAF-Reason": "défi"}, "bloqué", "1.1")

        self.assertEqual(len("bloqué".encode("utf-8")), fingerprint["body_length"])
        self.assertEqual("défi", fingerprint["headers"]["x-waf-reason"])
        self.assertEqual("bloqué", fingerprint["body"])


if __name__ == "__main__":
    unittest.main()
