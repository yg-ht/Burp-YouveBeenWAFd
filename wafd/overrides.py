"""Versioned, Burp-persisted enablement overrides for data catalogues."""

import json

try:
    string_types = (basestring,)
except NameError:  # Python 3 test environment.
    string_types = (str,)


class CatalogueOverrides(object):
    """Store rule and probe enablement without modifying bundled JSON files."""

    VERSION = 1

    def __init__(self, rules=None, probes=None):
        self.rules = self._boolean_map(rules or {}, "rules")
        self.probes = self._boolean_map(probes or {}, "probes")

    @staticmethod
    def _boolean_map(values, label):
        if not isinstance(values, dict):
            raise ValueError("%s overrides must be an object" % label)
        validated = {}
        for identifier, enabled in values.items():
            if not isinstance(identifier, string_types) or not identifier:
                raise ValueError("%s override ids must be non-empty strings" % label)
            if not isinstance(enabled, bool):
                raise ValueError("%s override values must be booleans" % label)
            validated[identifier] = enabled
        return validated

    def to_json(self):
        return json.dumps({
            "schema_version": self.VERSION,
            "rules": self.rules,
            "probes": self.probes,
        }, sort_keys=True)

    @classmethod
    def from_json(cls, text):
        document = json.loads(text)
        if not isinstance(document, dict) or document.get("schema_version") != cls.VERSION:
            raise ValueError("unsupported catalogue override schema")
        return cls(document.get("rules", {}), document.get("probes", {}))

    @classmethod
    def capture(cls, rules, probes):
        """Capture complete current states so removals and additions are deterministic."""
        return cls(dict((rule.rule_id, bool(rule.enabled)) for rule in rules),
                   dict((probe.probe_id, bool(probe.enabled)) for probe in probes))

    def apply(self, rules, probes):
        """Apply known IDs and ignore stale overrides from older catalogues."""
        for rule in rules:
            if rule.rule_id in self.rules:
                rule.enabled = self.rules[rule.rule_id]
        for probe in probes:
            if probe.probe_id in self.probes:
                probe.enabled = self.probes[probe.probe_id]
