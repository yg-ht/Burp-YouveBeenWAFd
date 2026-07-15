"""Rule catalogue loading and validation."""

import json

from .models import Rule

try:
    string_types = (basestring,)
except NameError:  # Python 3 test environment.
    string_types = (str,)


class RuleCatalogue(object):
    """Load bundled or user-supplied JSON rules without executing code."""

    def __init__(self, rules):
        self.rules = list(rules)
        self._validate_unique_ids()

    @classmethod
    def from_json(cls, text):
        document = json.loads(text)
        # Keep the catalogue declarative. Only recognised model fields are
        # constructed; JSON content is never imported or evaluated as code.
        if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
            raise ValueError("rule document must contain a rules list")
        return cls(cls._rule_from_dict(item) for item in document["rules"])

    @staticmethod
    def _rule_from_dict(item):
        if not isinstance(item, dict):
            raise ValueError("each rule must be an object")
        required = ("id", "name", "evidence_group", "weight")
        if any(key not in item for key in required):
            raise ValueError("rule is missing a required field")
        rule_id = item["id"]
        if not isinstance(rule_id, string_types) or not rule_id or len(rule_id) > 100:
            raise ValueError("rule id must be a non-empty short string")
        weight = float(item["weight"])
        if weight < 0 or weight > 100:
            raise ValueError("rule weight must be between 0 and 100")
        matcher = item.get("matcher", {})
        if not isinstance(matcher, dict):
            raise ValueError("rule matcher must be an object")
        return Rule(rule_id, str(item["name"]), str(item["evidence_group"]),
                    weight, tuple(item.get("tags", [])), matcher,
                    bool(item.get("enabled", True)))

    def _validate_unique_ids(self):
        # Evidence is deduplicated by rule identifier, so duplicate IDs would
        # make both confidence scoring and issue details order-dependent.
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")

    def enabled(self):
        return [rule for rule in self.rules if rule.enabled]
