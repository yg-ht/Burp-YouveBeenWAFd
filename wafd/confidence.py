"""Confidence calculation independent of Burp request/response APIs."""

from .models import Evidence


class ConfidenceEngine(object):
    """Calculate confidence from independent evidence groups.

    Each rule contributes at most once, and each evidence group contributes at
    most its strongest enabled rule. This prevents several aliases for one
    header or error page from falsely reaching the threshold.
    """

    def __init__(self, rules, threshold=0.60):
        self.rules = {rule.rule_id: rule for rule in rules}
        self.threshold = self._bounded_threshold(threshold)

    @staticmethod
    def _bounded_threshold(value):
        value = float(value)
        if value < 0.0 or value > 1.0:
            raise ValueError("confidence threshold must be between 0 and 1")
        return value

    def score(self, evidence):
        """Return ``(generic_score, product_scores)`` as values from 0 to 1."""
        strongest_by_group = {}
        product_scores = {}
        # Each evidence group contributes confidence points at most once. Rule
        # weights retain their documented 0-100 meaning, and adding a mutually
        # exclusive provider cannot dilute an existing assessment.
        for item in evidence:
            rule = self.rules.get(item.rule_id)
            if not rule or not rule.enabled or rule.weight <= 0:
                continue
            current = strongest_by_group.get(rule.evidence_group)
            if current is None or rule.weight > current[0]:
                strongest_by_group[rule.evidence_group] = (rule.weight, item)

        generic = sum(value[0] for value in strongest_by_group.values()) / 100.0
        for weight, item in strongest_by_group.values():
            if item.product:
                product_scores[item.product] = product_scores.get(item.product, 0.0) + weight
        return min(1.0, generic), {
            product: min(1.0, value / 100.0)
            for product, value in product_scores.items()
        }

    def has_waf(self, evidence):
        """Return whether current evidence meets the configured threshold."""
        return self.score(evidence)[0] >= self.threshold
