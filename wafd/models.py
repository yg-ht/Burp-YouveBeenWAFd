"""Data structures shared by passive and active detection routines.

This module is imported directly by Burp's Jython 2.7 runtime.  Every code path
must therefore use Python 2-compatible syntax: placing Python 3 syntax behind a
conditional does not help because Jython parses the complete file first.
"""


class Rule(object):
    """A configurable, data-driven detection rule.

    Args:
        rule_id: Stable identifier used by evidence and configuration overrides.
        name: Human-readable rule name.
        evidence_group: Group used to de-duplicate confidence contributions.
        weight: Confidence contribution for this rule.
        tags: Product, action, and generic classification tags.
        matcher: Data-driven matcher configuration.
        enabled: Whether the detector should evaluate this rule.
    """

    def __init__(self, rule_id, name, evidence_group, weight, tags=(), matcher=None,
                 enabled=True):
        # Store identifiers separately to keep diagnosis straightforward in
        # Jython stack traces and interactive Burp inspection.
        self.rule_id = rule_id
        self.name = name
        self.evidence_group = evidence_group
        self.weight = float(weight)

        # Copy tags into an immutable tuple.  A fresh matcher is created only
        # when none was supplied, preventing instances from sharing a default.
        self.tags = tuple(tags)
        self.matcher = {} if matcher is None else matcher
        self.enabled = bool(enabled)


class Evidence(object):
    """One distinct observation produced by a rule.

    The optional fields remain strings so evidence can be rendered, persisted
    in memory, and scored without importing Burp-specific Java classes.
    """

    def __init__(self, rule_id, origin, detail, product="", source="passive", action="",
                 characteristic="", classification=""):
        # Keep constructor ordering compatible with every existing detector
        # call while retaining named-argument support for specialist evidence.
        self.rule_id = rule_id
        self.origin = origin
        self.detail = detail
        self.product = product
        self.source = source
        self.action = action
        self.characteristic = characteristic
        self.classification = classification


class OriginAssessment(object):
    """Current bounded assessment for one origin."""

    def __init__(self, origin, evidence=None, representative_message=None):
        self.origin = origin

        # Copy caller-provided evidence so the assessment owns its mutable
        # collection and cannot accidentally modify a list held elsewhere.
        self.evidence = list(evidence) if evidence is not None else []
        self.representative_message = representative_message
