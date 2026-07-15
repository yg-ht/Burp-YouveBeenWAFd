"""Data structures shared by passive and active detection routines."""

try:
    from dataclasses import dataclass, field
except ImportError:  # pragma: no cover - Jython 2.7 uses the fallback classes.
    dataclass = None


if dataclass:
    @dataclass
    class Rule:
        """A configurable, data-driven detection rule."""

        rule_id: str
        name: str
        evidence_group: str
        weight: float
        tags: tuple = field(default_factory=tuple)
        matcher: dict = field(default_factory=dict)
        enabled: bool = True
        active: bool = False

    @dataclass(frozen=True)
    class Evidence:
        """One distinct observation produced by a rule."""

        rule_id: str
        origin: str
        detail: str
        product: str = ""
        source: str = "passive"
        action: str = ""

    @dataclass
    class OriginAssessment:
        """Current bounded assessment for one origin."""

        origin: str
        evidence: list = field(default_factory=list)
        representative_message: object = None

else:
    class Rule(object):
        def __init__(self, rule_id, name, evidence_group, weight, tags=(), matcher=None,
                     enabled=True, active=False):
            self.rule_id, self.name = rule_id, name
            self.evidence_group, self.weight = evidence_group, float(weight)
            self.tags, self.matcher = tuple(tags), matcher or {}
            self.enabled, self.active = bool(enabled), bool(active)

    class Evidence(object):
        def __init__(self, rule_id, origin, detail, product="", source="passive", action=""):
            self.rule_id, self.origin, self.detail = rule_id, origin, detail
            self.product, self.source, self.action = product, source, action

    class OriginAssessment(object):
        def __init__(self, origin, evidence=None, representative_message=None):
            self.origin = origin
            self.evidence = list(evidence or [])
            self.representative_message = representative_message
