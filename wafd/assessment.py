"""Per-origin evidence and issue-detail formatting."""

import json

try:
    from html import escape as html_escape
except ImportError:  # Jython 2.7 compatibility.
    from cgi import escape as html_escape

from .confidence import ConfidenceEngine
from .models import OriginAssessment


class AssessmentStore(object):
    """Maintain bounded current evidence and produce human-readable details."""

    def __init__(self, rules, threshold=0.60, max_evidence=100):
        self.engine = ConfidenceEngine(rules, threshold)
        self.max_evidence = int(max_evidence)
        self.assessments = {}

    def observe(self, origin, evidence, representative_message=None):
        assessment = self.assessments.setdefault(origin, OriginAssessment(origin))
        known = set(item.rule_id for item in assessment.evidence)
        for item in evidence:
            if item.rule_id not in known and len(assessment.evidence) < self.max_evidence:
                assessment.evidence.append(item)
                known.add(item.rule_id)
        if representative_message is not None:
            assessment.representative_message = representative_message
        return assessment

    def detail(self, origin):
        assessment = self.assessments.get(origin, OriginAssessment(origin))
        score, products = self.engine.score(assessment.evidence)
        product_names = sorted(products, key=lambda product: products[product], reverse=True)
        state = "WAF suspected" if score >= self.engine.threshold else "No WAF indicators detected"
        safe_origin = html_escape(str(origin), quote=True)
        lines = ["<p><b>%s</b></p>" % html_escape(state),
                 "<p>Origin: %s<br>Confidence: %.0f%% (threshold %.0f%%)</p>" %
                 (safe_origin, score * 100, self.engine.threshold * 100)]
        if product_names:
            lines.append("<p>Edge/provider signals: %s</p>" % ", ".join(
                html_escape(str(product), quote=True) for product in product_names))
        actions = sorted(set(item.action for item in assessment.evidence if item.action))
        if actions:
            lines.append("<p>Observed security actions: %s</p>" % ", ".join(
                html_escape(str(action), quote=True) for action in actions))
        if assessment.evidence:
            lines.append("<p>Detections:</p><ul>%s</ul>" % "".join(
                "<li>%s: %s</li>" % (html_escape(str(item.rule_id), quote=True),
                                      html_escape(str(item.detail), quote=True))
                for item in assessment.evidence))
        else:
            lines.append("<p>No distinct detection rules have matched yet.</p>")
        # This compact marker makes reload recovery possible without retaining
        # complete request bodies or serialising arbitrary Python objects.
        marker = json.dumps(sorted(item.rule_id for item in assessment.evidence),
                            separators=(",", ":"))
        lines.append("<p>Evidence IDs: %s</p>" % marker)
        return "".join(lines)
