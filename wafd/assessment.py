"""Per-origin evidence and issue-detail formatting."""

import json
import time

try:
    from html import escape as html_escape
except ImportError:  # Jython 2.7 compatibility.
    from cgi import escape as html_escape

from .confidence import ConfidenceEngine
from .models import Determination, Evidence, OriginAssessment, QualityState


class AssessmentStore(object):
    """Maintain bounded current evidence and produce human-readable details."""

    def __init__(self, rules, threshold=0.60, max_evidence=5000,
                 max_history=50, clock=None):
        self.engine = ConfidenceEngine(rules, threshold)
        self.max_evidence = int(max_evidence)
        self.max_history = max(1, int(max_history))
        self.clock = clock or self._utc_now
        self.assessments = {}

    @staticmethod
    def _utc_now():
        """Return a dependency-free UTC timestamp under CPython and Jython."""
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    @staticmethod
    def _quality_key(evidence):
        """Return the stable identity used for current-quality reconciliation."""
        return evidence.rule_id, evidence.characteristic

    @staticmethod
    def _copy_evidence(evidence, observed_at=None):
        """Copy evidence so historical determinations cannot change in place."""
        return Evidence(
            evidence.rule_id, evidence.origin, evidence.detail,
            evidence.product, evidence.source, evidence.action,
            evidence.characteristic, evidence.classification,
            evidence.observed_at if observed_at is None else observed_at)

    def _timestamp(self, value=None):
        """Return a UTC ISO-8601 timestamp suitable for issue rendering."""
        value = self.clock() if value is None else value
        if hasattr(value, "strftime"):
            return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return str(value)

    def observe(self, origin, evidence, representative_message=None,
                observed_at=None):
        assessment = self.assessments.setdefault(origin, OriginAssessment(origin))
        timestamp = self._timestamp(observed_at)
        # A rule contributes only once per origin. This prevents frequently
        # observed passive headers from overwhelming distinct behavioural
        # evidence and keeps the stored assessment bounded.
        indexed = dict((self._quality_key(item), position)
                       for position, item in enumerate(assessment.evidence))
        for item in evidence:
            evidence_key = self._quality_key(item)
            copied = self._copy_evidence(item, timestamp)
            if evidence_key in indexed:
                # The latest details replace an earlier observation while its
                # first-detected timestamp remains stable.
                assessment.evidence[indexed[evidence_key]] = copied
            elif len(assessment.evidence) < self.max_evidence:
                indexed[evidence_key] = len(assessment.evidence)
                assessment.evidence.append(copied)
            else:
                continue
            state = assessment.quality_states.get(evidence_key)
            first_detected = (state.first_detected_at if state is not None
                              else timestamp)
            assessment.quality_states[evidence_key] = QualityState(
                copied, first_detected, timestamp)
        if representative_message is not None:
            assessment.representative_message = representative_message
        return assessment

    def reconcile_active(self, origin, tested_characteristics, evidence,
                         representative_message=None, started_at=None,
                         completed_at=None):
        """Commit one active batch and replace only qualities it rechecked."""
        assessment = self.assessments.setdefault(origin, OriginAssessment(origin))
        started = self._timestamp(started_at)
        completed = self._timestamp(completed_at)
        tested = tuple(sorted(set(str(value) for value in tested_characteristics
                                  if str(value))))
        tested_set = set(tested)

        # Repeated transmissions for one probe can produce the same quality.
        # Keep its latest evidence once and reconcile the complete probe only
        # after every transmission in the batch has finished.
        matched_by_key = {}
        for item in evidence:
            if item.characteristic in tested_set:
                matched_by_key[self._quality_key(item)] = self._copy_evidence(
                    item, completed)

        old_tested_keys = set(
            self._quality_key(item) for item in assessment.evidence
            if item.characteristic in tested_set)
        preserved = [item for item in assessment.evidence
                     if item.characteristic not in tested_set]
        capacity = max(0, self.max_evidence - len(preserved))
        # Reconfirmed current qualities retain their existing bounded slots;
        # only the remaining capacity is used for newly discovered qualities.
        ordered_keys = sorted(
            matched_by_key,
            key=lambda key: (0 if key in old_tested_keys else 1, key))
        retained_keys = ordered_keys[:capacity]
        retained_key_set = set(retained_keys)
        cleared_keys = sorted(old_tested_keys - retained_key_set)
        matched_items = [matched_by_key[key] for key in retained_keys]
        assessment.evidence = preserved + matched_items

        for key in cleared_keys:
            state = assessment.quality_states.get(key)
            if state is not None:
                state.cleared_at = completed
        for item in matched_items:
            key = self._quality_key(item)
            state = assessment.quality_states.get(key)
            first_detected = (state.first_detected_at if state is not None
                              else completed)
            assessment.quality_states[key] = QualityState(
                item, first_detected, completed)

        assessment.latest_cleared_quality_keys = list(cleared_keys)
        if representative_message is not None:
            assessment.representative_message = representative_message

        score = self.engine.score(assessment.evidence)[0]
        determination = Determination(
            started, completed, tested, matched_items, cleared_keys,
            score, self.engine.threshold)
        assessment.determinations.append(determination)
        assessment.determinations = assessment.determinations[-self.max_history:]
        return assessment, determination

    def detail(self, origin):
        assessment = self.assessments.get(origin, OriginAssessment(origin))
        score, products = self.engine.score(assessment.evidence)
        product_names = sorted(products, key=lambda product: products[product], reverse=True)
        state = "WAF suspected" if score >= self.engine.threshold else "No WAF indicators detected"
        # Every value that can originate in HTTP traffic is escaped before it
        # reaches Burp's HTML issue renderer.
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
                "<li>%s%s%s: %s</li>" % (
                    html_escape(str(item.rule_id), quote=True),
                    (" [%s]" % html_escape(str(item.characteristic), quote=True))
                    if item.characteristic else "",
                    (" (%s)" % html_escape(str(item.classification), quote=True))
                    if item.classification else "",
                    html_escape(str(item.detail), quote=True))
                for item in assessment.evidence))
        else:
            lines.append("<p>No distinct detection rules have matched yet.</p>")
        # This compact marker makes reload recovery possible without retaining
        # complete request bodies or serialising arbitrary Python objects.
        marker = json.dumps(sorted(
            "%s:%s" % (item.rule_id, item.characteristic)
            if item.characteristic else item.rule_id
            for item in assessment.evidence),
                            separators=(",", ":"))
        lines.append("<p>Evidence IDs: %s</p>" % marker)
        return "".join(lines)
