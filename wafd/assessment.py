"""Per-origin evidence and issue-detail formatting."""

import base64
import json
import time
from threading import RLock

try:
    from html import escape as html_escape
except ImportError:  # Jython 2.7 compatibility.
    from cgi import escape as html_escape

from .confidence import ConfidenceEngine
from .models import (Determination, Evidence, OriginAssessment, ProbeOutcome,
                     QualityState)

try:
    string_types = (basestring,)
except NameError:  # CPython 3 test environment.
    string_types = (str,)


def _text(value):
    """Preserve Python 2 Unicode while stringifying non-text values."""
    return value if isinstance(value, string_types) else str(value)


class AssessmentStore(object):
    """Maintain bounded current evidence and produce human-readable details."""

    STATE_PREFIX = "<!-- WAFD_STATE_V1:"
    STATE_SUFFIX = " -->"
    STATE_VERSION = 1
    STATE_MAX_BYTES = 1024 * 1024
    STATE_MAX_IDENTIFIER = 4096
    STATE_MAX_TIMESTAMP = 64

    def __init__(self, rules, threshold=0.60, max_evidence=5000,
                 max_history=50, clock=None):
        self.engine = ConfidenceEngine(rules, threshold)
        self.max_evidence = int(max_evidence)
        self.max_history = max(1, int(max_history))
        self.clock = clock or self._utc_now
        self.assessments = {}
        self._lock = RLock()

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
        return _text(value)

    def _prune_quality_states(self, assessment):
        """Bound cleared lifecycle records while always retaining current ones."""
        if len(assessment.quality_states) <= self.max_evidence:
            return
        current_keys = set(self._quality_key(item) for item in assessment.evidence)
        removable = sorted(
            (key for key in assessment.quality_states if key not in current_keys),
            key=lambda key: assessment.quality_states[key].last_confirmed_at)
        while len(assessment.quality_states) > self.max_evidence and removable:
            del assessment.quality_states[removable.pop(0)]

    def observe(self, origin, evidence, representative_message=None,
                observed_at=None):
        with self._lock:
            return self._observe(
                origin, evidence, representative_message, observed_at)

    def _observe(self, origin, evidence, representative_message=None,
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
        self._prune_quality_states(assessment)
        return assessment

    def reconcile_active(self, origin, tested_characteristics, evidence,
                         representative_message=None, started_at=None,
                         completed_at=None, outcomes=None,
                         skipped_characteristics=None):
        """Commit one active batch and replace only qualities it rechecked."""
        with self._lock:
            return self._reconcile_active(
                origin, tested_characteristics, evidence,
                representative_message, started_at, completed_at,
                outcomes, skipped_characteristics)

    def _reconcile_active(self, origin, tested_characteristics, evidence,
                          representative_message=None, started_at=None,
                          completed_at=None, outcomes=None,
                          skipped_characteristics=None):
        assessment = self.assessments.setdefault(origin, OriginAssessment(origin))
        started = self._timestamp(started_at)
        completed = self._timestamp(completed_at)
        tested = tuple(sorted(set(_text(value) for value in tested_characteristics
                                  if _text(value))))
        tested_set = set(tested)

        # Repeated transmissions for one probe can produce the same quality.
        # Keep its latest evidence once and reconcile the complete probe only
        # after every transmission in the batch has finished.
        matched_by_key = {}
        for item in evidence:
            if item.characteristic in tested_set:
                matched_by_key[self._quality_key(item)] = self._copy_evidence(
                    item, item.observed_at or completed)

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
                              else item.observed_at or completed)
            assessment.quality_states[key] = QualityState(
                item, first_detected, item.observed_at or completed)

        assessment.latest_cleared_quality_keys = list(cleared_keys)
        if representative_message is not None:
            assessment.representative_message = representative_message

        score = self.engine.score(assessment.evidence)[0]
        determination = Determination(
            started, completed, tested,
            [self._copy_evidence(item) for item in assessment.evidence],
            cleared_keys, score, self.engine.threshold,
            [self._copy_evidence(item) for item in matched_items],
            list(outcomes or ()), sorted(set(skipped_characteristics or ())))
        assessment.determinations.append(determination)
        assessment.determinations = assessment.determinations[-self.max_history:]
        self._prune_quality_states(assessment)
        return assessment, determination

    @staticmethod
    def _key_document(key):
        return [_text(key[0]), _text(key[1])]

    def _evidence_for_key(self, origin, key, quality_states, observed_at=""):
        state = quality_states.get(key)
        if state is not None:
            return self._copy_evidence(state.evidence, observed_at or None)
        return Evidence(key[0], origin, "", characteristic=key[1],
                        observed_at=observed_at)

    def _determination_document(self, determination):
        return {
            "started_at": determination.started_at,
            "completed_at": determination.completed_at,
            "tested": list(determination.tested_characteristics),
            "qualities": [self._key_document(self._quality_key(item))
                          for item in determination.evidence],
            "matched": [self._key_document(self._quality_key(item))
                         for item in determination.matched_evidence],
            "cleared": [self._key_document(key)
                         for key in determination.cleared_quality_keys],
            "score": determination.score,
            "threshold": determination.threshold,
            "outcomes": [{
                "characteristic": item.characteristic,
                "state": item.connection_state,
                "elapsed_ms": item.elapsed_ms,
                "status": item.status,
                "observed_at": item.observed_at,
            } for item in determination.outcomes],
            "skipped": list(determination.skipped_characteristics),
        }

    def _state_document(self, origin, assessment):
        current_keys = set(self._quality_key(item) for item in assessment.evidence)
        qualities = []
        for key in sorted(assessment.quality_states):
            state = assessment.quality_states[key]
            item = state.evidence
            qualities.append({
                "k": self._key_document(key),
                "p": _text(item.product)[:128],
                "s": _text(item.source)[:32],
                "a": _text(item.action)[:128],
                "c": _text(item.classification)[:128],
                "o": _text(item.observed_at)[:self.STATE_MAX_TIMESTAMP],
                "f": _text(state.first_detected_at)[:self.STATE_MAX_TIMESTAMP],
                "l": _text(state.last_confirmed_at)[:self.STATE_MAX_TIMESTAMP],
                "x": _text(state.cleared_at)[:self.STATE_MAX_TIMESTAMP],
                "u": key in current_keys,
            })
        return {
            "version": self.STATE_VERSION,
            "origin": _text(origin),
            "qualities": qualities,
            "latest_cleared": [self._key_document(key)
                               for key in assessment.latest_cleared_quality_keys],
            "determinations": [self._determination_document(item)
                               for item in assessment.determinations],
        }

    def state_marker(self, origin):
        """Return bounded versioned state metadata for the current Burp issue."""
        with self._lock:
            return self._state_marker(origin)

    def _state_marker(self, origin):
        assessment = self.assessments.get(origin)
        if assessment is None:
            return ""
        document = self._state_document(origin, assessment)
        # Oldest summaries are redundant with immutable determination issues;
        # trim them first if the recoverable current-state marker is too large.
        while True:
            raw = json.dumps(document, separators=(",", ":"),
                             sort_keys=True).encode("utf-8")
            if len(raw) <= self.STATE_MAX_BYTES:
                # Standard Base64 has no hyphen, so the opaque payload cannot
                # introduce an invalid ``--`` sequence into the HTML comment.
                encoded = base64.b64encode(raw)
                if hasattr(encoded, "decode"):
                    encoded = encoded.decode("ascii")
                return "%s%s%s" % (
                    self.STATE_PREFIX, encoded, self.STATE_SUFFIX)
            if document["determinations"]:
                document["determinations"].pop(0)
                continue
            # Never publish an oversized or partial recovery payload.
            return ""

    @classmethod
    def _state_payload(cls, detail):
        text = _text(detail or "")
        start = text.rfind(cls.STATE_PREFIX)
        if start < 0:
            return None
        start += len(cls.STATE_PREFIX)
        end = text.find(cls.STATE_SUFFIX, start)
        if end < 0:
            raise ValueError("assessment state marker is incomplete")
        encoded = text[start:end]
        if not encoded or len(encoded) > ((cls.STATE_MAX_BYTES * 4 // 3) + 8):
            raise ValueError("assessment state marker is oversized")
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        if any(character not in allowed for character in encoded):
            raise ValueError("assessment state marker is malformed")
        try:
            raw = base64.b64decode(encoded.encode("ascii"))
        except Exception:
            raise ValueError("assessment state marker is malformed")
        if len(raw) > cls.STATE_MAX_BYTES:
            raise ValueError("assessment state marker is oversized")
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, TypeError, UnicodeError):
            raise ValueError("assessment state document is malformed")

    @classmethod
    def _validated_text(cls, value, name, maximum):
        if not isinstance(value, string_types) or len(value) > maximum:
            raise ValueError("assessment state %s is invalid" % name)
        return value

    @classmethod
    def _validated_key(cls, value):
        if not isinstance(value, list) or len(value) != 2:
            raise ValueError("assessment quality key is invalid")
        return (
            cls._validated_text(value[0], "rule id", cls.STATE_MAX_IDENTIFIER),
            cls._validated_text(value[1], "characteristic", cls.STATE_MAX_IDENTIFIER),
        )

    def restore(self, origin, detail):
        """Restore validated current state from an existing Burp issue detail."""
        with self._lock:
            return self._restore(origin, detail)

    def _restore(self, origin, detail):
        document = self._state_payload(detail)
        if document is None:
            return None
        if not isinstance(document, dict) or document.get("version") != self.STATE_VERSION:
            raise ValueError("assessment state version is unsupported")
        stored_origin = self._validated_text(
            document.get("origin"), "origin", self.STATE_MAX_IDENTIFIER)
        if stored_origin != _text(origin):
            raise ValueError("assessment state origin does not match")

        quality_documents = document.get("qualities")
        if (not isinstance(quality_documents, list) or
                len(quality_documents) > self.max_evidence):
            raise ValueError("assessment qualities are invalid")
        quality_states = {}
        current_evidence = []
        for quality in quality_documents:
            if not isinstance(quality, dict):
                raise ValueError("assessment quality is invalid")
            key = self._validated_key(quality.get("k"))
            if key in quality_states:
                raise ValueError("assessment quality is duplicated")
            # Rules removed from the current catalogue cannot contribute to a
            # restored score, so ignore their historical lifecycle record.
            if key[0] not in self.engine.rules:
                continue
            evidence = Evidence(
                key[0], stored_origin, "",
                self._validated_text(quality.get("p"), "product", 128),
                self._validated_text(quality.get("s"), "source", 32),
                self._validated_text(quality.get("a"), "action", 128),
                key[1],
                self._validated_text(
                    quality.get("c"), "classification", 128),
                self._validated_text(
                    quality.get("o"), "observed time",
                    self.STATE_MAX_TIMESTAMP))
            state = QualityState(
                evidence,
                self._validated_text(
                    quality.get("f"), "first detection time",
                    self.STATE_MAX_TIMESTAMP),
                self._validated_text(
                    quality.get("l"), "confirmation time",
                    self.STATE_MAX_TIMESTAMP),
                self._validated_text(
                    quality.get("x"), "clearance time",
                    self.STATE_MAX_TIMESTAMP))
            quality_states[key] = state
            if quality.get("u") is True:
                current_evidence.append(evidence)
            elif quality.get("u") is not False:
                raise ValueError("assessment quality current flag is invalid")

        determination_documents = document.get("determinations")
        if (not isinstance(determination_documents, list) or
                len(determination_documents) > self.max_history):
            raise ValueError("assessment determination history is invalid")
        determinations = []
        for item in determination_documents:
            if not isinstance(item, dict):
                raise ValueError("assessment determination is invalid")
            tested = item.get("tested")
            if not isinstance(tested, list) or len(tested) > self.max_evidence:
                raise ValueError("assessment tested probes are invalid")
            tested = [self._validated_text(
                value, "tested probe", self.STATE_MAX_IDENTIFIER)
                for value in tested]

            def restored_evidence(field):
                keys = item.get(field)
                if not isinstance(keys, list) or len(keys) > self.max_evidence:
                    raise ValueError("assessment determination qualities are invalid")
                return [self._evidence_for_key(
                    stored_origin, self._validated_key(key), quality_states,
                    self._validated_text(
                        item.get("completed_at"), "completion time",
                        self.STATE_MAX_TIMESTAMP)) for key in keys]

            cleared_values = item.get("cleared")
            if (not isinstance(cleared_values, list) or
                    len(cleared_values) > self.max_evidence):
                raise ValueError("assessment cleared qualities are invalid")
            cleared = [self._validated_key(key) for key in cleared_values]
            try:
                score = float(item.get("score"))
                threshold = float(item.get("threshold"))
            except (TypeError, ValueError):
                raise ValueError("assessment determination score is invalid")
            if not 0.0 <= score <= 1.0 or not 0.0 <= threshold <= 1.0:
                raise ValueError("assessment determination score is invalid")
            determinations.append(Determination(
                self._validated_text(
                    item.get("started_at"), "start time", self.STATE_MAX_TIMESTAMP),
                self._validated_text(
                    item.get("completed_at"), "completion time",
                    self.STATE_MAX_TIMESTAMP),
                tested, restored_evidence("qualities"), cleared, score, threshold,
                restored_evidence("matched"),
                self._restored_outcomes(item.get("outcomes")),
                self._restored_skipped(item.get("skipped"))))

        latest_cleared_values = document.get("latest_cleared")
        if (not isinstance(latest_cleared_values, list) or
                len(latest_cleared_values) > self.max_evidence):
            raise ValueError("assessment latest cleared qualities are invalid")
        assessment = OriginAssessment(
            stored_origin, current_evidence, quality_states=quality_states,
            determinations=determinations)
        assessment.latest_cleared_quality_keys = [
            self._validated_key(key) for key in latest_cleared_values]
        self.assessments[stored_origin] = assessment
        return assessment

    def _restored_outcomes(self, values):
        if not isinstance(values, list) or len(values) > self.max_evidence * 2:
            raise ValueError("assessment transport outcomes are invalid")
        outcomes = []
        for value in values:
            if not isinstance(value, dict):
                raise ValueError("assessment transport outcome is invalid")
            try:
                elapsed_ms = int(value.get("elapsed_ms"))
                status = int(value.get("status"))
            except (TypeError, ValueError):
                raise ValueError("assessment transport outcome is invalid")
            if elapsed_ms < 0 or status < 0 or status > 999:
                raise ValueError("assessment transport outcome is invalid")
            outcomes.append(ProbeOutcome(
                self._validated_text(
                    value.get("characteristic"), "outcome characteristic",
                    self.STATE_MAX_IDENTIFIER),
                self._validated_text(
                    value.get("state"), "connection state", 32),
                elapsed_ms, status,
                self._validated_text(
                    value.get("observed_at"), "outcome time",
                    self.STATE_MAX_TIMESTAMP)))
        return outcomes

    def _restored_skipped(self, values):
        if not isinstance(values, list) or len(values) > self.max_evidence:
            raise ValueError("assessment skipped probes are invalid")
        return [self._validated_text(
            value, "skipped probe", self.STATE_MAX_IDENTIFIER)
            for value in values]

    def discard_disabled(self, enabled_rules, enabled_probes):
        """Remove disabled qualities from current state but preserve history."""
        with self._lock:
            return self._discard_disabled(enabled_rules, enabled_probes)

    def _discard_disabled(self, enabled_rules, enabled_probes):
        enabled_rules = set(enabled_rules)
        enabled_probes = set(enabled_probes)
        for assessment in self.assessments.values():
            def enabled(key):
                return (key[0] in enabled_rules and
                        (not key[1] or key[1] in enabled_probes))

            assessment.evidence = [
                item for item in assessment.evidence
                if enabled(self._quality_key(item))]
            assessment.quality_states = dict(
                (key, state) for key, state in assessment.quality_states.items()
                if enabled(key))
            assessment.latest_cleared_quality_keys = [
                key for key in assessment.latest_cleared_quality_keys
                if enabled(key)]

    @staticmethod
    def _quality_label(key):
        """Return a compact rule/probe label for issue audit records."""
        if key[1]:
            return _text(key[0]) + " [" + _text(key[1]) + "]"
        return _text(key[0])

    def _evidence_label(self, evidence):
        """Include classifications needed to interpret one quality."""
        label = self._quality_label(self._quality_key(evidence))
        if evidence.classification:
            label = "%s (%s)" % (label, evidence.classification)
        return label

    def determination_detail(self, origin, determination):
        """Render one immutable active determination as escaped HTML."""
        state = "WAF suspected" if determination.suspected else "No WAF indicators detected"
        lines = [
            "<p><b>Historical active determination</b></p>",
            "<p>Origin: %s<br>Started: %s<br>Completed: %s</p>" % (
                html_escape(str(origin), quote=True),
                html_escape(str(determination.started_at), quote=True),
                html_escape(str(determination.completed_at), quote=True)),
            "<p>Result: %s<br>Confidence: %.0f%% (threshold %.0f%%)</p>" % (
                html_escape(state), determination.score * 100,
                determination.threshold * 100),
        ]
        tested = determination.tested_characteristics
        lines.append("<p>Tested probes: %s</p>" % (
            ", ".join(html_escape(str(value), quote=True) for value in tested)
            if tested else "None"))
        products = sorted(set(item.product for item in determination.evidence
                              if item.product))
        actions = sorted(set(item.action for item in determination.evidence
                             if item.action))
        if products:
            lines.append("<p>Provider/edge signals: %s</p>" % html_escape(
                ", ".join(products), quote=True))
        if actions:
            lines.append("<p>Observed security actions: %s</p>" % html_escape(
                ", ".join(actions), quote=True))
        if determination.outcomes:
            outcomes = []
            for item in determination.outcomes:
                outcomes.append("<li>%s: %s, HTTP %d, %d ms at %s</li>" % (
                    html_escape(_text(item.characteristic), quote=True),
                    html_escape(_text(item.connection_state), quote=True),
                    item.status, item.elapsed_ms,
                    html_escape(_text(item.observed_at), quote=True)))
            lines.append("<p>Transport outcomes:</p><ul>%s</ul>" %
                         "".join(outcomes))
        if determination.skipped_characteristics:
            lines.append("<p>Skipped probes: %s</p>" % html_escape(
                ", ".join(determination.skipped_characteristics), quote=True))
        matched = ["%s at %s" % (
            self._evidence_label(item), item.observed_at)
            for item in determination.matched_evidence]
        lines.append("<p>Qualities matched in this batch: %s</p>" % (
            ", ".join(html_escape(value, quote=True) for value in matched)
            if matched else "None"))
        cleared = [self._quality_label(key)
                   for key in determination.cleared_quality_keys]
        lines.append("<p>Qualities cleared by this batch: %s</p>" % (
            ", ".join(html_escape(value, quote=True) for value in cleared)
            if cleared else "None"))
        current = ["%s (last confirmed %s)" % (
            self._evidence_label(item), item.observed_at)
            for item in determination.evidence]
        lines.append("<p>Current qualities producing this result: %s</p>" % (
            ", ".join(html_escape(value, quote=True) for value in current)
            if current else "None"))
        return "".join(lines)

    def detail(self, origin):
        with self._lock:
            return self._detail(origin)

    def _detail(self, origin):
        assessment = self.assessments.get(origin, OriginAssessment(origin))
        score, products = self.engine.score(assessment.evidence)
        product_names = sorted(products, key=lambda product: products[product], reverse=True)
        state = "WAF suspected" if score >= self.engine.threshold else "No WAF indicators detected"
        # Every value that can originate in HTTP traffic is escaped before it
        # reaches Burp's HTML issue renderer.
        safe_origin = html_escape(str(origin), quote=True)
        last_checked = (assessment.determinations[-1].completed_at
                        if assessment.determinations else "")
        if not last_checked and assessment.quality_states:
            last_checked = max(
                state.last_confirmed_at
                for state in assessment.quality_states.values())
        lines = ["<p><b>%s</b></p>" % html_escape(state),
                 "<p>Origin: %s<br>Confidence: %.0f%% (threshold %.0f%%)%s</p>" %
                 (safe_origin, score * 100, self.engine.threshold * 100,
                  ("<br>Last checked: %s" % html_escape(
                      str(last_checked), quote=True)) if last_checked else "")]
        if product_names:
            lines.append("<p>Edge/provider signals: %s</p>" % ", ".join(
                html_escape(str(product), quote=True) for product in product_names))
        actions = sorted(set(item.action for item in assessment.evidence if item.action))
        if actions:
            lines.append("<p>Observed security actions: %s</p>" % ", ".join(
                html_escape(str(action), quote=True) for action in actions))
        if assessment.evidence:
            rendered = []
            for item in assessment.evidence:
                quality_state = assessment.quality_states.get(
                    self._quality_key(item))
                lifecycle = ""
                if quality_state is not None:
                    lifecycle = " (first detected %s; last confirmed %s)" % (
                        html_escape(str(quality_state.first_detected_at), quote=True),
                        html_escape(str(quality_state.last_confirmed_at), quote=True))
                rendered.append("<li>%s%s%s: %s%s</li>" % (
                    html_escape(str(item.rule_id), quote=True),
                    (" [%s]" % html_escape(str(item.characteristic), quote=True))
                    if item.characteristic else "",
                    (" (%s)" % html_escape(str(item.classification), quote=True))
                    if item.classification else "",
                    html_escape(str(item.detail), quote=True), lifecycle))
            lines.append("<p>Current qualities:</p><ul>%s</ul>" % "".join(rendered))
        else:
            lines.append("<p>No distinct detection rules have matched yet.</p>")

        if assessment.latest_cleared_quality_keys:
            cleared = []
            for key in assessment.latest_cleared_quality_keys:
                quality_state = assessment.quality_states.get(key)
                cleared_at = quality_state.cleared_at if quality_state is not None else ""
                cleared.append("<li>%s%s</li>" % (
                    html_escape(self._quality_label(key), quote=True),
                    (" at %s" % html_escape(str(cleared_at), quote=True))
                    if cleared_at else ""))
            lines.append("<p>Qualities cleared by the latest re-check:</p><ul>%s</ul>" %
                         "".join(cleared))

        if assessment.determinations:
            summaries = []
            for determination in reversed(assessment.determinations):
                verdict = "WAF suspected" if determination.suspected else "No WAF indicators"
                matched = [self._quality_label(self._quality_key(item))
                           for item in determination.matched_evidence]
                summaries.append("<li>%s: %s, %.0f%%; matched %s</li>" % (
                    html_escape(str(determination.completed_at), quote=True),
                    html_escape(verdict), determination.score * 100,
                    html_escape(", ".join(matched) if matched else "none", quote=True)))
            lines.append("<p>Recent active determinations:</p><ul>%s</ul>" %
                         "".join(summaries))
        # This compact marker makes reload recovery possible without retaining
        # complete request bodies or serialising arbitrary Python objects.
        marker = json.dumps(sorted(
            _text(item.rule_id) + ":" + _text(item.characteristic)
            if item.characteristic else _text(item.rule_id)
            for item in assessment.evidence),
                            separators=(",", ":"))
        lines.append("<p>Evidence IDs: %s</p>" % html_escape(marker, quote=True))
        state_marker = self.state_marker(origin)
        if state_marker:
            lines.append(state_marker)
        return "".join(lines)

    def current_issue_snapshot(self, origin):
        """Return representative, score and detail from one consistent state."""
        with self._lock:
            assessment = self.assessments[origin]
            score = self.engine.score(assessment.evidence)[0]
            return assessment.representative_message, score, self._detail(origin)
