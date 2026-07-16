import base64
import json
import unittest

from wafd.assessment import AssessmentStore
from wafd.models import Evidence, ProbeOutcome, Rule


class AssessmentTests(unittest.TestCase):
    def test_observation_tracks_first_detection_and_latest_confirmation(self):
        store = AssessmentStore(
            [Rule("r", "Rule", "g", 10)], clock=lambda: "unused")
        first = Evidence("r", "https://x", "first")
        latest = Evidence("r", "https://x", "latest")

        store.observe("https://x", [first], observed_at="2026-01-01T00:00:00Z")
        store.observe("https://x", [latest], observed_at="2026-01-02T00:00:00Z")

        assessment = store.assessments["https://x"]
        state = assessment.quality_states[("r", "")]
        self.assertEqual(state.first_detected_at, "2026-01-01T00:00:00Z")
        self.assertEqual(state.last_confirmed_at, "2026-01-02T00:00:00Z")
        self.assertEqual(assessment.evidence[0].detail, "latest")

    def test_active_recheck_clears_only_tested_probe_qualities(self):
        rules = [Rule("passive", "Passive", "p", 20),
                 Rule("active", "Active", "a", 60)]
        store = AssessmentStore(rules, clock=lambda: "unused")
        store.observe("https://x", [
            Evidence("passive", "https://x", "header"),
            Evidence("active", "https://x", "one", source="active",
                     characteristic="probe.one"),
            Evidence("active", "https://x", "two", source="active",
                     characteristic="probe.two"),
        ], observed_at="2026-01-01T00:00:00Z")

        assessment, determination = store.reconcile_active(
            "https://x", ["probe.one"], [],
            started_at="2026-01-02T00:00:00Z",
            completed_at="2026-01-02T00:01:00Z")

        self.assertEqual(
            [(item.rule_id, item.characteristic) for item in assessment.evidence],
            [("passive", ""), ("active", "probe.two")])
        self.assertEqual(
            determination.cleared_quality_keys,
            (("active", "probe.one"),))
        self.assertEqual(
            assessment.quality_states[("active", "probe.one")].cleared_at,
            "2026-01-02T00:01:00Z")

    def test_active_recheck_unions_repeated_matches_and_bounds_history(self):
        rules = [Rule("a", "A", "a", 60), Rule("b", "B", "b", 10)]
        store = AssessmentStore(rules, max_history=2, clock=lambda: "unused")
        repeated = [
            Evidence("a", "https://x", "first", source="active",
                     characteristic="probe"),
            Evidence("a", "https://x", "latest", source="active",
                     characteristic="probe"),
            Evidence("b", "https://x", "second", source="active",
                     characteristic="probe"),
        ]

        for index in range(3):
            assessment, determination = store.reconcile_active(
                "https://x", ["probe"], repeated,
                started_at="start-%d" % index,
                completed_at="end-%d" % index)

        self.assertEqual(len(assessment.determinations), 2)
        self.assertEqual(
            [item.rule_id for item in determination.evidence], ["a", "b"])
        self.assertEqual(
            [item.detail for item in assessment.evidence], ["latest", "second"])
        self.assertTrue(determination.suspected)

    def test_current_detail_renders_lifecycle_and_recent_determinations(self):
        store = AssessmentStore([Rule("r", "Rule", "g", 60)],
                                clock=lambda: "unused")
        store.reconcile_active(
            "https://x", ["probe"], [
                Evidence("r", "https://x", "matched", source="active",
                         characteristic="probe",
                         observed_at="2026-01-01T00:00:30Z")],
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:01:00Z")

        detail = store.detail("https://x")

        self.assertIn("Last checked: 2026-01-01T00:01:00Z", detail)
        self.assertIn("first detected 2026-01-01T00:00:30Z", detail)
        self.assertIn("Recent active determinations", detail)
        self.assertIn(store.STATE_PREFIX, detail)

    def test_versioned_state_round_trip_restores_current_and_history(self):
        rules = [Rule("passive", "Passive", "p", 20),
                 Rule("active", "Active", "a", 60)]
        original = AssessmentStore(rules, clock=lambda: "unused")
        original.observe(
            "https://x", [Evidence("passive", "https://x", "header")],
            observed_at="2026-01-01T00:00:00Z")
        original.reconcile_active(
            "https://x", ["probe"], [
                Evidence("active", "https://x", "blocked", source="active",
                         characteristic="probe",
                         observed_at="2026-01-02T00:00:30Z")],
            started_at="2026-01-02T00:00:00Z",
            completed_at="2026-01-02T00:01:00Z",
            outcomes=[ProbeOutcome(
                "probe", "complete", 25, 403,
                "2026-01-02T00:00:30Z")],
            skipped_characteristics=["skipped-probe"])
        detail = original.detail("https://x")
        payload = original._state_payload(detail)
        self.assertNotIn("detail", payload["qualities"][0])

        restored = AssessmentStore(rules, clock=lambda: "unused")
        assessment = restored.restore("https://x", detail)

        self.assertEqual(
            [(item.rule_id, item.characteristic) for item in assessment.evidence],
            [("active", "probe"), ("passive", "")])
        state = assessment.quality_states[("active", "probe")]
        self.assertEqual(state.first_detected_at, "2026-01-02T00:00:30Z")
        self.assertEqual(len(assessment.determinations), 1)
        self.assertEqual(
            assessment.determinations[0].tested_characteristics, ("probe",))
        self.assertEqual(
            assessment.determinations[0].outcomes[0].status, 403)
        self.assertEqual(
            assessment.determinations[0].skipped_characteristics,
            ("skipped-probe",))

    def test_state_restore_rejects_mismatched_unknown_and_oversized_data(self):
        store = AssessmentStore([Rule("r", "Rule", "g", 10)])
        store.observe("https://x", [Evidence("r", "https://x", "matched")])
        detail = store.detail("https://x")
        with self.assertRaises(ValueError):
            AssessmentStore([Rule("r", "Rule", "g", 10)]).restore(
                "https://different", detail)

        unknown = {
            "version": 99, "origin": "https://x", "qualities": [],
            "latest_cleared": [], "determinations": []}
        encoded = base64.b64encode(
            json.dumps(unknown).encode("utf-8")).decode("ascii")
        with self.assertRaises(ValueError):
            AssessmentStore([Rule("r", "Rule", "g", 10)]).restore(
                "https://x", "%s%s%s" % (
                    store.STATE_PREFIX, encoded, store.STATE_SUFFIX))

        oversized = "%s%s%s" % (
            store.STATE_PREFIX,
            "A" * ((store.STATE_MAX_BYTES * 4 // 3) + 9),
            store.STATE_SUFFIX)
        with self.assertRaises(ValueError):
            AssessmentStore([Rule("r", "Rule", "g", 10)]).restore(
                "https://x", oversized)

    def test_default_detail_is_present_before_evidence(self):
        store = AssessmentStore([Rule("r", "Rule", "g", 10)])
        detail = store.detail("https://example.test:443")
        self.assertIn("No WAF indicators detected", detail)
        self.assertIn("Evidence IDs: []", detail)

    def test_detail_promotes_at_threshold_and_lists_evidence(self):
        rules = [Rule("a", "A", "a", 60), Rule("b", "B", "b", 40)]
        store = AssessmentStore(rules)
        store.observe("https://x", [Evidence("a", "https://x", "header", "cloudflare")])
        detail = store.detail("https://x")
        self.assertIn("WAF suspected", detail)
        self.assertIn("cloudflare", detail)
        self.assertIn("Evidence IDs: [&quot;a&quot;]", detail)

    def test_dynamic_evidence_is_html_escaped(self):
        store = AssessmentStore([Rule("r", "Rule", "g", 10)])
        store.observe("https://x", [Evidence("r", "https://x", "<script>alert(1)</script>")])
        detail = store.detail("https://x")
        self.assertNotIn("<script>", detail)
        self.assertIn("&lt;script&gt;", detail)

    def test_active_characteristics_are_retained_and_classified_separately(self):
        store = AssessmentStore([Rule("r", "Rule", "g", 10)])
        store.observe("https://x", [
            Evidence("r", "https://x", "first", characteristic="probe.one"),
            Evidence("r", "https://x", "second", characteristic="probe.two",
                     classification="malformed-request"),
        ])
        detail = store.detail("https://x")
        self.assertIn("probe.one", detail)
        self.assertIn("probe.two", detail)
        self.assertIn("malformed-request", detail)


if __name__ == "__main__":
    unittest.main()
