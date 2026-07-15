"""Tests for Burp-independent UI filtering and bulk-selection behaviour."""

from pathlib import Path
import unittest

from wafd.extension import WafExtension
from wafd.models import Rule
from wafd.probes import Probe, ProbeCatalogue
from wafd.rules import RuleCatalogue


class _Checkbox(object):
    """Minimal Swing checkbox substitute used by UI helper tests."""

    def __init__(self, selected=False):
        self.visible = True
        self.selected = selected

    def setVisible(self, visible):
        self.visible = bool(visible)

    def isVisible(self):
        return self.visible

    def setSelected(self, selected):
        self.selected = bool(selected)


class CatalogueFilterTests(unittest.TestCase):
    def test_non_get_target_display_labels_round_trip_to_saved_values(self):
        root_label = WafExtension._non_get_target_label("root")
        selected_label = WafExtension._non_get_target_label("selected")

        self.assertEqual("Root path (/)", root_label)
        self.assertEqual("Selected request path", selected_label)
        self.assertEqual("root", WafExtension._non_get_target_value(root_label))
        self.assertEqual("selected", WafExtension._non_get_target_value(selected_label))
        with self.assertRaises(ValueError):
            WafExtension._non_get_target_value("unclear option")

    def test_tab_content_column_has_a_readable_maximum_width(self):
        self.assertEqual(960, WafExtension._tab_content_width())

    def test_tab_content_width_caps_wide_content_and_preserves_narrow_content(self):
        self.assertEqual(640, WafExtension._tab_content_width(640))
        self.assertEqual(960, WafExtension._tab_content_width(1920))
        self.assertEqual(0, WafExtension._tab_content_width(-1))

    def test_rules_are_grouped_by_provider_or_generic_behaviour(self):
        cloudflare = Rule("cf", "Cloudflare", "edge", 10,
                          ("cloudflare", "product"))
        generic = Rule("status", "Status", "status", 5, ("generic",))

        self.assertEqual("Cloudflare", WafExtension._rule_group(cloudflare))
        self.assertEqual(
            "Generic behavioural rules", WafExtension._rule_group(generic))

    def test_probes_are_grouped_by_function_and_provider_profile(self):
        sql = Probe("marker", (), (), "matrix.sqli.boolean.query", "SQL")
        multipart = Probe(
            "marker", (), (), "matrix.multipart.xss-marker.field", "Multipart")
        provider = Probe(
            "marker", ("cloudflare",), (), "cloudflare.challenge-profile", "Cloudflare")

        self.assertEqual("SQL injection", WafExtension._probe_group(sql))
        self.assertEqual(
            "Multipart, cookies and headers", WafExtension._probe_group(multipart))
        self.assertEqual(
            "Provider-specific profiles", WafExtension._probe_group(provider))

    def test_matrix_provider_associations_do_not_override_functional_group(self):
        probe = Probe(
            "marker", ("cloudflare", "aws-waf"), ("block",),
            "matrix.sqli.boolean.query", "SQL associated with providers")

        self.assertEqual("SQL injection", WafExtension._probe_group(probe))

    def test_grouped_rows_follow_declared_order_and_preserve_every_row(self):
        rows = [
            (Probe("x", ("cloudflare",), (), "cloudflare.profile", "Provider"),
             _Checkbox()),
            (Probe("x", (), (), "matrix.xss.script.query", "XSS"), _Checkbox()),
            (Probe("x", (), (), "matrix.sqli.boolean.query", "SQL"), _Checkbox()),
        ]

        grouped = WafExtension._group_catalogue_rows(
            rows, WafExtension._probe_group, WafExtension.PROBE_GROUP_ORDER)

        self.assertEqual(
            ["SQL injection", "Cross-site scripting", "Provider-specific profiles"],
            [label for label, unused_rows in grouped])
        self.assertEqual(3, sum(len(group_rows) for unused_label, group_rows in grouped))

    def test_bundled_catalogues_have_no_uncategorised_entries(self):
        project_root = Path(__file__).resolve().parents[1]
        rules = RuleCatalogue.from_json(
            (project_root / "data" / "default_rules.json").read_text()).rules
        probes = ProbeCatalogue.bundled().probes

        rule_groups = [WafExtension._rule_group(rule) for rule in rules]
        probe_groups = [WafExtension._probe_group(probe) for probe in probes]

        self.assertEqual(41, len(rule_groups))
        self.assertEqual(213, len(probe_groups))
        self.assertNotIn("Other rules", rule_groups)
        self.assertNotIn("Other generic probes", probe_groups)

    def test_filter_requires_every_case_insensitive_search_term(self):
        values = ("Cloudflare challenge", "cloudflare.challenge", "CF-Mitigated")

        self.assertTrue(WafExtension._matches_catalogue_filter(
            values, "CLOUDFLARE mitigated"))
        self.assertFalse(WafExtension._matches_catalogue_filter(
            values, "cloudflare captcha"))
        self.assertTrue(WafExtension._matches_catalogue_filter(values, "  "))

    def test_rule_search_values_include_metadata(self):
        rule = Rule("aws.captcha", "AWS CAPTCHA", "aws-action", 100,
                    ("aws-waf", "captcha", "generic"))

        values = WafExtension._rule_search_values(rule)

        self.assertIn("aws.captcha", values)
        self.assertIn("aws-action", values)
        self.assertIn("aws-waf", values)

    def test_probe_search_values_include_request_and_provider_metadata(self):
        probe = Probe("marker", ("azure-front-door",), ("block",),
                      "azure.xss.query", "Azure XSS", safe_methods=("GET",),
                      profile={"method": "GET", "placement": "query",
                               "content_type": "application/json"})

        values = WafExtension._probe_search_values(probe)

        self.assertIn("azure-front-door", values)
        self.assertIn("block", values)
        self.assertIn("GET", values)
        self.assertIn("query", values)
        self.assertIn("application/json", values)

    def test_row_filter_updates_visibility_and_returns_visible_count(self):
        cloudflare = Rule("cf", "Cloudflare", "edge", 10, ("cloudflare",))
        aws = Rule("aws", "AWS", "edge", 10, ("aws-waf",))
        cloudflare_checkbox = _Checkbox()
        aws_checkbox = _Checkbox()
        rows = [(cloudflare, cloudflare_checkbox), (aws, aws_checkbox)]

        visible = WafExtension._filter_catalogue_rows(
            rows, "cloudflare", WafExtension._rule_search_values)

        self.assertEqual(1, visible)
        self.assertTrue(cloudflare_checkbox.visible)
        self.assertFalse(aws_checkbox.visible)

    def test_bulk_selection_changes_visible_rows_only(self):
        visible = _Checkbox(False)
        hidden = _Checkbox(False)
        hidden.setVisible(False)
        rows = [(object(), visible), (object(), hidden)]

        changed = WafExtension._set_visible_catalogue_rows(rows, True)

        self.assertEqual(1, changed)
        self.assertTrue(visible.selected)
        self.assertFalse(hidden.selected)


if __name__ == "__main__":
    unittest.main()
