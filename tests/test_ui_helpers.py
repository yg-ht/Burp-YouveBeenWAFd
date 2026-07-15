"""Tests for Burp-independent UI filtering and bulk-selection behaviour."""

import unittest

from wafd.extension import WafExtension
from wafd.models import Rule
from wafd.probes import Probe


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
