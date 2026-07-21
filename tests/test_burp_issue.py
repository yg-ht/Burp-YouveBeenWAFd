import importlib
import sys
import types
import unittest
from unittest import mock

from wafd.burp_issue import WafScanIssue


class WafScanIssueTests(unittest.TestCase):
    def test_issue_implements_burp_interface_when_available(self):
        # Burp accepts scanner issues through a typed Java callback.  Import a
        # fresh module against a stand-in interface to verify the Jython class
        # declaration without requiring Burp in the CPython test environment.
        burp_module = types.ModuleType("burp")
        issue_interface = type("IScanIssue", (object,), {})
        burp_module.IScanIssue = issue_interface
        previous_module = sys.modules.pop("wafd.burp_issue", None)
        try:
            with mock.patch.dict(sys.modules, {"burp": burp_module}):
                issue_module = importlib.import_module("wafd.burp_issue")

            self.assertTrue(issubclass(issue_module.WafScanIssue, issue_interface))
        finally:
            sys.modules.pop("wafd.burp_issue", None)
            if previous_module is not None:
                sys.modules["wafd.burp_issue"] = previous_module

    def test_exposes_complete_legacy_issue_contract(self):
        url = object()
        service = object()
        message = object()
        issue = WafScanIssue(url, service, "detail", "remediation",
                             "Information", "Firm", [message])

        self.assertIs(issue.getUrl(), url)
        self.assertIs(issue.getHttpService(), service)
        self.assertEqual(issue.getIssueName(), "WAF Detector: WAF suspected")
        self.assertEqual(issue.getIssueType(), 0)
        self.assertEqual(issue.getSeverity(), "Information")
        self.assertEqual(issue.getConfidence(), "Firm")
        self.assertEqual(issue.getIssueDetail(), "detail")
        self.assertEqual(issue.getRemediationDetail(), "remediation")
        self.assertEqual(issue.getHttpMessages(), [message])
        self.assertIsNone(issue.getIssueBackground())
        self.assertIsNone(issue.getRemediationBackground())

    def test_issue_name_and_private_type_can_identify_historical_records(self):
        issue = WafScanIssue(
            object(), object(), "detail", "remediation", "Information",
            "Firm", [], name="WAF Detector: probe determination",
            issue_type=7)

        self.assertEqual(issue.getIssueName(), "WAF Detector: probe determination")
        self.assertEqual(issue.getIssueType(), 7)


if __name__ == "__main__":
    unittest.main()
