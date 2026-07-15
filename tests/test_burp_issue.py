import unittest

from wafd.burp_issue import WafScanIssue


class WafScanIssueTests(unittest.TestCase):
    def test_exposes_complete_legacy_issue_contract(self):
        url = object()
        service = object()
        message = object()
        issue = WafScanIssue(url, service, "detail", "remediation",
                             "Information", "Firm", [message])

        self.assertIs(issue.getUrl(), url)
        self.assertIs(issue.getHttpService(), service)
        self.assertEqual(issue.getIssueName(), "WAF Detector: current assessment")
        self.assertEqual(issue.getIssueType(), 0)
        self.assertEqual(issue.getSeverity(), "Information")
        self.assertEqual(issue.getConfidence(), "Firm")
        self.assertEqual(issue.getIssueDetail(), "detail")
        self.assertEqual(issue.getRemediationDetail(), "remediation")
        self.assertEqual(issue.getHttpMessages(), [message])
        self.assertIsNone(issue.getIssueBackground())
        self.assertIsNone(issue.getRemediationBackground())


if __name__ == "__main__":
    unittest.main()
