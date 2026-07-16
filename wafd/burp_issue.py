"""Legacy Burp IScanIssue-compatible value object."""

try:
    from burp import IScanIssue
except ImportError:  # CPython test environment has no Burp Java API.
    class IScanIssue(object):
        """Fallback base allowing the dependency-free core tests to import."""


class WafScanIssue(IScanIssue):
    """Expose one current assessment through Burp's legacy issue interface."""

    def __init__(self, url, http_service, detail, remediation, severity,
                 confidence, messages,
                 name="WAF Detector: current assessment", issue_type=0):
        self._url = url
        self._http_service = http_service
        self._detail = detail
        self._remediation = remediation
        self._severity = severity
        self._confidence = confidence
        self._messages = list(messages or [])
        self._name = name
        self._issue_type = int(issue_type)

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        # Zero is appropriate for a private extension-defined issue type; the
        # stable name and URL drive duplicate consolidation.
        return self._issue_type

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._remediation

    def getHttpMessages(self):
        return self._messages

    def getHttpService(self):
        return self._http_service
