"""Small Burp adapter around the testable WAF detection components."""

import json
import os

from .assessment import AssessmentStore
from .config import Configuration
from .detector import ResponseDetector
from .probes import ProbePlanner
from .rules import RuleCatalogue


class WafExtension(object):
    """Register the extension without importing Burp classes at module load."""

    def __init__(self):
        self.callbacks = None
        self.helpers = None
        self.catalogue = None
        self.detector = None
        self.assessments = None
        self.probes = ProbePlanner()
        self.configuration = Configuration()
        self._panel = None

    def registerExtenderCallbacks(self, callbacks):
        """Burp entry point; registration failures are reported to Burp output."""
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp WAF Detector")
        self.catalogue = self._load_default_catalogue()
        self._load_configuration()
        self.detector = ResponseDetector(self.catalogue)
        self.assessments = AssessmentStore(self.catalogue.rules, self.configuration.threshold)
        self.probes = ProbePlanner(self.configuration.max_probes)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Burp WAF Detector loaded with %d rules" % len(self.catalogue.rules))

    def _load_default_catalogue(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            "rules", "default_rules.json")
        with open(path, "r") as source:
            return RuleCatalogue.from_json(source.read())

    def _load_configuration(self):
        saved = self.callbacks.loadExtensionSetting("configuration")
        if saved:
            try:
                self.configuration = Configuration.from_json(saved)
            except (ValueError, TypeError):
                self.callbacks.printError("WAF Detector ignored invalid saved configuration")

    def save_configuration(self):
        self.callbacks.saveExtensionSetting("configuration", self.configuration.to_json())

    # IExtensionTab -----------------------------------------------------
    def getTabCaption(self):
        return "WAF Detector"

    def getUiComponent(self):
        if self._panel is None:
            try:
                from java.awt import BorderLayout, GridLayout
                from javax.swing import (BorderFactory, JButton, JCheckBox, JLabel,
                                         JPanel, JScrollPane, JTextField)
                self._panel = JPanel()
                self._panel.setLayout(BorderLayout())
                heading = JPanel(GridLayout(0, 2))
                heading.add(JLabel("Passive monitoring"))
                enabled = JCheckBox("Enabled", self.configuration.enabled)
                heading.add(enabled)
                heading.add(JLabel("WAF confidence threshold (0-1)"))
                threshold = JTextField(str(self.configuration.threshold))
                heading.add(threshold)
                self._panel.add(heading, BorderLayout.NORTH)

                rules_panel = JPanel()
                rules_panel.setLayout(GridLayout(0, 1))
                rules_panel.setBorder(BorderFactory.createTitledBorder("Detection rules"))
                checkboxes = []
                for rule in self.catalogue.rules:
                    checkbox = JCheckBox("%s [%s] (weight %.0f)" %
                                         (rule.name, rule.rule_id, rule.weight), rule.enabled)
                    checkboxes.append((rule, checkbox))
                    rules_panel.add(checkbox)
                self._panel.add(JScrollPane(rules_panel), BorderLayout.CENTER)
                save = JButton("Save settings")
                def save_settings(event):
                    try:
                        self.configuration.threshold = self.configuration._threshold(threshold.getText())
                        self.configuration.enabled = enabled.isSelected()
                        for rule, checkbox in checkboxes:
                            rule.enabled = checkbox.isSelected()
                        self.assessments.engine.threshold = self.configuration.threshold
                        self.save_configuration()
                    except (ValueError, TypeError) as error:
                        self.callbacks.printError("WAF Detector settings not saved: %s" % error)
                save.addActionListener(save_settings)
                self._panel.add(save, BorderLayout.SOUTH)
            except ImportError:  # Allows the adapter to be imported by tests.
                self._panel = object()
        return self._panel

    # IHttpListener ----------------------------------------------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Analyse responses only, bounded to Burp's configured scope."""
        if (not self.configuration.enabled or messageIsRequest or
                self._is_extension_traffic(toolFlag)):
            return
        try:
            request = self.helpers.analyzeRequest(messageInfo)
            url = request.getUrl()
            if self.configuration.in_scope_only and not self.callbacks.isInScope(url):
                return
            response_info = self.helpers.analyzeResponse(messageInfo.getResponse())
            response = self._normalise_response(messageInfo.getResponse(), response_info)
            origin = self._origin(url)
            evidence = self.detector.detect(origin, response)
            self.assessments.observe(origin, evidence, messageInfo)
            self._publish_issue(origin)
        except Exception as error:
            # A malformed message must not disrupt Burp's traffic processing.
            self.callbacks.printError("WAF Detector passive analysis failed: %s" % error)

    def _is_extension_traffic(self, tool_flag):
        return getattr(self.callbacks, "TOOL_EXTENDER", object()) == tool_flag

    def _normalise_response(self, raw_response, response_info):
        headers = {}
        for header in response_info.getHeaders():
            name = str(header.getName()).lower()
            headers[name] = str(header.getValue())
        body = raw_response[response_info.getBodyOffset():]
        if not isinstance(body, str):
            body = body.decode("utf-8", "replace")
        return {"status": response_info.getStatusCode(),
                "headers": headers, "body": body[:1024 * 1024]}

    @staticmethod
    def _origin(url):
        protocol = str(url.getProtocol()).lower()
        host = str(url.getHost()).lower()
        port = int(url.getPort())
        if port < 0:
            port = 443 if protocol == "https" else 80
        return "%s://%s:%d" % (protocol, host, port)

    def _publish_issue(self, origin):
        """Publish a replaceable current assessment for one origin."""
        assessment = self.assessments.assessments[origin]
        score = self.assessments.engine.score(assessment.evidence)[0]
        confidence = "Certain" if score >= 0.85 else ("Firm" if score >= 0.60 else "Tentative")
        issue = self.callbacks.makeScannerIssue(
            origin, "WAF Detector: current assessment", self.assessments.detail(origin),
            "Continue monitoring traffic and validate the suspected product manually.",
            "Information", confidence, [assessment.representative_message] if assessment.representative_message else [])
        self.callbacks.addScanIssue(issue)

    # IScannerCheck ----------------------------------------------------
    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Run a capped safe probe set for Scanner insertion points."""
        try:
            request_info = self.helpers.analyzeRequest(baseRequestResponse)
            name = insertionPoint.getInsertionPointName()
            payloads = self.probes.plan(request_info.getMethod(), name)
            results = []
            for payload in payloads:
                request = insertionPoint.buildRequest(payload.encode("utf-8"))
                response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request)
                if response is None or response.getResponse() is None:
                    continue
                response_info = self.helpers.analyzeResponse(response.getResponse())
                normalised = self._normalise_response(response.getResponse(), response_info)
                baseline_info = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
                baseline = self._normalise_response(baseRequestResponse.getResponse(), baseline_info)
                origin = self._origin(request_info.getUrl())
                evidence = self.detector.detect(origin, normalised, "active", baseline)
                self.assessments.observe(origin, evidence, response)
                self._publish_issue(origin)
                results.append(response)
            return []
        except Exception as error:
            self.callbacks.printError("WAF Detector active probe failed: %s" % error)
            return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # A new assessment contains the current evidence and supersedes the old.
        return 1

    # IContextMenuFactory ----------------------------------------------
    def createMenuItems(self, invocation):
        try:
            from javax.swing import JMenuItem
            messages = invocation.getSelectedMessages()
            if not messages:
                return []
            item = JMenuItem("Probe for WAF")
            item.addActionListener(lambda event: self._probe_selected(messages[0]))
            return [item]
        except ImportError:
            return []

    def _probe_selected(self, message):
        """Context-menu entry point; intentionally reuses Scanner behaviour."""
        try:
            request_info = self.helpers.analyzeRequest(message)
            extension = self
            class SelectedPoint(object):
                def getInsertionPointName(inner):
                    return "query"
                def buildRequest(inner, payload):
                    return extension.helpers.buildHttpMessage(request_info.getHeaders(), payload)
            self.doActiveScan(message, SelectedPoint())
        except Exception as error:
            self.callbacks.printError("WAF Detector context probe failed: %s" % error)
