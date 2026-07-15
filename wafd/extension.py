"""Small Burp adapter around the testable WAF detection components."""

import json
import os
import re

from .assessment import AssessmentStore
from .config import Configuration
from .detector import ResponseDetector
from .fingerprint import build_fingerprint
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
        self.probes = None
        self.configuration = Configuration()
        self._panel = None

    def registerExtenderCallbacks(self, callbacks):
        """Burp entry point; registration failures are reported to Burp output."""
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp WAF Detector")
        self.catalogue = self._load_default_catalogue()
        self._load_configuration()
        # The adapter owns Burp objects; the detector, scorer and planner stay
        # independent so their behaviour can be tested under CPython.
        self.detector = ResponseDetector(self.catalogue)
        self.assessments = AssessmentStore(self.catalogue.rules, self.configuration.threshold)
        # Non-GET probe profiles are permitted only when their catalogue entry
        # explicitly allows the method; the target policy controls the path.
        self.probes = ProbePlanner(self.configuration.max_probes)
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        callbacks.printOutput("Burp WAF Detector loaded with %d rules" % len(self.catalogue.rules))

    def _load_default_catalogue(self):
        path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            "data", "default_rules.json")
        with open(path, "r") as source:
            return RuleCatalogue.from_json(source.read())

    def _load_configuration(self):
        saved = self.callbacks.loadExtensionSetting("configuration")
        if saved:
            try:
                self.configuration = Configuration.from_json(saved)
            except (ValueError, TypeError):
                # Continue with validated defaults instead of preventing the
                # extension from loading because a saved setting is stale.
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
                    # Rule enablement is deliberately user-selectable because
                    # fingerprints and acceptable false-positive rates vary by
                    # engagement.
                    checkbox = JCheckBox("%s [%s] (weight %.0f)" %
                                         (rule.name, rule.rule_id, rule.weight), rule.enabled)
                    checkboxes.append((rule, checkbox))
                    rules_panel.add(checkbox)
                self._panel.add(JScrollPane(rules_panel), BorderLayout.CENTER)
                save = JButton("Save settings")
                def save_settings(event):
                    # Validate the complete editable state before persisting
                    # it; a malformed threshold leaves current settings intact.
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
        # Burp exposes headers as name/value objects. Normalising names here
        # gives the core detector one predictable, case-insensitive contract.
        headers = {}
        for header in response_info.getHeaders():
            name = str(header.getName()).lower()
            headers[name] = str(header.getValue())
        body = raw_response[response_info.getBodyOffset():]
        if not isinstance(body, str):
            body = body.decode("utf-8", "replace")
        first_line = raw_response.splitlines()[0] if raw_response.splitlines() else ""
        # Preserve HTTP/1.0, HTTP/1.1 and HTTP/2 for protocol-differential
        # rules without relying on Burp-specific response objects downstream.
        match = re.match(r"HTTP/(\d(?:\.\d)?)", str(first_line))
        return build_fingerprint(response_info.getStatusCode(), headers, body[:1024 * 1024],
                                 match.group(1) if match else "")

    @staticmethod
    def _origin(url):
        protocol = str(url.getProtocol()).lower()
        host = str(url.getHost()).lower()
        port = int(url.getPort())
        if port < 0:
            # Explicit ports keep assessments for different services separate,
            # including when java.net.URL omits the scheme's default port.
            port = 443 if protocol == "https" else 80
        return "%s://%s:%d" % (protocol, host, port)

    def _publish_issue(self, origin):
        """Publish a replaceable current assessment for one origin."""
        assessment = self.assessments.assessments[origin]
        score = self.assessments.engine.score(assessment.evidence)[0]
        confidence = "Certain" if score >= 0.85 else ("Firm" if score >= 0.60 else "Tentative")
        # Burp replaces earlier issues with the same identity via
        # consolidateDuplicateIssues(), leaving one current assessment.
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
            probe_entries = self.probes.plan_entries(request_info.getMethod(), name)
            method = str(request_info.getMethod()).upper()
            root_mode = (method not in ("GET", "HEAD", "OPTIONS") and
                         self.configuration.non_get_target == "root")
            control = baseRequestResponse
            root_headers = list(request_info.getHeaders())
            if root_mode:
                # By default, non-GET probes target / rather than replaying a
                # selected application action. The method is retained, while
                # the body is replaced with the configured probe marker.
                root_headers[0] = "%s / HTTP/1.1" % method
                control_request = self.helpers.buildHttpMessage(root_headers, "")
                control = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), control_request)
                if control is None or control.getResponse() is None:
                    # Falling back preserves scan availability, but means the
                    # selected response is the control for this comparison.
                    control = baseRequestResponse
            results = []
            for probe in probe_entries:
                if root_mode:
                    request = self.helpers.buildHttpMessage(root_headers, probe.value.encode("utf-8"))
                else:
                    request = insertionPoint.buildRequest(probe.value.encode("utf-8"))
                request = self._apply_probe_profile(request, probe.profile)
                response = self.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request)
                if response is None or response.getResponse() is None:
                    # A reset/no-response outcome is itself behavioural
                    # evidence, but it must not be treated as HTTP status 0.
                    origin = self._origin(request_info.getUrl())
                    reset = {"status": 0, "headers": {}, "body": "",
                             "connection_state": "no-response"}
                    evidence = self.detector.detect(origin, reset, "active")
                    self.assessments.observe(origin, evidence, baseRequestResponse)
                    self._publish_issue(origin)
                    continue
                response_info = self.helpers.analyzeResponse(response.getResponse())
                normalised = self._normalise_response(response.getResponse(), response_info)
                baseline_info = self.helpers.analyzeResponse(control.getResponse())
                baseline = self._normalise_response(control.getResponse(), baseline_info)
                origin = self._origin(request_info.getUrl())
                evidence = self.detector.detect(origin, normalised, "active", baseline)
                self.assessments.observe(origin, evidence, response)
                self._publish_issue(origin)
                results.append(response)
            return []
        except Exception as error:
            self.callbacks.printError("WAF Detector active probe failed: %s" % error)
            return []

    def _apply_probe_profile(self, request, profile):
        """Apply only explicitly declared, non-authentication profile headers."""
        request_headers = profile.get("request_headers", {}) if profile else {}
        if profile and profile.get("accept"):
            request_headers = dict(request_headers)
            request_headers["Accept"] = profile["accept"]
        if not request_headers:
            return request
        info = self.helpers.analyzeRequest(request)
        headers = list(info.getHeaders())
        lowered = dict((str(key).lower(), value) for key, value in request_headers.items())
        updated = []
        seen = set()
        for header in headers:
            # Replace a declared header once while preserving all unrelated
            # request headers and the original body bytes.
            name = str(header).split(":", 1)[0].strip().lower()
            if name in lowered:
                updated.append("%s: %s" % (name, lowered[name]))
                seen.add(name)
            else:
                updated.append(str(header))
        for name, value in lowered.items():
            if name not in seen:
                updated.append("%s: %s" % (name, value))
        body = request[info.getBodyOffset():]
        return self.helpers.buildHttpMessage(updated, body)

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
                    # Parse and rebuild the request line so the marker is added
                    # to the request target, never after the HTTP version.
                    headers = list(request_info.getHeaders())
                    encoded = extension.helpers.urlEncode(payload.decode("utf-8"))
                    headers[0] = extension._append_query_parameter(
                        headers[0], "wafd_probe", encoded)
                    body = message.getRequest()[request_info.getBodyOffset():]
                    return extension.helpers.buildHttpMessage(headers, body)
            self.doActiveScan(message, SelectedPoint())
        except Exception as error:
            self.callbacks.printError("WAF Detector context probe failed: %s" % error)

    @staticmethod
    def _append_query_parameter(request_line, name, encoded_value):
        """Append an encoded query parameter to a valid HTTP request target."""
        # Split only between the three request-line components and normalise
        # their separators when rebuilding the line.
        parts = str(request_line).split(None, 2)
        if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
            raise ValueError("request line must contain method, target and HTTP version")
        method, target, version = parts
        if target == "*" or method.upper() == "CONNECT":
            raise ValueError("request-target form does not support query parameters")
        if not version.upper().startswith("HTTP/"):
            raise ValueError("request line must end with an HTTP version")

        # Fragments are not normally present in HTTP request targets, but if a
        # client supplies one, keep it after the newly added query parameter.
        target_and_query, marker, fragment = target.partition("#")
        if target_and_query.endswith(("?", "&")):
            separator = ""
        else:
            separator = "&" if "?" in target_and_query else "?"
        updated_target = "%s%s%s=%s" % (
            target_and_query, separator, str(name), str(encoded_value))
        if marker:
            updated_target = "%s#%s" % (updated_target, fragment)
        return "%s %s %s" % (method, updated_target, version)
