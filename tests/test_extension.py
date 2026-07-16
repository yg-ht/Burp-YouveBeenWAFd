import sys
import types
import unittest
from unittest import mock

from wafd.assessment import AssessmentStore
from wafd.config import Configuration
from wafd.detector import ResponseDetector
from wafd.extension import WafExtension
from wafd.models import Evidence
from wafd.overrides import CatalogueOverrides
from wafd.probes import ProbeCatalogue, ProbePlanner
from wafd.rules import RuleCatalogue


class _Url(object):
    def getProtocol(self):
        return "https"

    def getHost(self):
        return "example.test"

    def getPort(self):
        return -1


class _RequestInfo(object):
    def __init__(self, raw):
        text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        head = text.split("\r\n\r\n", 1)[0]
        self.headers = head.split("\r\n")

    def getMethod(self):
        return self.headers[0].split(" ", 1)[0]

    def getHeaders(self):
        return self.headers

    def getBodyOffset(self):
        return len("\r\n".join(self.headers).encode("utf-8")) + 4

    def getUrl(self):
        return _Url()


class _ResponseInfo(object):
    def __init__(self, raw, headers=None):
        self.raw = raw
        self.headers = list(headers or [])

    def getHeaders(self):
        return self.headers

    def getBodyOffset(self):
        return self.raw.index(b"\r\n\r\n") + 4

    def getStatusCode(self):
        return int(self.raw.split(b" ", 2)[1])


class _Helpers(object):
    def analyzeRequest(self, message):
        raw = message.getRequest() if hasattr(message, "getRequest") else message
        return _RequestInfo(raw)

    def analyzeResponse(self, raw):
        return _ResponseInfo(raw)

    def buildHttpMessage(self, headers, body):
        body = body if isinstance(body, bytes) else str(body).encode("utf-8")
        return ("\r\n".join(str(header) for header in headers) + "\r\n\r\n").encode("utf-8") + body

    def bytesToString(self, value):
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


class _Message(object):
    def __init__(self, request, response=None):
        self.request = request
        self.response = response or b"HTTP/1.1 200 OK\r\n\r\nordinary"

    def getRequest(self):
        return self.request

    def getResponse(self):
        return self.response

    def getHttpService(self):
        return object()


class _Callbacks(object):
    def __init__(self):
        self.requests = []
        self.errors = []
        self.issues = []
        self.saved_messages = []
        self.persisted_message = None

    def makeHttpRequest(self, service, request):
        self.requests.append(request)
        return _Message(request, b"HTTP/1.1 403 Forbidden\r\n\r\nblocked")

    def addScanIssue(self, issue):
        self.issues.append(issue)

    def saveBuffersToTempFiles(self, message):
        self.saved_messages.append(message)
        return self.persisted_message if self.persisted_message is not None else message

    def printError(self, message):
        self.errors.append(message)


class ExtensionRequestLineTests(unittest.TestCase):
    """Exercise request-line handling without requiring Burp's Java runtime."""

    def test_context_parameter_is_inserted_before_http_version(self):
        request_line = WafExtension._append_query_parameter(
            "GET /search HTTP/1.1", "wafd_probe", "%3Cscript%3E")
        self.assertEqual(
            request_line,
            "GET /search?wafd_probe=%3Cscript%3E HTTP/1.1")

    def test_context_parameter_preserves_existing_query_and_fragment(self):
        request_line = WafExtension._append_query_parameter(
            "GET /search?q=ordinary#section HTTP/2", "wafd_probe", "marker")
        self.assertEqual(
            request_line,
            "GET /search?q=ordinary&wafd_probe=marker#section HTTP/2")

    def test_context_parameter_rejects_malformed_request_line(self):
        with self.assertRaises(ValueError):
            WafExtension._append_query_parameter("GET /search", "wafd_probe", "marker")

    def test_context_parameter_rejects_targets_without_query_components(self):
        with self.assertRaises(ValueError):
            WafExtension._append_query_parameter(
                "OPTIONS * HTTP/1.1", "wafd_probe", "marker")
        with self.assertRaises(ValueError):
            WafExtension._append_query_parameter(
                "CONNECT example.test:443 HTTP/1.1", "wafd_probe", "marker")

    def test_context_parameter_supports_absolute_form_targets(self):
        request_line = WafExtension._append_query_parameter(
            "GET https://example.test/search HTTP/1.1", "wafd_probe", "marker")
        self.assertEqual(
            request_line,
            "GET https://example.test/search?wafd_probe=marker HTTP/1.1")

    def test_ipv6_origin_uses_bracketed_authority(self):
        class _Ipv6Url(_Url):
            def getHost(self):
                return "2001:db8::1"

        self.assertEqual(WafExtension._origin(_Ipv6Url()),
                         "https://[2001:db8::1]:443")


class ExtensionActiveAdapterTests(unittest.TestCase):
    def test_context_menu_action_schedules_instead_of_probing_inline(self):
        class _MenuItem(object):
            def __init__(self, label):
                self.label = label
                self.listener = None

            def addActionListener(self, listener):
                self.listener = listener

        class _Invocation(object):
            def getSelectedMessages(self):
                return [selected_message]

        # Supply the Java Swing import expected by createMenuItems() without
        # requiring Burp's Jython runtime in the unit-test process.
        swing_module = types.ModuleType("javax.swing")
        swing_module.JMenuItem = _MenuItem
        javax_module = types.ModuleType("javax")
        javax_module.swing = swing_module

        extension = WafExtension()
        selected_message = object()
        extension._start_selected_probe = mock.Mock()
        extension._probe_selected = mock.Mock()
        with mock.patch.dict(
                sys.modules,
                {"javax": javax_module, "javax.swing": swing_module}):
            menu_items = extension.createMenuItems(_Invocation())
            menu_items[0].listener(None)

        extension._start_selected_probe.assert_called_once_with(selected_message)
        extension._probe_selected.assert_not_called()

    def test_context_probe_is_scheduled_on_a_daemon_worker(self):
        extension = WafExtension()
        extension.callbacks = _Callbacks()
        selected_message = object()
        persisted_message = object()
        extension.callbacks.persisted_message = persisted_message

        with mock.patch("wafd.extension.Thread") as thread_class:
            extension._start_selected_probe(selected_message)

        self.assertEqual(extension.callbacks.saved_messages, [selected_message])
        thread_class.assert_called_once_with(
            target=extension._run_selected_probe,
            args=(persisted_message,),
            name="WAF Detector active probe")
        worker = thread_class.return_value
        worker.setDaemon.assert_called_once_with(True)
        worker.start.assert_called_once_with()
        self.assertIn(worker, extension._context_probe_workers)

    def test_context_probe_does_not_fall_back_inline_when_worker_start_fails(self):
        extension = WafExtension()
        extension.callbacks = _Callbacks()
        extension._probe_selected = mock.Mock()

        with mock.patch("wafd.extension.Thread") as thread_class:
            thread_class.return_value.start.side_effect = RuntimeError("no thread")
            extension._start_selected_probe(object())

        extension._probe_selected.assert_not_called()
        self.assertEqual(len(extension.callbacks.errors), 1)
        self.assertIn("could not start context probe", extension.callbacks.errors[0])
        self.assertEqual(extension._context_probe_workers, set())

    def test_context_worker_releases_tracking_after_completion(self):
        extension = WafExtension()
        extension._probe_selected = mock.Mock()
        persisted_message = object()
        worker = object()
        extension._context_probe_workers.add(worker)

        with mock.patch("wafd.extension.current_thread", return_value=worker):
            extension._run_selected_probe(persisted_message)

        extension._probe_selected.assert_called_once_with(persisted_message)
        self.assertEqual(extension._context_probe_workers, set())

    def test_queued_context_worker_is_discarded_without_probing_after_unload(self):
        extension = WafExtension()
        extension._probe_selected = mock.Mock()
        persisted_message = object()
        worker = object()
        extension._context_probe_workers.add(worker)
        extension.extensionUnloaded()

        with mock.patch("wafd.extension.current_thread", return_value=worker):
            extension._run_selected_probe(persisted_message)

        extension._probe_selected.assert_not_called()
        self.assertEqual(extension._context_probe_workers, set())

    def test_extension_unload_stops_active_batch_after_in_flight_request(self):
        rules = RuleCatalogue.from_json('{"rules":[]}')
        probes = ProbeCatalogue.from_json('{"schema_version":2,"probes":[{'
            '"id":"repeated","value":"marker","repeat":3}]}')
        extension = WafExtension()

        class _UnloadingCallbacks(_Callbacks):
            def makeHttpRequest(self, service, request):
                response = _Callbacks.makeHttpRequest(self, service, request)
                extension.extensionUnloaded()
                return response

        extension.configuration = Configuration()
        extension.catalogue = rules
        extension.detector = ResponseDetector(rules)
        extension.assessments = AssessmentStore(rules.rules)
        extension.probes = ProbePlanner(catalogue=probes)
        extension.helpers = _Helpers()
        extension.callbacks = _UnloadingCallbacks()
        base = _Message(b"GET /selected HTTP/1.1\r\nHost: example.test\r\n\r\n")

        class _InsertionPoint(object):
            def getInsertionPointName(self):
                return "query"

            def buildRequest(self, payload):
                return base.getRequest()

        extension.doActiveScan(base, _InsertionPoint())

        self.assertEqual(len(extension.callbacks.requests), 1)
        self.assertEqual(extension.callbacks.issues, [])

    def test_response_normalisation_extracts_version_from_raw_bytes(self):
        extension = WafExtension()
        raw = b"HTTP/1.1 403 Forbidden\r\n\r\nblocked"
        fingerprint = extension._normalise_response(raw, _ResponseInfo(raw), 12)
        self.assertEqual(fingerprint["http_version"], "1.1")
        self.assertEqual(fingerprint["elapsed_ms"], 12)

    def test_response_normalisation_accepts_legacy_string_headers(self):
        extension = WafExtension()
        extension.helpers = _Helpers()
        raw = (b"HTTP/1.1 403 Forbidden\r\nSet-Cookie: first=secret\r\n"
               b"Set-Cookie: second=secret\r\nServer: cloudflare\r\n\r\nblocked")
        response_info = _ResponseInfo(raw, [
            "HTTP/1.1 403 Forbidden",
            "Set-Cookie: first=secret",
            "Set-Cookie: second=secret",
            "Server: cloudflare",
        ])
        fingerprint = extension._normalise_response(raw, response_info)
        self.assertEqual(fingerprint["http_version"], "1.1")
        self.assertEqual(fingerprint["cookies"], ["first", "second"])
        self.assertEqual(fingerprint["headers"]["server"], "cloudflare")
        self.assertNotIn("secret", str(fingerprint))

    def test_specialist_profile_sends_one_control_and_all_repeats_at_root(self):
        rules = RuleCatalogue.from_json('{"rules":[]}')
        probes = ProbeCatalogue.from_json('{"schema_version":2,"probes":[{'
            '"id":"post-body","value":"marker","repeat":2,"safe_methods":["POST"],'
            '"profile":{"placement":"raw_body","method":"POST",'
            '"content_type":"text/plain","control_value":"ordinary"}}]}')
        extension = WafExtension()
        extension.configuration = Configuration()
        extension.catalogue = rules
        extension.detector = ResponseDetector(rules)
        extension.assessments = AssessmentStore(rules.rules)
        extension.probes = ProbePlanner(catalogue=probes)
        extension.helpers = _Helpers()
        extension.callbacks = _Callbacks()

        base = _Message(b"GET /selected HTTP/1.1\r\nHost: example.test\r\n\r\n")

        class _InsertionPoint(object):
            def getInsertionPointName(self):
                return "query"

            def buildRequest(self, payload):
                raise AssertionError("specialist profile must use the request builder")

        extension.doActiveScan(base, _InsertionPoint())

        self.assertEqual(extension.callbacks.errors, [])
        self.assertEqual(len(extension.callbacks.requests), 3)
        request_lines = [request.split(b"\r\n", 1)[0]
                         for request in extension.callbacks.requests]
        self.assertEqual(request_lines, [b"POST / HTTP/1.1"] * 3)
        bodies = [request.split(b"\r\n\r\n", 1)[1]
                  for request in extension.callbacks.requests]
        self.assertEqual(bodies, [b"ordinary", b"marker", b"marker"])
        self.assertEqual(len(extension.callbacks.issues), 1)
        self.assertEqual(extension.callbacks.issues[0].getIssueName(),
                         "WAF Detector: current assessment")

    def test_active_transport_exceptions_are_classified_without_escaping(self):
        extension = WafExtension()

        class _FailingCallbacks(_Callbacks):
            def makeHttpRequest(self, service, request):
                raise IOError("connection reset by peer")

        extension.callbacks = _FailingCallbacks()
        message, state, elapsed = extension._send_active_request(object(), b"request")
        self.assertIsNone(message)
        self.assertEqual(state, "reset")
        self.assertGreaterEqual(elapsed, 0)
        self.assertTrue(extension.callbacks.errors)


class ExtensionSettingsTests(unittest.TestCase):
    def test_disabled_rule_and_probe_evidence_is_discarded(self):
        rules = RuleCatalogue.from_json('{"rules":['
            '{"id":"enabled","name":"Enabled","evidence_group":"one","weight":1},'
            '{"id":"disabled","name":"Disabled","evidence_group":"two","weight":1}]}')
        probes = ProbeCatalogue.from_json('{"schema_version":2,"probes":['
            '{"id":"enabled-probe","value":"one"},'
            '{"id":"disabled-probe","value":"two"}]}')
        rules.rules[1].enabled = False
        probes.probes[1].enabled = False
        extension = WafExtension()
        extension.catalogue = rules
        extension.probes = ProbePlanner(catalogue=probes)
        extension.assessments = AssessmentStore(rules.rules)
        extension.assessments.observe("https://x", [
            Evidence("enabled", "https://x", "keep passive"),
            Evidence("disabled", "https://x", "drop rule"),
            Evidence("enabled", "https://x", "keep active",
                     characteristic="enabled-probe"),
            Evidence("enabled", "https://x", "drop probe",
                     characteristic="disabled-probe"),
        ])

        extension._discard_disabled_evidence()

        details = [item.detail for item in extension.assessments.assessments["https://x"].evidence]
        self.assertEqual(details, ["keep passive", "keep active"])

    def test_catalogue_overrides_are_loaded_and_saved_through_burp_settings(self):
        class _SettingsCallbacks(_Callbacks):
            def __init__(self):
                _Callbacks.__init__(self)
                self.settings = {}

            def loadExtensionSetting(self, name):
                return self.settings.get(name)

            def saveExtensionSetting(self, name, value):
                self.settings[name] = value

        callbacks = _SettingsCallbacks()
        callbacks.settings["catalogue_overrides"] = CatalogueOverrides(
            {"rule": False}, {"probe": False}).to_json()
        extension = WafExtension()
        extension.callbacks = callbacks
        extension._load_catalogue_overrides()
        self.assertFalse(extension.overrides.rules["rule"])

        extension.catalogue = RuleCatalogue.from_json('{"rules":['
            '{"id":"rule","name":"Rule","evidence_group":"g","weight":1}]}')
        probe_catalogue = ProbeCatalogue.from_json('{"schema_version":2,"probes":['
            '{"id":"probe","value":"x"}]}')
        extension.probes = ProbePlanner(catalogue=probe_catalogue)
        extension.catalogue.rules[0].enabled = False
        extension.probes.catalogue.probes[0].enabled = False
        extension.save_catalogue_overrides()
        restored = CatalogueOverrides.from_json(callbacks.settings["catalogue_overrides"])
        self.assertFalse(restored.rules["rule"])
        self.assertFalse(restored.probes["probe"])


if __name__ == "__main__":
    unittest.main()
