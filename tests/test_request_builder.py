import json
import unittest

from wafd.request_builder import ProbeRequestBuilder
from wafd.probes import ProbeCatalogue


class ProbeRequestBuilderTests(unittest.TestCase):
    def setUp(self):
        self.builder = ProbeRequestBuilder()
        self.headers = [
            "GET /search?q=ordinary HTTP/1.1",
            "Host: example.test",
            "Content-Length: 8",
        ]

    def build(self, profile, value="<script>alert(1)</script>", root_non_get=True):
        return self.builder.build(self.headers, "original", profile, value, root_non_get)

    def test_query_changes_only_declared_parameter(self):
        built = self.build({"placement": "query", "parameter": "probe"})
        self.assertEqual(
            built.headers[0],
            "GET /search?q=ordinary&probe=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1")
        self.assertEqual(built.body, "original")

    def test_query_replaces_existing_named_parameter_without_pollution(self):
        built = self.build({"placement": "query", "parameter": "q"}, "probe")
        self.assertEqual(built.headers[0], "GET /search?q=probe HTTP/1.1")

    def test_form_json_and_vendor_json_bodies(self):
        form = self.build({"placement": "form", "method": "POST", "parameter": "id"})
        self.assertEqual(form.headers[0], "POST / HTTP/1.1")
        self.assertEqual(form.body, "id=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        self.assertIn("Content-Type: application/x-www-form-urlencoded", form.headers)

        vendor_json = self.build({"placement": "json", "method": "POST",
                                  "parameter": "value",
                                  "content_type": "application/vnd.example.resource+json"})
        self.assertEqual(json.loads(vendor_json.body)["value"], "<script>alert(1)</script>")
        self.assertIn("Content-Type: application/vnd.example.resource+json", vendor_json.headers)

    def test_graphql_variables_and_query_are_shallow(self):
        variables = self.build({"placement": "graphql_variables", "method": "POST"}, "marker")
        document = json.loads(variables.body)
        self.assertEqual(document["variables"]["value"], "marker")
        self.assertNotIn("...", document["query"])

        direct = self.build({"placement": "graphql_query", "method": "POST",
                             "content_type": "application/graphql"}, "marker")
        self.assertEqual(direct.body, 'query WAFTest { wafTest(value: "marker") }')

    def test_xml_and_soap_treat_probe_as_text(self):
        xml = self.build({"placement": "xml", "method": "POST"})
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", xml.body)
        soap = self.build({"placement": "soap", "method": "POST"})
        self.assertIn("soap:Envelope", soap.body)
        self.assertIn("&lt;script&gt;", soap.body)

    def test_header_replaces_only_named_header_and_rejects_crlf(self):
        headers = self.headers + ["X-WAF-Test: old", "Authorization: secret"]
        built = self.builder.build(headers, "", {"placement": "header", "header": "X-WAF-Test"},
                                     "marker")
        self.assertIn("X-WAF-Test: marker", built.headers)
        self.assertIn("Authorization: secret", built.headers)
        with self.assertRaises(ValueError):
            self.build({"placement": "header"}, "one\r\nInjected: true")

    def test_cookie_preserves_existing_cookie_without_exposing_other_values(self):
        headers = self.headers + ["Cookie: session=secret"]
        built = self.builder.build(headers, "", {"placement": "cookie", "cookie": "waf_test"},
                                     "1' OR '1'='1")
        self.assertIn("Cookie: session=secret; waf_test=1%27+OR+%271%27%3D%271", built.headers)

    def test_multipart_field_filename_and_content(self):
        field = self.build({"placement": "multipart_field", "method": "POST"}, "marker")
        self.assertIn('name="description"', field.body)
        self.assertIn("\r\nmarker\r\n", field.body)

        filename = self.build({"placement": "multipart_filename", "method": "POST"}, "probe.txt")
        self.assertIn('filename="probe.txt"', filename.body)
        self.assertIn("\r\nWAFTEST\r\n", filename.body)

        content = self.build({"placement": "multipart_file", "method": "POST"}, "suspicious text")
        self.assertIn('filename="waf-test.txt"', content.body)
        self.assertIn("suspicious text", content.body)

    def test_query_pairs_preserve_order_for_parameter_pollution(self):
        profile = {"placement": "query_pairs", "parameters": [
            {"name": "id", "value": "ordinary"},
            {"name": "id", "value": "$value"},
        ]}
        built = self.build(profile, "1 OR 1=1")
        self.assertIn("id=ordinary&id=1+OR+1%3D1", built.headers[0])

    def test_raw_encoding_preserves_malformed_percent_marker(self):
        built = self.build({"placement": "query", "parameter": "value", "encoding": "raw"}, "%ZZ")
        self.assertIn("value=%ZZ", built.headers[0])

    def test_content_length_is_removed_for_burp_to_recalculate(self):
        built = self.build({"placement": "raw_body", "method": "POST"}, "changed")
        self.assertFalse(any(header.lower().startswith("content-length:")
                             for header in built.headers))

    def test_method_endpoint_and_raw_query_reject_request_line_injection(self):
        with self.assertRaises(ValueError):
            self.build({"placement": "raw_body", "method": "POST\r\nInjected: true"})
        with self.assertRaises(ValueError):
            self.build({"placement": "raw_body", "method": "POST",
                        "endpoint": "/\r\nInjected: true"})
        with self.assertRaises(ValueError):
            self.build({"placement": "raw_query"}, "value\r\nInjected: true")

    def test_configured_size_probes_respect_threshold_and_hard_maximum(self):
        limits = {"body_test_threshold": 100, "header_test_threshold": 80,
                  "header_count_test_threshold": 5, "inspection_boundary": 60,
                  "size_hard_max": 200}
        below = self.builder.build(
            self.headers, "", {"placement": "sized_body", "method": "POST",
                               "threshold_offset": -1}, "WAFTEST", limits=limits)
        self.assertEqual(len(below.body), 99)
        above = self.builder.build(
            self.headers, "", {"placement": "sized_header", "threshold_offset": 1},
            "WAFTEST", limits=limits)
        padding = next(header for header in above.headers
                       if header.startswith("X-WAF-Test-Padding:"))
        self.assertEqual(len(padding.split(": ", 1)[1]), 81)
        with self.assertRaises(ValueError):
            self.builder.build(
                self.headers, "", {"placement": "sized_body", "method": "POST",
                                   "threshold_factor": 3}, "WAFTEST", limits=limits)

    def test_inspection_markers_straddle_configured_boundary(self):
        limits = {"body_test_threshold": 100, "header_test_threshold": 80,
                  "header_count_test_threshold": 5, "inspection_boundary": 60,
                  "size_hard_max": 200}
        before = self.builder.build(
            self.headers, "", {"placement": "inspection_body", "method": "POST",
                               "marker_position": "before-boundary"}, "WAFTEST", limits=limits)
        after = self.builder.build(
            self.headers, "", {"placement": "inspection_body", "method": "POST",
                               "marker_position": "after-boundary"}, "WAFTEST", limits=limits)
        self.assertLess(before.body.index("WAFTEST"), 60)
        self.assertGreater(after.body.index("WAFTEST"), 60)

    def test_cookie_repetition_and_multiple_header_variants(self):
        repeated = self.build({"placement": "cookie_repeated", "cookie": "waf_test"}, "marker")
        self.assertTrue(any("waf_test=ordinary; waf_test=marker" in header
                            for header in repeated.headers))
        multiple = self.build({"placement": "cookie_multiple_headers", "cookie": "waf_test"},
                              "marker")
        self.assertEqual(sum(header.startswith("Cookie:") for header in multiple.headers), 2)

    def test_every_bundled_specialist_profile_builds_probe_and_control(self):
        limits = {"body_test_threshold": 8192, "header_test_threshold": 4096,
                  "header_count_test_threshold": 64, "inspection_boundary": 8192,
                  "size_hard_max": 262144}
        specialist = [probe for probe in ProbeCatalogue.bundled().probes
                      if probe.profile.get("placement")]
        self.assertEqual(len(specialist), 164)
        for probe in specialist:
            self.builder.build(self.headers, "original", probe.profile, probe.value,
                               limits=limits)
            control_profile = dict(probe.profile)
            control_profile.update(probe.profile.get("control_profile", {}))
            self.builder.build(
                self.headers, "original", control_profile,
                probe.profile.get("control_value", "ordinary"), limits=limits)


if __name__ == "__main__":
    unittest.main()
