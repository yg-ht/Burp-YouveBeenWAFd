import unittest

from wafd.extension import WafExtension


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


if __name__ == "__main__":
    unittest.main()
