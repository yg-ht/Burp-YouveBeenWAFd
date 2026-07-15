import unittest
import re

from wafd.fingerprint import build_fingerprint


class FingerprintTests(unittest.TestCase):
    def test_captures_hash_length_cookies_and_protocol(self):
        fingerprint = build_fingerprint(
            403, {"Set-Cookie": "cf_clearance=token; Path=/", "Content-Type": "text/html"},
            "blocked", "2", "complete")
        self.assertEqual(fingerprint["status"], 403)
        self.assertEqual(fingerprint["http_version"], "2")
        self.assertEqual(fingerprint["cookies"], ["cf_clearance"])
        self.assertNotEqual(fingerprint["cookie_fingerprints"]["cf_clearance"], "token")
        self.assertEqual(fingerprint["body_length"], len("blocked"))
        self.assertEqual(len(fingerprint["body_hash"]), 64)

    def test_transport_state_is_retained(self):
        fingerprint = build_fingerprint(0, {}, "", connection_state="reset")
        self.assertEqual(fingerprint["connection_state"], "reset")

    def test_http_version_status_line_pattern_extracts_version(self):
        match = re.match(r"HTTP/(\d(?:\.\d)?)", "HTTP/1.1 403 Forbidden")
        self.assertEqual(match.group(1), "1.1")

    def test_cookie_value_hash_changes_without_retaining_secret(self):
        first = build_fingerprint(200, {"Set-Cookie": "session=first-secret; Path=/"}, "")
        second = build_fingerprint(200, {"Set-Cookie": "session=second-secret; Path=/"}, "")
        self.assertNotEqual(first["cookie_fingerprints"]["session"],
                            second["cookie_fingerprints"]["session"])
        self.assertNotIn("first-secret", str(first))


if __name__ == "__main__":
    unittest.main()
