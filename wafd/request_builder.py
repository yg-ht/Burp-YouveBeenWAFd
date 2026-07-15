"""Construct specialised active-probe requests without Burp dependencies."""

import json

try:
    from urllib import quote_plus
except ImportError:  # Python 3 test environment.
    from urllib.parse import quote_plus


class BuiltRequest(object):
    """A request line, header list and body ready for Burp's message helper."""

    def __init__(self, headers, body):
        self.headers = list(headers)
        self.body = body


class ProbeRequestBuilder(object):
    """Build one control or probe request from declarative placement metadata."""

    IDEMPOTENT_METHODS = ("GET", "HEAD", "OPTIONS")
    MULTIPART_BOUNDARY = "----WAFDProbeBoundary7MA4YWxk"

    def build(self, headers, original_body, profile, value, root_non_get=True, limits=None):
        """Return a specialised request while preserving unrelated headers."""
        if not headers:
            raise ValueError("request requires a request line")

        method, target, version = self._parse_request_line(headers[0])
        outgoing_method = self._http_method(profile.get("method", method))
        placement = str(profile.get("placement", "raw_body"))
        limits = dict(limits or {})

        # Explicit profile endpoints take precedence. Otherwise constructed
        # non-GET bodies use the configured root policy while GET-like probes
        # preserve the selected target.
        endpoint = profile.get("endpoint")
        if endpoint:
            target = self._request_target(endpoint)
        elif root_non_get and outgoing_method not in self.IDEMPOTENT_METHODS:
            target = "/"

        updated_headers = ["%s %s %s" % (outgoing_method, target, version)]
        updated_headers.extend(str(header) for header in headers[1:])
        # Preserve the original body object for query/header/cookie placements;
        # in Burp this may be a Java byte array rather than a Python string.
        body = original_body

        if placement == "query":
            target = self._set_query_parameter(target, profile.get("parameter", "wafd"),
                                               value, profile.get("encoding", "url"))
            updated_headers[0] = "%s %s %s" % (outgoing_method, target, version)
        elif placement == "raw_query":
            target = self._append_raw_query(target, value)
            updated_headers[0] = "%s %s %s" % (outgoing_method, target, version)
        elif placement == "query_pairs":
            target = self._append_query_pairs(target, profile.get("parameters", []), value,
                                              profile.get("encoding", "url"))
            updated_headers[0] = "%s %s %s" % (outgoing_method, target, version)
        elif placement == "form":
            body = self._form_body(profile.get("parameter", "wafd"), value)
            updated_headers = self._content_type(updated_headers,
                                                 "application/x-www-form-urlencoded")
        elif placement == "json":
            body = json.dumps({str(profile.get("parameter", "wafd")): value},
                              separators=(",", ":"))
            updated_headers = self._content_type(
                updated_headers, profile.get("content_type", "application/json"))
        elif placement == "graphql_variables":
            variable = str(profile.get("parameter", "value"))
            body = json.dumps({
                "query": "query WAFTest($%s: String!) { wafTest(value: $%s) }" %
                         (variable, variable),
                "variables": {variable: value},
            }, separators=(",", ":"))
            updated_headers = self._content_type(updated_headers, "application/json")
        elif placement == "graphql_query":
            query = "query WAFTest { wafTest(value: %s) }" % json.dumps(value)
            if profile.get("content_type") == "application/graphql":
                body = query
            else:
                body = json.dumps({"query": query}, separators=(",", ":"))
            updated_headers = self._content_type(
                updated_headers, profile.get("content_type", "application/json"))
        elif placement == "xml":
            element = self._xml_name(profile.get("parameter", "wafd"))
            body = "<?xml version=\"1.0\"?><root><%s>%s</%s></root>" % (
                element, self._xml_escape(value), element)
            updated_headers = self._content_type(
                updated_headers, profile.get("content_type", "application/xml"))
        elif placement == "soap":
            body = ("<?xml version=\"1.0\"?>"
                    "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
                    "<soap:Body><wafTest><value>%s</value></wafTest></soap:Body>"
                    "</soap:Envelope>") % self._xml_escape(value)
            updated_headers = self._content_type(
                updated_headers, profile.get("content_type", "application/soap+xml"))
        elif placement == "header":
            updated_headers = self._set_header(
                updated_headers, profile.get("header", "X-WAF-Test"), value)
        elif placement == "cookie":
            cookie_name = self._token(profile.get("cookie", "waf_test"), "cookie name")
            cookie_value = self._encode(value, profile.get("encoding", "url"))
            updated_headers = self._append_cookie(updated_headers, cookie_name, cookie_value)
        elif placement == "cookie_repeated":
            cookie_name = self._token(profile.get("cookie", "waf_test"), "cookie name")
            encoded = self._encode(value, profile.get("encoding", "url"))
            updated_headers = self._append_cookie(
                updated_headers, cookie_name, "ordinary")
            updated_headers = self._append_cookie(updated_headers, cookie_name, encoded)
        elif placement == "cookie_multiple_headers":
            cookie_name = self._token(profile.get("cookie", "waf_test"), "cookie name")
            encoded = self._encode(value, profile.get("encoding", "url"))
            updated_headers.append("Cookie: %s=ordinary" % cookie_name)
            updated_headers.append("Cookie: %s=%s" % (cookie_name, encoded))
        elif placement in ("multipart_field", "multipart_filename", "multipart_file",
                           "multipart_empty_filename", "multipart_multiple_files",
                           "multipart_repeated_field"):
            body = self._multipart_body(placement, profile, value)
            updated_headers = self._content_type(
                updated_headers, "multipart/form-data; boundary=%s" % self.MULTIPART_BOUNDARY)
        elif placement == "raw_body":
            body = value
            updated_headers = self._content_type(
                updated_headers, profile.get("content_type", "text/plain"))
        elif placement in ("sized_body", "inspection_body"):
            body = self._sized_body(profile, value, limits)
            updated_headers = self._content_type(
                updated_headers, profile.get("content_type", "application/octet-stream"))
        elif placement == "sized_header":
            size = self._configured_size(profile, limits, "header_test_threshold")
            header_name = profile.get("header", "X-WAF-Test-Padding")
            updated_headers = self._set_header(updated_headers, header_name,
                                               self._padded_value(value, size, "end"))
        elif placement == "header_count":
            count = self._configured_count(profile, limits)
            updated_headers = self._remove_prefix_headers(updated_headers, "x-waf-test-padding-")
            existing_count = len(updated_headers) - 1
            if count < existing_count:
                raise ValueError("configured header count is below existing request header count")
            for index in range(count - existing_count):
                updated_headers.append("X-WAF-Test-Padding-%04d: x" % index)
        elif placement == "total_header_size":
            size = self._configured_size(profile, limits, "header_test_threshold")
            updated_headers = self._remove_header(updated_headers, "x-waf-test-padding")
            existing_size = sum(len(str(header)) + 2 for header in updated_headers)
            prefix_size = len("X-WAF-Test-Padding: ") + 2
            padding_size = size - existing_size - prefix_size
            if padding_size < len(str(value)):
                raise ValueError("configured total header size is below existing headers")
            updated_headers.append("X-WAF-Test-Padding: %s" %
                                   self._padded_value(value, padding_size, "end"))
        else:
            raise ValueError("unsupported probe placement: %s" % placement)

        # Burp's buildHttpMessage recalculates Content-Length. Remove the old
        # value so a changed body cannot retain a conflicting duplicate.
        updated_headers = self._remove_header(updated_headers, "content-length")
        return BuiltRequest(updated_headers, body)

    @staticmethod
    def _parse_request_line(request_line):
        parts = str(request_line).split(None, 2)
        if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
            raise ValueError("invalid HTTP request line")
        return parts[0].upper(), parts[1], parts[2]

    @staticmethod
    def _http_method(value):
        method = str(value).upper()
        separators = '()<>@,;:\\"/[]?={} \t'
        if not method or any(character in separators or ord(character) < 33 or ord(character) > 126
                             for character in method):
            raise ValueError("invalid HTTP method")
        return method

    @staticmethod
    def _request_target(value):
        target = str(value)
        if not target or any(character in target for character in "\r\n \t"):
            raise ValueError("invalid HTTP request target")
        return target

    def _set_query_parameter(self, target, name, value, encoding):
        """Replace the first named parameter, or append it when absent."""
        if target == "*":
            raise ValueError("asterisk-form request target cannot contain a query")
        before_fragment, marker, fragment = str(target).partition("#")
        path, query_marker, query = before_fragment.partition("?")
        encoded_name = self._encode(name, encoding)
        replacement = "%s=%s" % (encoded_name, self._encode(value, encoding))
        parameters = query.split("&") if query_marker else []
        replaced = False
        for index, parameter in enumerate(parameters):
            if not replaced and parameter.split("=", 1)[0] == encoded_name:
                parameters[index] = replacement
                replaced = True
        if not replaced:
            parameters.append(replacement)
        result = path + "?" + "&".join(parameters)
        return result + (("#" + fragment) if marker else "")

    def _append_query_pairs(self, target, parameters, value, encoding):
        if target == "*":
            raise ValueError("asterisk-form request target cannot contain a query")
        before_fragment, marker, fragment = str(target).partition("#")
        pairs = []
        for parameter in parameters:
            if not isinstance(parameter, dict):
                raise ValueError("query parameters must be objects")
            name = str(parameter.get("name", ""))
            item_value = parameter.get("value", "")
            if item_value == "$value":
                item_value = value
            pairs.append("%s=%s" % (
                self._encode(name, encoding), self._encode(item_value, encoding)))
        if not pairs:
            raise ValueError("query placement requires at least one parameter")
        separator = "" if before_fragment.endswith(("?", "&")) else (
            "&" if "?" in before_fragment else "?")
        result = before_fragment + separator + "&".join(pairs)
        return result + (("#" + fragment) if marker else "")

    @staticmethod
    def _append_raw_query(target, value):
        """Append deliberately malformed-but-bounded query syntax verbatim."""
        if any(character in str(value) for character in "\r\n \t"):
            raise ValueError("raw query syntax cannot contain whitespace or line breaks")
        before_fragment, marker, fragment = str(target).partition("#")
        separator = "" if before_fragment.endswith(("?", "&")) else (
            "&" if "?" in before_fragment else "?")
        result = before_fragment + separator + str(value)
        return result + (("#" + fragment) if marker else "")

    def _form_body(self, name, value):
        return "%s=%s" % (self._encode(name, "url"), self._encode(value, "url"))

    def _multipart_body(self, placement, profile, value):
        field = self._token(profile.get("field", "description"), "multipart field")
        boundary = self.MULTIPART_BOUNDARY
        parts = []
        if placement in ("multipart_field", "multipart_repeated_field"):
            if placement == "multipart_repeated_field":
                parts.append((field, None, profile.get("part_content_type"), "ordinary"))
            parts.append((field, None, profile.get("part_content_type"), value))
        elif placement == "multipart_multiple_files":
            parts.append((field, "ordinary.txt", "text/plain", "ordinary"))
            parts.append((field, "waf-test.txt", profile.get("part_content_type", "text/plain"), value))
        else:
            if placement == "multipart_filename":
                filename, payload = value, "WAFTEST"
            elif placement == "multipart_empty_filename":
                filename, payload = "", value
            else:
                filename, payload = profile.get("filename", "waf-test.txt"), value
            parts.append((field, filename, profile.get("part_content_type", "text/plain"), payload))

        lines = []
        for part_field, filename, content_type, payload in parts:
            lines.append("--" + boundary)
            disposition = 'Content-Disposition: form-data; name="%s"' % part_field
            if filename is not None:
                disposition += '; filename="%s"' % self._quoted_value(
                    filename, "multipart filename")
            lines.append(disposition)
            if content_type:
                lines.append("Content-Type: %s" % self._header_value(content_type))
            lines.extend(["", self._as_text(payload)])
        lines.extend(["--" + boundary + "--", ""])
        return "\r\n".join(lines)

    @staticmethod
    def _as_text(value):
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return str(value)

    @staticmethod
    def _xml_escape(value):
        return (str(value).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;")
                .replace("'", "&apos;"))

    @staticmethod
    def _xml_name(value):
        name = str(value)
        if not name or not (name[0].isalpha() or name[0] == "_") or not all(
                character.isalnum() or character in "_.-" for character in name):
            raise ValueError("invalid XML element name")
        return name

    @staticmethod
    def _token(value, label):
        token = str(value)
        if not token or any(character in token for character in "\r\n:;=\""):
            raise ValueError("invalid %s" % label)
        return token

    @staticmethod
    def _header_value(value):
        text = str(value)
        if "\r" in text or "\n" in text:
            raise ValueError("header values cannot contain line breaks")
        return text

    def _quoted_value(self, value, label):
        text = self._header_value(value)
        if "\x00" in text:
            raise ValueError("%s cannot contain a null byte" % label)
        return text.replace("\\", "\\\\").replace('"', '\\"')

    def _set_header(self, headers, name, value):
        header_name = self._token(name, "header name")
        header_value = self._header_value(value)
        lowered = header_name.lower()
        result = [headers[0]]
        replaced = False
        for header in headers[1:]:
            current_name = str(header).split(":", 1)[0].strip().lower()
            if current_name == lowered:
                if not replaced:
                    result.append("%s: %s" % (header_name, header_value))
                    replaced = True
            else:
                result.append(str(header))
        if not replaced:
            result.append("%s: %s" % (header_name, header_value))
        return result

    def _append_cookie(self, headers, name, value):
        existing = None
        retained = [headers[0]]
        for header in headers[1:]:
            if str(header).split(":", 1)[0].strip().lower() == "cookie":
                if existing is None:
                    existing = str(header).split(":", 1)[1].strip()
            else:
                retained.append(str(header))
        cookie = "%s=%s" % (name, value)
        retained.append("Cookie: %s" % ((existing + "; " + cookie) if existing else cookie))
        return retained

    def _sized_body(self, profile, value, limits):
        if profile.get("placement") == "inspection_body":
            boundary = self._limit(limits, "inspection_boundary")
            hard_max = self._limit(limits, "size_hard_max")
            position = profile.get("marker_position", "beginning")
            if position == "beginning":
                offset = 0
            elif position == "before-boundary":
                offset = max(0, boundary - len(str(value)) - 1)
            elif position == "after-boundary":
                offset = boundary + 1
            elif position == "end":
                offset = max(0, min(hard_max, boundary + 1024) - len(str(value)))
            else:
                raise ValueError("unsupported inspection marker position")
            requested = offset + len(str(value)) + 1
            if requested > hard_max:
                raise ValueError("inspection probe exceeds configured hard maximum")
            return ("A" * offset) + str(value) + ("A" * (requested - offset - len(str(value))))
        size = self._configured_size(profile, limits, "body_test_threshold")
        return self._padded_value(value, size, profile.get("marker_position", "end"))

    def _configured_size(self, profile, limits, threshold_name):
        threshold = self._limit(limits, threshold_name)
        factor = float(profile.get("threshold_factor", 1.0))
        offset = int(profile.get("threshold_offset", 0))
        size = int(threshold * factor) + offset
        hard_max = self._limit(limits, "size_hard_max")
        if size < 1 or size > hard_max:
            raise ValueError("configured size probe exceeds hard maximum")
        return size

    def _configured_count(self, profile, limits):
        threshold = self._limit(limits, "header_count_test_threshold")
        count = threshold + int(profile.get("threshold_offset", 0))
        if count < 1 or count > 500:
            raise ValueError("configured header-count probe is out of bounds")
        return count

    @staticmethod
    def _limit(limits, name):
        if name not in limits:
            raise ValueError("missing configured limit: %s" % name)
        return int(limits[name])

    @staticmethod
    def _padded_value(value, size, position):
        marker = str(value)
        if len(marker) > size:
            raise ValueError("probe marker is larger than configured size")
        padding = "A" * (size - len(marker))
        return marker + padding if position == "beginning" else padding + marker

    def _content_type(self, headers, value):
        return self._set_header(headers, "Content-Type", self._header_value(value))

    @staticmethod
    def _remove_header(headers, lowered_name):
        return [headers[0]] + [str(header) for header in headers[1:]
                               if str(header).split(":", 1)[0].strip().lower() != lowered_name]

    @staticmethod
    def _remove_prefix_headers(headers, lowered_prefix):
        return [headers[0]] + [str(header) for header in headers[1:]
                               if not str(header).split(":", 1)[0].strip().lower().startswith(
                                   lowered_prefix)]

    @staticmethod
    def _encode(value, encoding):
        text = str(value)
        if encoding == "raw":
            return text
        if encoding != "url":
            raise ValueError("unsupported value encoding: %s" % encoding)
        return quote_plus(text)
