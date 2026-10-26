import unittest
from unittest.mock import Mock, patch

from genesys.platform_api import PlatformAPIClient, PlatformAPIError, _retry_after


CATALOG = {
    "format_version": 1, "source_sha256": "test", "operations": [
        {"method": "GET", "path": "/api/v2/users", "parameters": [{"name": "pageSize", "in": "query", "required": False, "type": "integer"}]},
        {"method": "GET", "path": "/api/v2/users/{userId}", "parameters": [{"name": "userId", "in": "path", "required": True}]},
        {"method": "POST", "path": "/api/v2/users", "parameters": [{"name": "body", "in": "body", "required": True}]},
        {"method": "POST", "path": "/api/v2/analytics/conversations/details/query", "parameters": [{"name": "body", "in": "body", "required": True}]},
        {"method": "GET", "path": "/api/v2/required", "parameters": [{"name": "interval", "in": "query", "required": True, "type": "string"}]},
        {"method": "DELETE", "path": "/api/v2/users/{userId}", "parameters": []},
    ]
}


class StubGenesys:
    URL = "https://api.mypurecloud.com"
    def auth_headers(self):
        return {"Authorization": "Bearer this-token-is-secret", "Content-Type": "application/json"}


def result(status=200, content_type="application/json", value=None, headers=None):
    response = Mock()
    response.status_code = status
    response.headers = {"Content-Type": content_type, **(headers or {})}
    response.content = b"{}" if value is None else value
    response.text = response.content.decode("utf-8", errors="replace")
    response.json.return_value = {"ok": True}
    return response


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.session = Mock()
        self.client = PlatformAPIClient(StubGenesys(), CATALOG, session=self.session)

    def test_all_operations_available_without_network(self):
        self.assertEqual(self.client.operation_count, 6)
        self.assertEqual(len(self.client.list_operations("GET")), 3)
        self.session.request.assert_not_called()

    def test_get_json_and_query(self):
        self.session.request.return_value = result()
        self.assertEqual(self.client.request("GET /api/v2/users", query={"pageSize": 25}), {"ok": True})
        kwargs = self.session.request.call_args.kwargs
        self.assertEqual(kwargs["method"], "GET")
        self.assertEqual(kwargs["params"], {"pageSize": 25})
        self.assertEqual(kwargs["url"], "https://api.mypurecloud.com/api/v2/users")
        self.assertFalse(kwargs["allow_redirects"])

    def test_path_vars_normalized_and_encoded(self):
        self.session.request.return_value = result()
        self.client.request("GET /api/v2/users/{userId}", path_params={"userId": "test@domain.com"})
        self.assertTrue(self.session.request.call_args.kwargs["url"].endswith("/test%40domain.com"))
        for text in ("../x", "", "..", "a/b", "a\\b"):
            with self.assertRaises(ValueError):
                self.client.request("GET /api/v2/users/{userId}", path_params={"userId": text})

    def test_unknown_operation_and_query_rejected(self):
        with self.assertRaises(KeyError):
            self.client.request("GET https://evil.example/secrets")
        with self.assertRaises(ValueError):
            self.client.request("GET /api/v2/users", query={"unsupported": "x"})
        self.session.request.assert_not_called()

    def test_missing_required_query(self):
        with self.assertRaises(ValueError):
            self.client.request("GET /api/v2/required")
        self.session.request.return_value = result()
        self.client.request("GET /api/v2/required", query={"interval": "today"})

    def test_write_requires_explicit_consent(self):
        with self.assertRaises(PermissionError):
            self.client.request("POST /api/v2/users", json_body={"name": "X"})
        with self.assertRaises(ValueError):
            self.client.request("POST /api/v2/users", allow_mutation=True)
        self.session.request.return_value = result()
        self.client.request("POST /api/v2/users", json_body={"name": "X"}, allow_mutation=True)
        self.assertEqual(self.session.request.call_args.kwargs["json"], {"name": "X"})
        self.assertEqual(self.session.request.call_args.kwargs["method"], "POST")

    def test_post_analytics_requires_explicit_consent_even_if_readonly(self):
        with self.assertRaises(PermissionError):
            self.client.request("POST /api/v2/analytics/conversations/details/query", json_body={})

    def test_429_get_retries_with_retry_after(self):
        self.session.request.side_effect = [result(429, headers={"Retry-After": "0.01"}), result()]
        with patch("genesys.platform_api.time.sleep") as sleep:
            self.assertEqual(self.client.request("GET /api/v2/users"), {"ok": True})
            sleep.assert_called_once_with(0.01)
        self.assertEqual(self.session.request.call_count, 2)

    def test_429_with_long_retry_after_does_not_retry_early(self):
        self.session.request.return_value = result(429, headers={"Retry-After": "120"})
        with patch("genesys.platform_api.time.sleep") as sleep:
            with self.assertRaises(PlatformAPIError):
                self.client.request("GET /api/v2/users")
            sleep.assert_not_called()
        self.assertEqual(self.session.request.call_count, 1)

    def test_429_write_not_retried(self):
        self.session.request.return_value = result(429)
        with self.assertRaises(PlatformAPIError):
            self.client.request("POST /api/v2/users", json_body={}, allow_mutation=True)
        self.assertEqual(self.session.request.call_count, 1)

    def test_http_error_has_no_secret_body(self):
        self.session.request.return_value = result(403, value=b'{"secret":"dont print me"}')
        with self.assertRaises(PlatformAPIError) as captured:
            self.client.request("GET /api/v2/users")
        self.assertEqual(captured.exception.status_code, 403)
        self.assertNotIn("secret", str(captured.exception))
        self.assertNotIn("Bearer", str(captured.exception))

    def test_redirect_blocked(self):
        self.session.request.return_value = result(302, headers={"Location": "https://evil.example"})
        with self.assertRaises(PlatformAPIError):
            self.client.request("GET /api/v2/users")

    def test_binary_text_204(self):
        self.session.request.return_value = result(200, "application/octet-stream", b"binary")
        self.assertEqual(self.client.request("GET /api/v2/users"), b"binary")
        self.session.request.return_value = result(200, "text/plain", b"hello")
        self.assertEqual(self.client.request("GET /api/v2/users"), "hello")
        self.session.request.return_value = result(204, value=b"")
        self.assertIsNone(self.client.request("GET /api/v2/users"))

    def test_retry_after_parser(self):
        self.assertEqual(_retry_after("2.25"), 2.25)
        self.assertIsNone(_retry_after("invalid date"))
        self.assertEqual(_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", clock=1800000000), 0)

    def test_rejects_wrong_catalog_or_url(self):
        with self.assertRaises(ValueError):
            PlatformAPIClient(StubGenesys(), {"format_version": 9, "operations": []})
        class BadClient(StubGenesys):
            URL = "http://api.mypurecloud.com"
        with self.assertRaises(ValueError):
            PlatformAPIClient(BadClient(), CATALOG)


if __name__ == "__main__":
    unittest.main()