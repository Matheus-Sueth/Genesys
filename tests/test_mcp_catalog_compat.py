"""Compatibilidade dos métodos MCP Catalog durante expansão da biblioteca."""
import unittest
from unittest.mock import Mock, patch

from genesys.api import Genesys, GenesysMcpCatalogError, GenesysRegion


class _TokenProvider:
    def get_region(self):
        return GenesysRegion("mypurecloud.com")

    def get_access_token(self):
        return "PRIVATE-TOKEN"

    def token_info(self):
        return {}


class McpCatalogCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.api = Genesys(_TokenProvider())

    def test_legacy_methods_remain_available(self):
        for method in ("get_mcp_catalog_page", "get_mcp_catalog_detail", "get_mcp_action_schema"):
            self.assertTrue(callable(getattr(self.api, method, None)), method)

    def test_explicit_approved_catalog_paths_only(self):
        invalid = [
            "/api/v2/oauth/clients", "https://external.test/secrets",
            "/api/v2/routing/queues/../oauth", "/api/v2/routing/queues?id=x",
            "/api/v2/routing/queues#fragment", "/api/v2/routing/queues/%2e%2e",
        ]
        with patch("genesys.api.requests.get") as get:
            for path in invalid:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.api._mcp_catalog_get(path)
            get.assert_not_called()

    def test_queue_list_is_bounded_and_delegated(self):
        response = Mock(ok=True, is_redirect=False, status_code=200, content=b"{}")
        response.json.return_value = {"entities": []}
        with patch("genesys.api.requests.get", return_value=response) as get:
            result = self.api.get_mcp_catalog_page("queue", page_size=10)
        self.assertEqual(result, {"entities": []})
        self.assertEqual(get.call_args.kwargs["url"],
                         "https://api.mypurecloud.com/api/v2/routing/queues")
        self.assertEqual(get.call_args.kwargs["params"], {"pageNumber": 1, "pageSize": 10})
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertEqual(get.call_args.kwargs["timeout"], 10)
        self.assertIn("PRIVATE-TOKEN", str(get.call_args.kwargs["headers"]))

    def test_bad_ids_and_query_never_call_api(self):
        with patch("genesys.api.requests.get") as get:
            with self.assertRaises(ValueError):
                self.api.get_mcp_catalog_detail("queue", "../../secret")
            with self.assertRaises(ValueError):
                self.api.get_mcp_action_schema("INVALID", "/api/v2/users")
            with self.assertRaises(ValueError):
                self.api.get_mcp_catalog_page("skill", page_size=100)
            get.assert_not_called()

    def test_http_error_does_not_leak_body_or_token(self):
        response = Mock(ok=False, is_redirect=False, status_code=403, content=b"PRIVATE-PII")
        with patch("genesys.api.requests.get", return_value=response):
            with self.assertRaises(GenesysMcpCatalogError) as ctx:
                self.api.get_mcp_catalog_page("skill")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertNotIn("PRIVATE-PII", str(ctx.exception))
        self.assertNotIn("PRIVATE-TOKEN", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
