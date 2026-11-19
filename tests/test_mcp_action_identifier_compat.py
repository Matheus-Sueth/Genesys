"""Regressões de IDs Genesys no MCP: listagem -> detalhe -> schema."""
import unittest
from unittest.mock import Mock, patch

from genesys.api import Genesys, GenesysRegion
from genesys.mcp_action_identifiers import (
    ACTION_ID_MAX_LENGTH, normalize_mcp_action_id,
)


_UUID = "15d2e5a3-6448-43fb-bac8-a78b3d938da4"
_IDS = (
    _UUID,
    "static_" + _UUID,
    "custom_-_" + _UUID,
    "static_-_PureCloud-Get-User-Presence_-_" + _UUID,
    "static_-_Salesforce-GetMostRecentOpenCaseByContactId_-_" + _UUID,
)


class _TokenProvider:
    def get_region(self):
        return GenesysRegion("mypurecloud.com")

    def get_access_token(self):
        return "PRIVATE-TOKEN"

    def token_info(self):
        return {}


def _response(body):
    response = Mock(ok=True, is_redirect=False, status_code=200, content=b"{}")
    response.json.return_value = body
    return response


class McpActionIdentifierCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.api = Genesys(_TokenProvider())

    def test_normalization_preserves_full_id_and_only_lowercases_uuid(self):
        for action_id in _IDS:
            with self.subTest(action_id=action_id):
                self.assertEqual(normalize_mcp_action_id(action_id), action_id)
                self.assertLessEqual(len(action_id), ACTION_ID_MAX_LENGTH)
                self.assertEqual(
                    normalize_mcp_action_id(action_id[:-36] + _UUID.upper()),
                    action_id,
                )

    def test_listed_action_id_can_be_queried_without_discarding_prefix(self):
        for action_id in _IDS:
            with self.subTest(action_id=action_id):
                payload = {"id": action_id, "name": "Exemplo", "contract": {}}
                with patch("genesys.api.requests.get", return_value=_response(payload)) as get:
                    result = self.api.get_mcp_catalog_detail("data_action", action_id)
                self.assertEqual(result["id"], action_id)
                self.assertEqual(
                    get.call_args.kwargs["url"],
                    "https://api.mypurecloud.com/api/v2/integrations/actions/" + action_id,
                )
                self.assertEqual(get.call_args.kwargs["timeout"], 10)
                self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_same_action_schema_is_allowed_but_cross_action_reference_is_denied(self):
        for action_id in _IDS:
            own_uri = "/api/v2/integrations/actions/" + action_id + "/schemas/input"
            other_id = "static_" + _UUID if action_id != "static_" + _UUID else "custom_-_" + _UUID
            foreign_uri = "/api/v2/integrations/actions/" + other_id + "/schemas/input"
            with self.subTest(action_id=action_id):
                with patch("genesys.api.requests.get", return_value=_response({"type": "object"})) as get:
                    self.assertEqual(
                        self.api.get_mcp_action_schema(action_id, own_uri),
                        {"type": "object"},
                    )
                    self.assertEqual(
                        get.call_args.kwargs["url"], "https://api.mypurecloud.com" + own_uri,
                    )
                    with self.assertRaises(ValueError):
                        self.api.get_mcp_action_schema(action_id, foreign_uri)
                    self.assertEqual(get.call_count, 1)

    def test_malicious_or_invalid_action_ids_never_open_remote_requests(self):
        invalid = (
            "custom_" + _UUID, "custom_-_" + "f" * 36,
            "dynamic_" + _UUID,
            "static_-_PureCloud-Get-User-Presence_-_../../" + _UUID,
            "static_-_PureCloud-Get-User-Presence_-_" + _UUID + "?x=1",
            "static_-_PureCloud-Get-User-Presence_-_" + _UUID + "/schemas/input",
            "static_-_" + "A" * 129 + "_-_" + _UUID,
            "https://example.invalid/" + _UUID,
            _UUID + "%2fetc", _UUID + "#fragment", _UUID + "/../private",
            _UUID.replace("-", ""), "", None,
        )
        with patch("genesys.api.requests.get") as get:
            for action_id in invalid:
                with self.subTest(action_id=action_id):
                    with self.assertRaises(ValueError):
                        self.api.get_mcp_catalog_detail("data_action", action_id)
                    with self.assertRaises(ValueError):
                        self.api.get_mcp_action_schema(
                            action_id, "/api/v2/integrations/actions/" + _UUID + "/schemas/input",
                        )
            get.assert_not_called()

    def test_arbitrary_path_and_schema_suffix_never_open_remote_requests(self):
        action_id = "custom_-_" + _UUID
        base = "/api/v2/integrations/actions/" + action_id
        invalid = (
            base + "/schemas/../secret", base + "/schemas/input?token=1",
            base + "/schemas/input#fragment", base + "/execute",
            base + "/draft", base + "/schemas/", base + "/schemas/%2e%2e",
        )
        with patch("genesys.api.requests.get") as get:
            for path in invalid:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.api._mcp_catalog_get(path)
            get.assert_not_called()


if __name__ == "__main__":
    unittest.main()
