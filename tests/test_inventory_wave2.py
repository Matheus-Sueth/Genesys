import unittest
from unittest.mock import Mock, patch

from genesys.inventory_wave2 import (
    CURSOR, INVENTORY_WAVE2_ENDPOINTS, PAGE_NUMBER, SINGLE,
    WAVE2_QUERY_PARAMETERS, _next_cursor, inventory_get_wave2,
)


class Client:
    URL = "https://api.mypurecloud.com"

    def auth_headers(self):
        return {"Authorization": "Bearer fictitious-token"}


def response(payload, status=200, headers=None):
    resp = Mock()
    resp.status_code = status
    resp.ok = status in range(200, 300)
    resp.headers = headers or {}
    resp.json.return_value = payload
    resp.text = "SENSITIVE ERROR BODY"
    return resp


class Wave2Tests(unittest.TestCase):
    def test_allowlist_shape(self):
        self.assertEqual(len(INVENTORY_WAVE2_ENDPOINTS), 16)
        self.assertEqual(sum(v == PAGE_NUMBER for v in INVENTORY_WAVE2_ENDPOINTS.values()), 12)
        self.assertEqual(sum(v == CURSOR for v in INVENTORY_WAVE2_ENDPOINTS.values()), 3)
        self.assertEqual(sum(v == SINGLE for v in INVENTORY_WAVE2_ENDPOINTS.values()), 1)
        self.assertEqual(set(INVENTORY_WAVE2_ENDPOINTS), set(WAVE2_QUERY_PARAMETERS))

    @patch("genesys.inventory_http.requests.get")
    def test_page_number(self, get):
        get.side_effect = [
            response({"entities": [{"id": "one"}], "pageCount": 2}),
            response({"entities": [{"id": "two"}], "pageCount": 2}),
        ]
        records = inventory_get_wave2(
            Client(), "/api/v2/flows/milestones", all_pages=True, page_size=1
        )
        self.assertEqual(records, [{"id": "one"}, {"id": "two"}])
        self.assertEqual(
            [call.kwargs["params"]["pageNumber"] for call in get.call_args_list], [1, 2]
        )
        self.assertEqual(get.call_args.kwargs["timeout"], (5, 30))

    @patch("genesys.inventory_http.requests.get")
    def test_cursor_from_cursors(self, get):
        get.side_effect = [
            response({"entities": [{"id": "one"}], "cursors": {"after": "next1"}}),
            response({"entities": [{"id": "two"}], "cursors": {}}),
        ]
        results = inventory_get_wave2(
            Client(), "/api/v2/routing/skillgroups", all_pages=True, page_size=10
        )
        self.assertEqual(len(results), 2)
        self.assertNotIn("after", get.call_args_list[0].kwargs["params"])
        self.assertEqual(get.call_args_list[1].kwargs["params"]["after"], "next1")

    @patch("genesys.inventory_http.requests.get")
    def test_cursor_from_next_uri(self, get):
        get.side_effect = [
            response({"entities": [{"id": "one"}], "nextUri": "/api/v2/webdeployments/deployments?after=next%2Bcursor&pageSize=20"}),
            response({"entities": [], "cursors": {}}),
        ]
        results = inventory_get_wave2(
            Client(), "/api/v2/webdeployments/deployments", all_pages=True, page_size=20
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(get.call_args_list[1].kwargs["params"]["after"], "next+cursor")

    def test_cursor_never_accept_external_url(self):
        with self.assertRaises(ValueError):
            _next_cursor({"nextUri": "https://evil.example/api/v2/knowledge/knowledgebases?after=oops"}, "/api/v2/knowledge/knowledgebases")
        with self.assertRaises(ValueError):
            _next_cursor({"nextUri": "/api/v2/users?after=other"}, "/api/v2/knowledge/knowledgebases")

    @patch("genesys.inventory_http.requests.get")
    def test_repeated_cursor_and_incomplete(self, get):
        get.return_value = response({"entities": [{"id": 1}], "cursors": {"after": "repeat"}})
        with self.assertRaisesRegex(RuntimeError, "cursor repetido"):
            inventory_get_wave2(Client(), "/api/v2/routing/skillgroups", all_pages=True, page_size=10)
        get.return_value = response({"entities": [{"id": 1}], "cursors": {}})
        with self.assertRaisesRegex(RuntimeError, "página cheia sem cursor"):
            inventory_get_wave2(Client(), "/api/v2/routing/skillgroups", all_pages=True, page_size=1)

    @patch("genesys.inventory_http.requests.get")
    def test_max_pages_and_no_silent_truncation(self, get):
        get.return_value = response({"entities": [], "cursors": {"after": "next"}})
        with self.assertRaisesRegex(RuntimeError, "max_pages"):
            inventory_get_wave2(Client(), "/api/v2/knowledge/knowledgebases", all_pages=True, max_pages=1)

    @patch("genesys.inventory_http.requests.get")
    def test_oauth_redaction(self, get):
        get.return_value = response({"entities": [{"id": "safe", "clientSecret": "do-not-show", "nested": {"API_KEY": "also-secret", "name": "Test"}}]})
        result = inventory_get_wave2(Client(), "/api/v2/oauth/clients")
        client = result["entities"][0]
        self.assertEqual(client["clientSecret"], "[REDACTED]")
        self.assertEqual(client["nested"]["API_KEY"], "[REDACTED]")
        self.assertEqual(client["nested"]["name"], "Test")
        self.assertEqual(client["id"], "safe")

    @patch("genesys.inventory_http.requests.get")
    def test_429_retry_and_403_redaction(self, get):
        get.side_effect = [
            response({}, 429, {"Retry-After": "0"}),
            response({"entities": []}),
        ]
        with patch("genesys.inventory_http.time.sleep") as sleep:
            self.assertEqual(inventory_get_wave2(Client(), "/api/v2/outbound/campaigns")["entities"], [])
            sleep.assert_called_once_with(0.0)
        get.side_effect = None
        get.return_value = response({}, 403)
        with self.assertRaises(Exception) as ctx:
            inventory_get_wave2(Client(), "/api/v2/outbound/campaigns")
        self.assertNotIn("SENSITIVE ERROR BODY", str(ctx.exception))

    def test_reject_unknown_params_and_cursor_before(self):
        cases = [
            ("/api/v2/knowledge/knowledgebases", {"all_pages": True, "params": {"before": "x"}}),
            ("/api/v2/oauth/clients", {"all_pages": True}),
            ("/api/v2/knowledge/knowledgebases", {"params": {"pageNumber": 2}}),
            ("/api/v2/outbound/campaigns", {"params": {"evil": 1}}),
            ("/api/v2/outbound/campaigns", {"max_pages": 0}),
            ("/api/v2/outbound/campaigns", {"params": {"pageSize": 10}}),
            ("/api/v2/outbound/campaigns?bad=x", {}),
        ]
        for path, opts in cases:
            with self.subTest(path=path, opts=opts), self.assertRaises(ValueError):
                inventory_get_wave2(Client(), path, **opts)

    @patch("genesys.inventory_http.requests.get")
    def test_first_page_raw(self, get):
        get.return_value = response({"entities": [{"id": 1}], "cursors": {"after": "a"}})
        r = inventory_get_wave2(Client(), "/api/v2/knowledge/knowledgebases", page_size=17)
        self.assertEqual(r["cursors"]["after"], "a")
        self.assertEqual(get.call_args.kwargs["params"]["pageSize"], 17)


if __name__ == "__main__":
    unittest.main()