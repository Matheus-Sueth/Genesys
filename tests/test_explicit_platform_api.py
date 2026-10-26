import unittest
from unittest.mock import Mock, patch
from genesys.api import Genesys

class ExplicitPlatformAPITests(unittest.TestCase):
    def setUp(self):
        self.api = object.__new__(Genesys)
        self.api.URL = "https://api.mypurecloud.com"
        self.api.auth_headers = lambda: {"Authorization": "Bearer test", "Content-Type": "application/json"}

    @patch("genesys.api.requests.request")
    def test_get(self, request):
        response = Mock(status_code=200, content=b"{}", headers={"Content-Type": "application/json"})
        response.json.return_value = {}
        request.return_value = response
        self.assertEqual(self.api.get_agentic_virtualagents(params={"pageNumber": 1}), {})
        self.assertEqual(request.call_args.args[0], "GET")

    @patch("genesys.api.requests.request")
    def test_path_encoded(self, request):
        request.return_value = Mock(status_code=204, content=b"", headers={})
        self.api.get_analytics_conversation_details("a/b")
        self.assertIn("a%2Fb", request.call_args.args[1])

    @patch("genesys.api.requests.request")
    def test_post_not_retried(self, request):
        request.return_value = Mock(status_code=429, content=b"", headers={})
        with self.assertRaisesRegex(RuntimeError, "429"):
            self.api.post_agentic_virtualagents(body={"name": "T"})
        self.assertEqual(request.call_count, 1)
