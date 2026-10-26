import unittest

from genesys.catalog import build_catalog, diff_catalog, filter_catalog


SWAGGER = {
    "swagger": "2.0",
    "info": {"version": "v2"},
    "security": [{"oauth": ["routing:readonly"]}],
    "parameters": {"Page": {"name": "pageNumber", "in": "query", "type": "integer"}},
    "paths": {
        "/api/v2/routing/queues": {
            "get": {
                "operationId": "getRoutingQueues",
                "tags": ["Routing"],
                "parameters": [{"$ref": "#/parameters/Page"}],
                "summary": "List queues",
            },
            "post": {"summary": "Create queue"},
        },
        "/api/v2/routing/queues/{queueId}": {
            "parameters": [{"name": "queueId", "in": "path", "required": True, "type": "string"}],
            "get": {"operationId": "getRoutingQueue", "tags": ["Routing"], "deprecated": True,
                    "x-purecloud-permissions": ["routing:queue:view"]},
        },
        "/api/v2/analytics/something": {
            "get": {"parameters": [{"name": "interval", "in": "query", "required": True, "type": "string"}]},
        },
    },
}


class CatalogTests(unittest.TestCase):
    def test_get_count_metadata_and_classification(self):
        result = build_catalog(SWAGGER)
        self.assertEqual(result["total_operations"], 3)
        self.assertEqual(result["method_counts"], {"GET": 3})
        listing = filter_catalog(result, text="List queues")[0]
        self.assertEqual(listing["pagination_parameters"], ["pageNumber"])
        self.assertEqual(listing["classification"], "collection_candidate")
        self.assertEqual(listing["oauth_scopes"], ["routing:readonly"])
        detail = filter_catalog(result, classification="requires_path_ids")[0]
        self.assertEqual(detail["permissions"], ["routing:queue:view"])
        self.assertEqual(detail["required_path_parameters"], ["queueId"])
        self.assertEqual(len(filter_catalog(result, include_deprecated=False)), 2)
        self.assertEqual(len(filter_catalog(result, classification="requires_query")), 1)

    def test_all_methods_and_deterministic(self):
        original = build_catalog(SWAGGER, methods=("GET", "POST"))
        self.assertEqual(original, build_catalog(SWAGGER, methods=("GET", "POST")))
        self.assertEqual(original["method_counts"], {"GET": 3, "POST": 1})
        changed = build_catalog(SWAGGER)
        diff = diff_catalog(changed, original)
        self.assertEqual(diff["added"], ["POST /api/v2/routing/queues"])

    def test_invalid_and_missing_ref(self):
        with self.assertRaisesRegex(ValueError, "paths"):
            build_catalog({"swagger": "2.0"})
        bad = {"swagger": "2.0", "paths": {"/x": {"get": {"parameters": [{"$ref": "#/parameters/x"}]}}}}
        with self.assertRaisesRegex(ValueError, "não encontrada"):
            build_catalog(bad)


if __name__ == "__main__":
    unittest.main()
