import csv
import tempfile
import unittest
from pathlib import Path

from genesys.coverage import compare_coverage, export_coverage, inspect_library

SOURCE = '''
import requests
class Another:
    def unrelated(self):
        return requests.get("https://example.com/api/v2/ghost")
class Genesys:
    def listing(self):
        response = requests.get(url=f"{self.URL}/api/v2/routing/queues", params={})
        return response.json()
    def detail(self, queue_id):
        url = f"{self.URL}/api/v2/routing/queues/{queue_id}?expand=members"
        return requests.get(url=url)
    def unknown(self, some_url):
        return requests.get(url=some_url)
    def pagination(self, page):
        url = f"{self.URL}/api/v2/users?pageSize={page}"
        return requests.get(url)
    def send(self):
        return requests.post(f"{self.URL}/api/v2/routing/queues")
'''


def op(method, path, classification="collection_candidate", deprecated=False):
    return {
        "method": method, "path": path, "classification": classification,
        "deprecated": deprecated, "id": f"{method} {path}",
    }


CATALOG = {"source_sha256": "test", "operations": [
    op("GET", "/api/v2/routing/queues"),
    op("GET", "/api/v2/routing/queues/{queueId}", "requires_path_ids"),
    op("GET", "/api/v2/users"),
    op("POST", "/api/v2/routing/queues"),
    op("GET", "/api/v2/architect/flows"),
    op("GET", "/api/v2/analytics/conversations/details"),
    op("GET", "/api/v2/deprecated/thing", deprecated=True),
]}


class CoverageTests(unittest.TestCase):
    def test_paths_dynamic_queries_class_scope_and_verbs(self):
        inspection = inspect_library(SOURCE)
        self.assertEqual(inspection["class_methods"], 5)
        self.assertEqual(inspection["http_calls"], 5)
        self.assertEqual(inspection["resolved_http_calls"], 4)
        report = compare_coverage(CATALOG, inspection)
        self.assertEqual(report["static_matches"], 4)
        self.assertEqual(report["not_matched_static"], 3)
        self.assertEqual(len(report["manual_review_calls"]), 1)
        status = {row["id"]: row for row in report["operations"]}
        self.assertEqual(
            status["GET /api/v2/routing/queues/{queueId}"]["status"], "implemented_static"
        )
        self.assertEqual(status["GET /api/v2/architect/flows"]["priority"], "P0")
        self.assertEqual(
            status["GET /api/v2/analytics/conversations/details"]["priority"], "P3"
        )
        self.assertEqual(status["GET /api/v2/deprecated/thing"]["priority"], "P3")
        with tempfile.TemporaryDirectory() as tmp:
            export_coverage(report, tmp, top=2)
            self.assertTrue((Path(tmp) / "coverage.json").exists())
            self.assertTrue((Path(tmp) / "coverage.md").exists())
            with (Path(tmp) / "coverage.csv").open(
                encoding="utf-8-sig", newline=""
            ) as f:
                self.assertEqual(len(list(csv.DictReader(f))), 7)

    def test_unknown_path_is_not_invented(self):
        source = '''
import requests
class Genesys:
    def foo(self, path):
        url = f"{self.URL}/api/v2/{path}/users"
        return requests.get(url=url)
'''
        self.assertIsNone(inspect_library(source)["calls"][0]["path"])

    def test_syntax_error(self):
        with self.assertRaises(SyntaxError):
            inspect_library("class Genesys: def = !")


if __name__ == "__main__":
    unittest.main()
