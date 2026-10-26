import unittest

from genesys.coverage import compare_coverage, inspect_library


class InventoryCoverageTests(unittest.TestCase):
    def test_inventory_wrappers_detected_in_coverage(self):
        source = '''
class Genesys:
    def get_inventory_users(self):
        return self._inventory_get("/api/v2/users", all_pages=True)
    def get_inventory_groups(self):
        return self._inventory_get("/api/v2/groups")
'''
        inspection = inspect_library(source)
        self.assertEqual(inspection["http_calls"], 2)
        self.assertEqual(inspection["resolved_http_calls"], 2)
        catalog = {"operations": [
            {"method": "GET", "path": "/api/v2/users"},
            {"method": "GET", "path": "/api/v2/groups"},
        ]}
        result = compare_coverage(catalog, inspection)
        self.assertEqual(result["static_matches"], 2)


if __name__ == "__main__":
    unittest.main()
