import unittest
from pathlib import Path

from genesys.coverage import compare_coverage, inspect_library


class CoverageWave2Tests(unittest.TestCase):
    def test_wave2_wrappers_detected(self):
        source = '''
class Genesys:
    def get_inventory_knowledge_bases(self):
        return self._inventory_get_wave2("/api/v2/knowledge/knowledgebases", all_pages=True)
    def get_inventory_oauth_clients(self):
        return self._inventory_get_wave2("/api/v2/oauth/clients")
'''
        result = inspect_library(source)
        catalog = {"operations": [
            {"method": "GET", "path": "/api/v2/knowledge/knowledgebases"},
            {"method": "GET", "path": "/api/v2/oauth/clients"},
        ]}
        self.assertEqual(compare_coverage(catalog, result)["static_matches"], 2)


if __name__ == "__main__":
    unittest.main()