import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from genesys.inventory_http import INVENTORY_ENDPOINTS, inventory_get, _retry_after


class Client:
    URL = 'https://api.mypurecloud.com'
    def auth_headers(self):
        return {'Authorization': 'Bearer test'}


def response(payload, *, status=200, headers=None):
    r = Mock()
    r.status_code = status
    r.ok = 200 <= status < 300
    r.json.return_value = payload
    r.headers = headers or {}
    return r


class InventoryHttpTests(unittest.TestCase):
    def test_whitelist_matches_first_wave(self):
        self.assertEqual(len(INVENTORY_ENDPOINTS), 14)
        self.assertEqual(sum(INVENTORY_ENDPOINTS.values()), 11)

    @patch('genesys.inventory_http.requests.get')
    def test_direct_returns_raw(self, get):
        get.return_value = response({'id': 'org'})
        result = inventory_get(Client(), '/api/v2/organizations/me')
        self.assertEqual(result, {'id': 'org'})
        self.assertEqual(get.call_args.kwargs['timeout'], (5,30))
        self.assertEqual(get.call_args.args[0], 'https://api.mypurecloud.com/api/v2/organizations/me')

    @patch('genesys.inventory_http.requests.get')
    def test_paginated_and_raw_page(self, get):
        get.side_effect=[response({'entities': [{'id': 1}], 'pageCount': 2}), response({'entities': [{'id': 2}], 'pageCount': 2})]
        got=inventory_get(Client(), '/api/v2/groups', all_pages=True, page_size=1)
        self.assertEqual(got, [{'id':1},{'id':2}])
        self.assertEqual([c.kwargs['params']['pageNumber'] for c in get.call_args_list], [1,2])
        get.return_value = response({'entities':[{'id':3}]})
        get.side_effect = None
        self.assertEqual(inventory_get(Client(), '/api/v2/groups', page_size=20)['entities'][0]['id'],3)

    @patch('genesys.inventory_http.requests.get')
    def test_retry_429(self, get):
        get.side_effect = [response({},status=429,headers={'Retry-After':'0'}),response({'entities':[],'pageCount':0})]
        with patch('genesys.inventory_http.time.sleep') as sleeper:
            inventory_get(Client(), '/api/v2/users')
            sleeper.assert_called_once_with(0.0)
        self.assertEqual(get.call_count,2)

    @patch('genesys.inventory_http.requests.get')
    def test_retry_limit(self,get):
        get.return_value=response({},status=429,headers={'Retry-After':'70'})
        with self.assertRaisesRegex(RuntimeError, 'acima do limite'):
            inventory_get(Client(), '/api/v2/users')
        self.assertEqual(get.call_count,1)

    @patch('genesys.inventory_http.requests.get')
    def test_error_no_body_exposed(self, get):
        get.return_value=response({},status=403)
        get.return_value.text='secret value'
        with self.assertRaises(Exception) as error:
            inventory_get(Client(), '/api/v2/users')
        self.assertNotIn('secret',str(error.exception))

    @patch('genesys.inventory_http.requests.get')
    def test_page_limit_does_not_truncate(self,get):
        get.return_value=response({'entities':[{'id':1}], 'pageCount':3})
        with self.assertRaisesRegex(RuntimeError, 'página repetida|incompleto'):
            inventory_get(Client(), '/api/v2/users', all_pages=True, page_size=1,max_pages=1)

    def test_params_validation_and_no_side_effects(self):
        for kwargs in [
            {'path':'https://external.com/'},
            {'path':'/api/v2/telephony/settings','all_pages':True},
            {'path':'/api/v2/groups','params':{'secret':'x'}},
            {'path':'/api/v2/groups','max_pages':0},
        ]:
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                inventory_get(Client(),**kwargs)

    def test_retry_after_parser(self):
        self.assertEqual(_retry_after({'Retry-After':'2.5'},0),2.5)
        self.assertEqual(_retry_after({},2),4.0)


if __name__=='__main__':
    unittest.main()