"""Verificações locais para a API segura de catálogo MCP; nenhuma chamada externa."""
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from genesys.api import Genesys, GenesysMcpCatalogError


@pytest.fixture
def api():
    obj = object.__new__(Genesys)
    obj.URL = "https://api.sae1.pure.cloud"
    with patch.object(Genesys, "auth_headers", return_value={"Authorization": "Bearer SOMENTE_TESTE"}):
        yield obj


def _ok():
    response = Mock()
    response.status_code = 200
    response.ok = True
    response.is_redirect = False
    response.content = b'{"entities":[]}'
    response.json.return_value = {"entities": []}
    return response


def test_pages_use_static_resource_paths(api):
    with patch("genesys.api.requests.get", return_value=_ok()) as getter:
        result = api.get_mcp_catalog_page("data_table", page_number=3, page_size=8)
    assert result == {"entities": []}
    assert getter.call_args.kwargs["url"] == "https://api.sae1.pure.cloud/api/v2/flows/datatables/divisionviews"
    assert getter.call_args.kwargs["params"] == {"pageNumber": 3, "pageSize": 8}
    assert getter.call_args.kwargs["allow_redirects"] is False


def test_detail_expands_datatable_schema_only(api):
    ident = str(uuid4())
    with patch("genesys.api.requests.get", return_value=_ok()) as getter:
        api.get_mcp_catalog_detail("data_table", ident, expand_schema=True)
    assert getter.call_args.kwargs["params"] == {"expand": "schema"}
    with pytest.raises(ValueError):
        api.get_mcp_catalog_detail("queue", ident, expand_schema=True)


@pytest.mark.parametrize("resource", ["https://example.com", "/api/v2/tokens/me", "integration"])
def test_arbitrary_resources_are_rejected(api, resource):
    with patch("genesys.api.requests.get") as getter:
        with pytest.raises(ValueError):
            api.get_mcp_catalog_page(resource)
    getter.assert_not_called()


def test_mcp_contract_uri_must_be_bound_to_action(api):
    ident = str(uuid4())
    uri = f"/api/v2/integrations/actions/{ident}/schemas/0123456789abcdef"
    with patch("genesys.api.requests.get", return_value=_ok()) as getter:
        api.get_mcp_action_schema(ident, uri)
    assert getter.call_args.kwargs["url"].endswith(uri)
    for untrusted in (
        "https://evil.example/token",
        "/api/v2/integrations/actions/other/schemas/abc",
        f"/api/v2/integrations/actions/{ident}/schemas/abc/../../oauth",
    ):
        with patch("genesys.api.requests.get") as getter:
            with pytest.raises(ValueError):
                api.get_mcp_action_schema(ident, untrusted)
        getter.assert_not_called()


def test_raw_upstream_error_never_reaches_caller(api):
    response = _ok()
    response.status_code = 403
    response.ok = False
    response.content = b'{"token":"SECRET"}'
    with patch("genesys.api.requests.get", return_value=response):
        with pytest.raises(GenesysMcpCatalogError) as exc:
            api.get_mcp_catalog_page("skill")
    assert exc.value.status_code == 403
    assert "SECRET" not in str(exc.value)
