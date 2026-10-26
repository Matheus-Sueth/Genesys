"""Consultas GET da Onda 2 de inventário Genesys Cloud.

Implementação estática, sem endpoint arbitrário e sem alteração do OAuth existente.
Contratos de parâmetros baseados no Swagger de 26/10/2026.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

from genesys.inventory_http import _request_page

# Modo de paginação explícito por endpoint.
PAGE_NUMBER = "page_number"
CURSOR = "cursor"
SINGLE = "single"

INVENTORY_WAVE2_ENDPOINTS: dict[str, str] = {
    "/api/v2/routing/skillgroups": CURSOR,
    "/api/v2/routing/email/domains": PAGE_NUMBER,
    "/api/v2/routing/sms/phonenumbers": PAGE_NUMBER,
    "/api/v2/telephony/providers/edges/edgegroups": PAGE_NUMBER,
    "/api/v2/telephony/providers/edges/outboundroutes": PAGE_NUMBER,
    "/api/v2/telephony/providers/edges/didpools": PAGE_NUMBER,
    "/api/v2/telephony/providers/edges/dids": PAGE_NUMBER,
    "/api/v2/oauth/clients": SINGLE,
    "/api/v2/authorization/permissions": PAGE_NUMBER,
    "/api/v2/recording/mediaretentionpolicies": PAGE_NUMBER,
    "/api/v2/outbound/campaigns": PAGE_NUMBER,
    "/api/v2/webdeployments/deployments": CURSOR,
    "/api/v2/quality/forms/evaluations": PAGE_NUMBER,
    "/api/v2/knowledge/knowledgebases": CURSOR,
    "/api/v2/flows/milestones": PAGE_NUMBER,
    "/api/v2/flows/outcomes": PAGE_NUMBER,
}

# Parâmetros permitidos derivados diretamente do Swagger.
WAVE2_QUERY_PARAMETERS: dict[str, frozenset[str]] = {
    "/api/v2/routing/skillgroups": frozenset("after before name pageSize".split()),
    "/api/v2/routing/email/domains": frozenset("excludeStatus expand filter pageNumber pageSize".split()),
    "/api/v2/routing/sms/phonenumbers": frozenset("countryCode expand integration.id language pageNumber pageSize phoneNumber phoneNumberStatus phoneNumberType sortBy sortOrder supportedContent.id".split()),
    "/api/v2/telephony/providers/edges/edgegroups": frozenset("managed name pageNumber pageSize sortBy".split()),
    "/api/v2/telephony/providers/edges/outboundroutes": frozenset("externalTrunkBases.ids name pageNumber pageSize site.id sortBy".split()),
    "/api/v2/telephony/providers/edges/didpools": frozenset("id pageNumber pageSize sortBy".split()),
    "/api/v2/telephony/providers/edges/dids": frozenset("didPool.id id owner.id pageNumber pageSize phoneNumber sortBy sortOrder".split()),
    "/api/v2/oauth/clients": frozenset(),
    "/api/v2/authorization/permissions": frozenset("pageNumber pageSize query queryType".split()),
    "/api/v2/recording/mediaretentionpolicies": frozenset("deleteDaysThreshold enabled expand hasErrors name nextPage pageNumber pageSize previousPage sortBy summary".split()),
    "/api/v2/outbound/campaigns": frozenset("callAnalysisResponseSetId contactListId distributionQueueId divisionId dncListIds edgeGroupId filterType id name pageNumber pageSize sortBy sortOrder".split()),
    "/api/v2/webdeployments/deployments": frozenset("after before expand pageSize".split()),
    "/api/v2/quality/forms/evaluations": frozenset("expand name nextPage pageNumber pageSize previousPage sortBy sortOrder".split()),
    "/api/v2/knowledge/knowledgebases": frozenset("after before coreLanguage limit name pageSize published sortBy sortOrder".split()),
    "/api/v2/flows/milestones": frozenset("description divisionId id name nameOrDescription pageNumber pageSize sortBy sortOrder".split()),
    "/api/v2/flows/outcomes": frozenset("description divisionId id name nameOrDescription pageNumber pageSize sortBy sortOrder".split()),
}

# Evita coletar/expor segredos eventualmente devolvidos no cadastro OAuth.
_SECRET_KEYS = frozenset({
    "clientsecret", "secret", "password", "accesstoken", "refreshtoken",
    "apikey", "privatekey", "authorization", "credential", "credentials",
})
_RECORD_KEYS = ("entities", "items", "results", "deployments", "knowledgeBases", "skillGroups")


def _redact_oauth(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if re.sub(r"[^a-z0-9]", "", key.lower()) in _SECRET_KEYS else _redact_oauth(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_oauth(item) for item in value]
    return value


def _items(payload: Any, path: str) -> list[Any]:
    if not isinstance(payload, dict):
        raise ValueError(f"GET {path}: resposta paginada não é objeto JSON")
    for key in _RECORD_KEYS:
        if isinstance(payload.get(key), list):
            return payload[key]
    raise ValueError(f"GET {path}: nenhuma coleção reconhecida; não é possível concluir inventário")


def _next_cursor(payload: dict[str, Any], path: str) -> str | None:
    cursors = payload.get("cursors") or {}
    if isinstance(cursors, dict):
        after = cursors.get("after")
        if isinstance(after, str) and after:
            return after
    # Há APIs Genesys que oferecem somente nextUri. A URI não é seguida;
    # extraímos exclusivamente o token do mesmo path já autorizado.
    uri = payload.get("nextUri") or payload.get("nextURI")
    if uri:
        if not isinstance(uri, str):
            raise ValueError(f"GET {path}: nextUri inesperada")
        parsed = urlsplit(uri)
        if parsed.scheme or parsed.netloc or parsed.path != path:
            raise ValueError(f"GET {path}: nextUri não corresponde ao endpoint permitido")
        tokens = parse_qs(parsed.query).get("after", [])
        if len(tokens) == 1 and tokens[0]:
            return tokens[0]
        raise ValueError(f"GET {path}: nextUri sem cursor after válido")
    return None


def inventory_get_wave2(
    client: Any,
    path: str,
    *,
    params: Mapping[str, Any] | None = None,
    all_pages: bool = False,
    max_pages: int = 25,
    page_size: int = 100,
    timeout: tuple[int, int] = (5, 30),
    max_retries: int = 3,
    max_retry_after: float = 60,
) -> Any:
    """GET autorizado: dict original (padrão) ou lista completa (all_pages=True).

    Em erro de paginação, falha sem retornar coleta parcial silenciosamente.
    """
    mode = INVENTORY_WAVE2_ENDPOINTS.get(path)
    if mode is None:
        raise ValueError("Endpoint fora da Onda 2 de inventário")
    if type(max_pages) is not int or not 1 <= max_pages <= 500:
        raise ValueError("max_pages deve estar entre 1 e 500")
    if type(page_size) is not int or not 1 <= page_size <= 500:
        raise ValueError("page_size deve estar entre 1 e 500")
    if type(max_retries) is not int or not 0 <= max_retries <= 5:
        raise ValueError("max_retries deve estar entre 0 e 5")
    if not isinstance(max_retry_after, (int, float)) or not math.isfinite(max_retry_after) or max_retry_after < 0:
        raise ValueError("max_retry_after deve ser um número não negativo")
    if len(timeout) != 2 or any(type(n) not in (int, float) or not math.isfinite(n) or n <= 0 for n in timeout):
        raise ValueError("timeout deve conter connect/read positivos")
    parameters = dict(params or {})
    unknown = set(parameters) - WAVE2_QUERY_PARAMETERS[path]
    if unknown:
        raise ValueError(f"Parâmetros não documentados em {path}: {', '.join(sorted(unknown))}")
    if "pageSize" in parameters and parameters["pageSize"] != page_size:
        raise ValueError("Use page_size em vez de params['pageSize']")
    if all_pages and mode == SINGLE:
        raise ValueError(f"GET {path} não usa paginação; omita all_pages")
    if all_pages and mode == PAGE_NUMBER and ("nextPage" in parameters or "previousPage" in parameters):
        raise ValueError("Não combinar paginação por página com cursores nextPage/previousPage")
    if all_pages and mode == CURSOR and "before" in parameters:
        raise ValueError("all_pages percorre somente a direção after")

    def request(p: dict[str, Any]) -> Any:
        result = _request_page(client, path, p, timeout, max_retries, max_retry_after)
        return _redact_oauth(result) if path == "/api/v2/oauth/clients" else result

    if mode == SINGLE:
        return request(parameters)
    parameters["pageSize"] = page_size
    if mode == PAGE_NUMBER:
        first = parameters.get("pageNumber", 1)
        if type(first) is not int or first < 1:
            raise ValueError("pageNumber deve ser inteiro positivo")
        if not all_pages:
            parameters["pageNumber"] = first
            return request(parameters)
        results: list[Any] = []
        signatures: set[str] = set()
        for offset in range(max_pages):
            number = first + offset
            parameters["pageNumber"] = number
            payload = request(parameters)
            items = _items(payload, path)
            signature = json.dumps(items, ensure_ascii=False, sort_keys=True, default=str)
            if items and signature in signatures:
                raise RuntimeError(f"GET {path}: página repetida; inventário incompleto")
            signatures.add(signature)
            results.extend(items)
            count = payload.get("pageCount")
            more = number < count if type(count) is int and count >= 0 else len(items) >= page_size and bool(items)
            if not more:
                return results
        raise RuntimeError(f"GET {path}: max_pages={max_pages} atingido; inventário incompleto")

    if not all_pages:
        return request(parameters)
    cursor = parameters.get("after")
    if cursor is not None and (not isinstance(cursor, str) or not cursor):
        raise ValueError("after deve ser string não vazia")
    seen_cursors: set[str] = set()
    records: list[Any] = []
    for _ in range(max_pages):
        if cursor:
            if cursor in seen_cursors:
                raise RuntimeError(f"GET {path}: cursor repetido; inventário incompleto")
            seen_cursors.add(cursor)
            parameters["after"] = cursor
        payload = request(parameters)
        items = _items(payload, path)
        records.extend(items)
        next_cursor = _next_cursor(payload, path)
        if not next_cursor:
            if len(items) >= page_size:
                raise RuntimeError(f"GET {path}: página cheia sem cursor de continuação; revisar manualmente")
            return records
        cursor = next_cursor
    raise RuntimeError(f"GET {path}: max_pages={max_pages} atingido; inventário incompleto")