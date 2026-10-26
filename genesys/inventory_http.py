"""Cliente GET restrito para inventário de organizações Genesys Cloud.

Não expõe respostas de erro ou tokens em mensagens de exceção. Os endpoints são
explicitamente autorizados e provêm do catálogo Swagger de 26/10/2026.
"""
from __future__ import annotations

import email.utils
import json
import math
import time
from datetime import datetime, timezone
from typing import Any, Mapping

import requests

# True = endpoint com pageNumber/pageSize; False = recurso único.
INVENTORY_ENDPOINTS: dict[str, bool] = {
    "/api/v2/organizations/me": False,
    "/api/v2/users": True,
    "/api/v2/groups": True,
    "/api/v2/routing/skills": True,
    "/api/v2/routing/languages": True,
    "/api/v2/flows/datatables": True,
    "/api/v2/architect/schedules": True,
    "/api/v2/architect/schedulegroups": True,
    "/api/v2/architect/emergencygroups": True,
    "/api/v2/integrations": True,
    "/api/v2/routing/queues/divisionviews/all": True,
    "/api/v2/telephony/providers/edges/sites": True,
    "/api/v2/routing/settings": False,
    "/api/v2/telephony/settings": False,
}

_QUERY: dict[str, frozenset[str]] = {
    "/api/v2/users": frozenset("expand id integrationPresenceSource jabberId pageNumber pageSize sortOrder state userCustomAttributeSchemaIds".split()),
    "/api/v2/groups": frozenset("id jabberId pageNumber pageSize sortOrder".split()),
    "/api/v2/routing/skills": frozenset("id name pageNumber pageSize".split()),
    "/api/v2/routing/languages": frozenset("id name pageNumber pageSize sortOrder".split()),
    "/api/v2/flows/datatables": frozenset("divisionId expand name pageNumber pageSize sortBy sortOrder".split()),
    "/api/v2/architect/schedules": frozenset("divisionId name pageNumber pageSize sortBy sortOrder".split()),
    "/api/v2/architect/schedulegroups": frozenset("divisionId name pageNumber pageSize scheduleIds sortBy sortOrder".split()),
    "/api/v2/architect/emergencygroups": frozenset("name pageNumber pageSize sortBy sortOrder".split()),
    "/api/v2/integrations": frozenset("credentialId expand ids integrationType nextPage pageNumber pageSize previousPage reportedState sortBy".split()),
    "/api/v2/routing/queues/divisionviews/all": frozenset("pageNumber pageSize sortOrder".split()),
    "/api/v2/telephony/providers/edges/sites": frozenset("expand location.id managed name pageNumber pageSize sortBy sortOrder".split()),
}


def _retry_after(headers: Mapping[str, str], attempt: int) -> float:
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw:
        try:
            delay = float(raw)
            if math.isfinite(delay) and delay >= 0:
                return delay
        except (TypeError, ValueError):
            try:
                date = email.utils.parsedate_to_datetime(raw)
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                return max(0.0, (date - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                pass
    return float(min(2 ** attempt, 8))


def _request_page(client: Any, path: str, parameters: dict[str, Any], timeout: tuple[int, int], max_retries: int, max_retry_after: float) -> Any:
    for attempt in range(max_retries + 1):
        response = requests.get(
            f"{client.URL.rstrip('/')}{path}",
            headers=client.auth_headers(),
            params=dict(parameters),
            timeout=timeout,
        )
        if response.status_code == 429 and attempt < max_retries:
            delay = _retry_after(response.headers, attempt)
            if delay > max_retry_after:
                raise RuntimeError(f"GET {path}: Retry-After acima do limite configurado ({max_retry_after}s)")
            time.sleep(delay)
            continue
        if not response.ok:
            raise requests.HTTPError(
                f"GET {path}: HTTP {response.status_code} (sem exposição de resposta ou credenciais)",
                response=response,
            )
        return response.json()
    raise AssertionError("Fluxo de tentativas inconsistente")


def inventory_get(
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
    """Obtém resposta bruta (padrão) ou lista agregada (all_pages=True).

    Falha se exceder max_pages: não retorna inventário truncado silenciosamente.
    """
    if path not in INVENTORY_ENDPOINTS:
        raise ValueError("Endpoint fora da lista de inventário permitida")
    if not isinstance(max_pages, int) or not 1 <= max_pages <= 500:
        raise ValueError("max_pages deve estar entre 1 e 500")
    if not isinstance(page_size, int) or not 1 <= page_size <= 500:
        raise ValueError("page_size deve estar entre 1 e 500")
    if not isinstance(max_retries, int) or not 0 <= max_retries <= 5:
        raise ValueError("max_retries deve estar entre 0 e 5")
    if not isinstance(max_retry_after, (int, float)) or not math.isfinite(max_retry_after) or max_retry_after < 0:
        raise ValueError("max_retry_after deve ser um número não negativo")
    if len(timeout) != 2 or any(not isinstance(t, (int, float)) or t <= 0 for t in timeout):
        raise ValueError("timeout deve conter connect/read positivos")
    parameters = dict(params or {})
    unknown = set(parameters) - _QUERY.get(path, frozenset())
    if unknown:
        raise ValueError(f"Parâmetros não documentados em {path}: {', '.join(sorted(unknown))}")
    paged = INVENTORY_ENDPOINTS[path]
    if all_pages and not paged:
        raise ValueError(f"Endpoint {path} não possui paginação")
    if not paged:
        return _request_page(client, path, parameters, timeout, max_retries, max_retry_after)

    if "pageSize" in parameters and parameters["pageSize"] != page_size:
        raise ValueError("Use page_size em vez de params['pageSize']")
    if all_pages and ("nextPage" in parameters or "previousPage" in parameters):
        raise ValueError("Paginação por cursor de integração requer consulta manual")
    parameters["pageSize"] = page_size
    first_page = parameters.get("pageNumber", 1)
    if not isinstance(first_page, int) or first_page < 1:
        raise ValueError("pageNumber deve ser inteiro positivo")
    if not all_pages:
        parameters["pageNumber"] = first_page
        return _request_page(client, path, parameters, timeout, max_retries, max_retry_after)

    records: list[Any] = []
    seen_pages: set[str] = set()
    for offset in range(max_pages):
        number = first_page + offset
        parameters["pageNumber"] = number
        payload = _request_page(client, path, parameters, timeout, max_retries, max_retry_after)
        if not isinstance(payload, dict):
            raise ValueError(f"GET {path}: paginação esperava objeto JSON")
        items = next((payload[key] for key in ("entities", "items", "results") if isinstance(payload.get(key), list)), None)
        if items is None:
            raise ValueError(f"GET {path}: não foi encontrada lista paginável")
        signature = json.dumps(items, sort_keys=True, ensure_ascii=False, default=str)
        if signature in seen_pages and items:
            raise RuntimeError(f"GET {path}: página repetida; inventário incompleto")
        seen_pages.add(signature)
        records.extend(items)
        page_count = payload.get("pageCount")
        if isinstance(page_count, int) and page_count >= 0:
            more = number < page_count
        else:
            more = len(items) >= page_size and bool(items)
        if not more:
            return records
    raise RuntimeError(f"GET {path}: max_pages={max_pages} atingido; inventário incompleto")