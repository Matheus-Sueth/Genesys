"""Catálogo estático de operações Genesys Cloud; não consulta organizações."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

import requests

HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
PAGINATION_NAMES = frozenset({"pagenumber", "pagesize", "page", "limit", "cursor", "after", "before", "offset"})
DEFAULT_SWAGGER_URL = "https://api.mypurecloud.com/api/v2/docs/swagger"
CATALOG_FORMAT_VERSION = 1


def _resolve_ref(document: Mapping[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValueError(f"Referência externa não suportada: {reference}")
    value: Any = document
    for segment in reference[2:].split("/"):
        segment = segment.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or segment not in value:
            raise ValueError(f"Referência Swagger não encontrada: {reference}")
        value = value[segment]
    if not isinstance(value, dict):
        raise ValueError(f"Referência Swagger inválida: {reference}")
    return value


def _parameters(document: Mapping[str, Any], path_item: Mapping[str, Any], operation: Mapping[str, Any]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in (*path_item.get("parameters", []), *operation.get("parameters", [])):
        param = _resolve_ref(document, raw["$ref"]) if "$ref" in raw else raw
        if not isinstance(param, dict):
            raise ValueError("Parâmetro Swagger inválido")
        position, name = param.get("in"), param.get("name")
        if not position or not name:
            raise ValueError("Parâmetro Swagger sem 'in' ou 'name'")
        schema = param.get("schema") or {}
        merged[(position, name)] = {
            "name": name,
            "in": position,
            "required": bool(param.get("required", False)),
            "type": param.get("type") or schema.get("type") or ("object" if schema.get("$ref") else None),
        }
    return sorted(merged.values(), key=lambda item: (item["in"], item["name"]))


def _security_scopes(document: Mapping[str, Any], operation: Mapping[str, Any]) -> list[str]:
    security = operation.get("security", document.get("security", []))
    scopes: set[str] = set()
    for choice in security or []:
        if isinstance(choice, dict):
            for values in choice.values():
                if isinstance(values, list):
                    scopes.update(scope for scope in values if isinstance(scope, str))
    return sorted(scopes)


def _vendor_list(operation: Mapping[str, Any], keys: Iterable[str]) -> list[str]:
    values: set[str] = set()
    for key in keys:
        value = operation.get(key)
        if isinstance(value, str):
            values.add(value)
        elif isinstance(value, list):
            values.update(item for item in value if isinstance(item, str))
    return sorted(values)


def build_catalog(document: Mapping[str, Any], methods: Iterable[str] = ("GET",), source_url: str = DEFAULT_SWAGGER_URL) -> dict[str, Any]:
    """Transforma Swagger 2.0/OpenAPI 3.x em catálogo determinístico, sem fazer chamadas à ORG."""
    if not isinstance(document, dict) or not isinstance(document.get("paths"), dict):
        raise ValueError("Swagger/OpenAPI inválido: campo 'paths' ausente")
    if not (document.get("swagger") == "2.0" or str(document.get("openapi", "")).startswith("3.")):
        raise ValueError("Especificação precisa ser Swagger 2.0 ou OpenAPI 3.x")
    requested = {method.lower() for method in methods}
    if not requested or requested - HTTP_METHODS:
        raise ValueError("Métodos HTTP solicitados inválidos")

    operations: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for path, item in sorted(document["paths"].items()):
        if not isinstance(item, dict):
            continue
        for method, operation in sorted(item.items()):
            if method.lower() not in requested or method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            params = _parameters(document, item, operation)
            required_path = [p["name"] for p in params if p["in"] == "path" and p["required"]]
            required_query = [p["name"] for p in params if p["in"] == "query" and p["required"]]
            pagination = [p["name"] for p in params if p["in"] == "query" and p["name"].lower() in PAGINATION_NAMES]
            classification = "requires_path_ids" if required_path else "requires_query" if required_query else "collection_candidate"
            api_method = method.upper()
            identifier = f"{api_method} {path}"
            if identifier in seen_ids:
                raise ValueError(f"Operação duplicada: {identifier}")
            seen_ids.add(identifier)
            operations.append({
                "id": identifier,
                "method": api_method,
                "path": path,
                "operation_id": operation.get("operationId"),
                "tags": operation.get("tags", []),
                "summary": operation.get("summary", ""),
                "deprecated": bool(operation.get("deprecated", False)),
                "parameters": params,
                "required_path_parameters": required_path,
                "required_query_parameters": required_query,
                "pagination_parameters": pagination,
                "classification": classification,
                "oauth_scopes": sorted(set(_security_scopes(document, operation) + _vendor_list(operation, ("x-purecloud-scopes", "x-required-scopes")))),
                "permissions": _vendor_list(operation, ("x-purecloud-permissions", "x-required-permissions")),
            })
    counts = Counter(op["method"] for op in operations)
    canonical = json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return {
        "format_version": CATALOG_FORMAT_VERSION,
        "source_url": source_url,
        "source_sha256": hashlib.sha256(canonical).hexdigest(),
        "source_api_version": document.get("info", {}).get("version"),
        "total_operations": len(operations),
        "method_counts": dict(sorted(counts.items())),
        "operations": operations,
    }


def filter_catalog(catalog: Mapping[str, Any], *, method: str | None = None, tag: str | None = None, text: str | None = None, classification: str | None = None, include_deprecated: bool = True) -> list[dict[str, Any]]:
    """Pesquisa metadados de operações em memória."""
    results = []
    for op in catalog.get("operations", []):
        if method and op["method"] != method.upper():
            continue
        if tag and tag.lower() not in {t.lower() for t in op.get("tags", [])}:
            continue
        if classification and op.get("classification") != classification:
            continue
        if not include_deprecated and op.get("deprecated"):
            continue
        if text and text.lower() not in " ".join((op.get("path", ""), op.get("summary", ""), op.get("operation_id") or "")).lower():
            continue
        results.append(op)
    return results


def diff_catalog(previous: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, list[str]]:
    """Aponta operações adicionadas, removidas e com metadados alterados."""
    before = {op["id"]: op for op in previous.get("operations", [])}
    after = {op["id"]: op for op in current.get("operations", [])}
    return {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "changed": sorted(k for k in before.keys() & after.keys() if before[k] != after[k]),
    }


def load_catalog(path: str | Path) -> dict[str, Any]:
    catalog = json.loads(Path(path).read_text(encoding="utf-8"))
    if catalog.get("format_version") != CATALOG_FORMAT_VERSION:
        raise ValueError("Versão do formato de catálogo não suportada")
    return catalog


def fetch_catalog(*, methods: Iterable[str] = ("GET",), swagger_url: str = DEFAULT_SWAGGER_URL, timeout: tuple[int, int] = (10, 90)) -> dict[str, Any]:
    """Baixa apenas documentação Swagger, sem token nem consulta à organização."""
    response = requests.get(swagger_url, timeout=timeout, headers={"Accept": "application/json"})
    response.raise_for_status()
    return build_catalog(response.json(), methods=methods, source_url=swagger_url)
