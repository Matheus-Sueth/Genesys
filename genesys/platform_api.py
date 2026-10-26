"""Cliente universal declarativo da Genesys Cloud Platform API.

Executa somente operações presentes no catálogo Swagger fornecido pelo chamador.
Não executa chamadas ou obtém tokens durante a inicialização.
"""
from __future__ import annotations

import datetime as dt
import email.utils
import json
import re
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlsplit

import requests

_UNSET = object()
_PATH_PARAM = re.compile(r"\{([^{}]+)\}")
_ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


class PlatformAPIError(RuntimeError):
    """Falha HTTP sem expor tokens, payloads ou respostas possivelmente sensíveis."""

    def __init__(self, operation_id: str, status_code: int | None, request_id: str | None = None):
        self.operation_id = operation_id
        self.status_code = status_code
        self.request_id = request_id
        suffix = f" (request id: {request_id})" if request_id else ""
        status = str(status_code) if status_code is not None else "erro de transporte"
        super().__init__(f"Genesys Cloud API {operation_id}: HTTP {status}{suffix}")


def _retry_after(value: str | None, *, clock: float | None = None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (ValueError, TypeError):
        try:
            date = email.utils.parsedate_to_datetime(value)
            if date.tzinfo is None:
                date = date.replace(tzinfo=dt.timezone.utc)
            instant = dt.datetime.fromtimestamp(clock if clock is not None else time.time(), tz=dt.timezone.utc)
            return max(0.0, (date - instant).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None


def _catalog_dict(catalog: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(catalog, (str, Path)):
        result = json.loads(Path(catalog).read_text(encoding="utf-8-sig"))
    else:
        result = dict(catalog)
    if result.get("format_version") != 1 or not isinstance(result.get("operations"), list):
        raise ValueError("Catálogo inválido: execute scripts/update_api_catalog.py --all-methods")
    return result


class PlatformAPIClient:
    """Executor multi-verbo baseado em uma lista de operações do Swagger.

    Usa o objeto `Genesys` existente para obter a URL regional e headers OAuth.
    POST/PUT/PATCH/DELETE exigem autorização explícita por invocação.
    """

    def __init__(
        self,
        genesys_client: Any,
        catalog: str | Path | Mapping[str, Any],
        *,
        session: requests.Session | None = None,
    ) -> None:
        base_url = str(getattr(genesys_client, "URL", "")).rstrip("/")
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.startswith("api.") or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("URL de API Genesys Cloud inválida")
        if not callable(getattr(genesys_client, "auth_headers", None)):
            raise TypeError("Cliente Genesys deve fornecer auth_headers()")
        self._base_url = base_url
        self._genesys = genesys_client
        self._session = session or requests.Session()
        source = _catalog_dict(catalog)
        self.source_sha256 = source.get("source_sha256")
        self._operations: dict[str, dict[str, Any]] = {}
        for item in source["operations"]:
            method, path = item.get("method"), item.get("path")
            if method not in _ALLOWED_METHODS or not isinstance(path, str) or not path.startswith("/api/v2/") or "?" in path or "#" in path or "//" in path:
                raise ValueError("Operação inválida no catálogo")
            identifier = f"{method} {path}"
            if identifier in self._operations:
                raise ValueError(f"Operação duplicada: {identifier}")
            self._operations[identifier] = dict(item)

    @property
    def operation_count(self) -> int:
        return len(self._operations)

    def list_operations(self, method: str | None = None) -> list[str]:
        """Lista operações carregadas sem executar chamadas HTTP."""
        if method is None:
            return sorted(self._operations)
        return sorted(key for key in self._operations if key.startswith(f"{method.upper()} "))

    def operation_info(self, operation_id: str) -> dict[str, Any]:
        if operation_id not in self._operations:
            raise KeyError(f"Operação não catalogada: {operation_id}")
        return dict(self._operations[operation_id])

    def request(
        self,
        operation_id: str,
        *,
        path_params: Mapping[str, Any] | None = None,
        query: Mapping[str, Any] | None = None,
        json_body: Any = _UNSET,
        data: bytes | str | None = None,
        allow_mutation: bool = False,
        timeout: float = 30.0,
        max_retries: int = 2,
        response_mode: str = "auto",
    ) -> Any:
        """Executa uma operação catalogada, mantendo proteções de erro e autenticação.

        response_mode: auto, json, text, bytes ou raw.
        A validação é estrutural (parâmetros); JSON Schema completo não está no catálogo v1.
        """
        operation = self._operations.get(operation_id)
        if operation is None:
            raise KeyError(f"Operação não catalogada: {operation_id}")
        method = operation["method"]
        if method not in ("GET", "HEAD", "OPTIONS") and not allow_mutation:
            raise PermissionError("Operações que podem modificar dados exigem allow_mutation=True")
        if response_mode not in {"auto", "json", "text", "bytes", "raw"}:
            raise ValueError("response_mode inválido")
        if timeout <= 0 or not (0 <= max_retries <= 10):
            raise ValueError("timeout ou max_retries inválido")
        if json_body is not _UNSET and data is not None:
            raise ValueError("Use apenas um dos parâmetros json_body ou data")
        params = dict(path_params or {})
        template = operation["path"]
        required_names = set(_PATH_PARAM.findall(template))
        if set(params) != required_names:
            raise ValueError(f"path_params deve conter exatamente: {sorted(required_names)}")
        for name, value in params.items():
            if value is None or isinstance(value, (dict, list, tuple)):
                raise ValueError(f"Parâmetro de rota inválido: {name}")
            literal = str(value)
            if not literal or literal in {".", ".."} or "/" in literal or "\\" in literal:
                raise ValueError(f"Parâmetro de rota inválido: {name}")
            template = template.replace("{" + name + "}", quote(literal, safe=""))

        query_params = dict(query or {})
        param_specs = {
            p["name"]: p for p in operation.get("parameters", [])
            if p.get("in") == "query" and isinstance(p.get("name"), str)
        }
        unexpected = set(query_params) - set(param_specs)
        if unexpected:
            raise ValueError(f"Parâmetros query não documentados: {sorted(unexpected)}")
        missing = {
            name for name, item in param_specs.items()
            if item.get("required") and (name not in query_params or query_params[name] is None)
        }
        if missing:
            raise ValueError(f"Parâmetros query obrigatórios ausentes: {sorted(missing)}")
        for key, value in query_params.items():
            if value is None:
                continue
            declared = param_specs[key].get("type")
            if declared == "boolean" and isinstance(value, bool):
                query_params[key] = str(value).lower()
            elif declared == "array" and isinstance(value, (list, tuple)):
                query_params[key] = list(value)
            elif isinstance(value, (dict, set)):
                raise ValueError(f"Parâmetro query não serializável: {key}")
        if any(p.get("in") == "body" and p.get("required") for p in operation.get("parameters", [])) and json_body is _UNSET and data is None:
            raise ValueError("Corpo obrigatório ausente (json_body ou data)")

        url = self._base_url + template
        # Não permite substituir Authorization nem encaminhar o token em redirects.
        headers = dict(self._genesys.auth_headers())
        if not any(k.lower() == "authorization" for k in headers):
            raise RuntimeError("auth_headers() não forneceu Authorization")
        attempt = 0
        while True:
            kwargs: dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": headers,
                "params": query_params,
                "timeout": timeout,
                "allow_redirects": False,
            }
            if json_body is not _UNSET:
                kwargs["json"] = json_body
            elif data is not None:
                kwargs["data"] = data
            try:
                response = self._session.request(**kwargs)
            except requests.RequestException:
                raise PlatformAPIError(operation_id, None) from None
            if response.status_code == 429 and method in {"GET", "HEAD"} and attempt < max_retries:
                seconds = _retry_after(response.headers.get("Retry-After"))
                if seconds is None:
                    seconds = min(2 ** attempt, 30)
                # Não antecipe a retomada quando o servidor exigir espera longa.
                # Deixe a aplicação agendar nova tentativa após o Retry-After.
                if seconds > 60:
                    raise PlatformAPIError(operation_id, 429)
                time.sleep(seconds)
                attempt += 1
                continue
            if not 200 <= response.status_code < 300:
                request_id = response.headers.get("inin-correlation-id") or response.headers.get("X-Request-ID")
                raise PlatformAPIError(operation_id, response.status_code, request_id)
            if response_mode == "raw":
                return response
            if response.status_code == 204 or not response.content or method == "HEAD":
                return None
            if response_mode == "bytes":
                return response.content
            if response_mode == "text":
                return response.text
            if response_mode == "json":
                return response.json()
            content_type = response.headers.get("Content-Type", "").lower()
            if "json" in content_type:
                return response.json()
            if content_type.startswith("text/"):
                return response.text
            return response.content