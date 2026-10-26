"""Auditoria estática de chamadas Genesys: não executa código nem faz requisições.

Somente correspondências de método HTTP e caminho resolvido são consideradas
implementadas; chamadas dinâmicas ficam para revisão manual.
"""
from __future__ import annotations

import ast
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_BASES = {"self.URL", "self.URL_AUTH", "self.region.url_api", "self.region.url_auth"}
_PATH = re.compile(r"/api/v2(?:/[^?#]*)?")
_PARAMETER = re.compile(r"^\{[^{}\/]+\}$")
_UNRESOLVED = "__UNRESOLVED__"

# Prioridades de projeto; não são regras oficiais da Genesys.
_DOMAINS = (
    ("identity_access", ("/api/v2/users", "/api/v2/authorization", "/api/v2/groups", "/api/v2/oauth")),
    ("routing", ("/api/v2/routing",)),
    ("architect", ("/api/v2/flows", "/api/v2/architect")),
    ("integrations", ("/api/v2/integrations",)),
    ("telephony", ("/api/v2/telephony", "/api/v2/locations")),
    ("conversations", ("/api/v2/conversations",)),
    ("analytics", ("/api/v2/analytics", "/api/v2/usage")),
)
_INVENTORY_DOMAINS = {"identity_access", "routing", "architect", "integrations", "telephony"}


def _expr(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return aliases.get(node.id)
    if isinstance(node, ast.Attribute):
        return "" if ast.unparse(node) in _BASES else None
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for chunk in node.values:
            if isinstance(chunk, ast.Constant) and isinstance(chunk.value, str):
                parts.append(chunk.value)
            elif isinstance(chunk, ast.FormattedValue):
                rendered = _expr(chunk.value, aliases)
                if rendered == "" and ast.unparse(chunk.value) in _BASES:
                    parts.append("")
                elif rendered is not None and isinstance(chunk.value, ast.Name) and chunk.value.id in aliases:
                    parts.append(rendered)
                elif isinstance(chunk.value, ast.Name) and (
                    chunk.value.id.endswith("_id") or chunk.value.id.endswith("Id") or chunk.value.id.endswith("ID")
                ):
                    parts.append("{var}")
                else:
                    parts.append(_UNRESOLVED)
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _expr(node.left, aliases), _expr(node.right, aliases)
        return left + right if left is not None and right is not None else None
    return None


def _normalize(path: str) -> str | None:
    """Remove query string e normaliza IDs de rota em segmentos completos."""
    match = _PATH.search(path)
    if not match:
        return None
    raw = match.group(0).rstrip("/")
    segments = raw.split("/")
    if any(
        _UNRESOLVED in segment or
        (("{" in segment or "}" in segment) and not _PARAMETER.fullmatch(segment))
        for segment in segments
    ):
        return None
    return "/".join("{}" if _PARAMETER.fullmatch(segment) else segment for segment in segments).lower()


def _request_method(call: ast.Call) -> str | None:
    func = call.func
    if not isinstance(func, ast.Attribute) or func.attr.lower() not in _METHODS:
        return None
    if isinstance(func.value, ast.Name) and func.value.id == "requests":
        return func.attr.upper()
    return None


def _url_argument(call: ast.Call) -> ast.AST | None:
    return next((kw.value for kw in call.keywords if kw.arg == "url"), None) or (
        call.args[0] if call.args else None
    )


def inspect_library(
    source: str, *, file_name: str = "genesys/api.py", class_name: str = "Genesys"
) -> dict[str, Any]:
    """Analisa requests.<método> na classe indicada, sem importar o código."""
    root = ast.parse(source, filename=file_name)
    cls = next(
        (n for n in root.body if isinstance(n, ast.ClassDef) and n.name == class_name), None
    )
    if cls is None:
        raise ValueError(f"Classe {class_name!r} não encontrada em {file_name}")
    calls: list[dict[str, Any]] = []
    for function in cls.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        aliases: dict[str, str] = {}
        for node in sorted(
            ast.walk(function),
            key=lambda n: (getattr(n, "lineno", -1), getattr(n, "col_offset", -1)),
        ):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                value = _expr(node.value, aliases)
                if value is not None:
                    aliases[node.targets[0].id] = value
                else:
                    aliases.pop(node.targets[0].id, None)
            if not isinstance(node, ast.Call):
                continue
            method = _request_method(node)
            if method is None:
                continue
            url_node = _url_argument(node)
            raw = _expr(url_node, aliases) if url_node is not None else None
            canonical = _normalize(raw) if raw is not None else None
            calls.append({
                "method": method,
                "path": canonical,
                "source_method": function.name,
                "file": file_name,
                "line": node.lineno,
                "resolution": "static" if canonical else "manual_review",
            })
    calls.sort(key=lambda x: (x["line"], x["method"]))
    return {
        "class_name": class_name,
        "source_file": file_name,
        "class_methods": sum(
            isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) for f in cls.body
        ),
        "http_calls": len(calls),
        "resolved_http_calls": sum(call["path"] is not None for call in calls),
        "unresolved_http_calls": sum(call["path"] is None for call in calls),
        "calls": calls,
    }


def _domain(path: str) -> str:
    for domain, prefixes in _DOMAINS:
        if any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes):
            return domain
    return "other"


def _priority(operation: Mapping[str, Any], domain: str) -> tuple[str, str]:
    if operation.get("deprecated"):
        return "P3", "Operação obsoleta; verificar substituição antes de implementar"
    if operation.get("method") != "GET":
        return "P3", "Não é GET; avaliar separadamente efeitos colaterais"
    if domain in _INVENTORY_DOMAINS:
        if operation.get("classification") == "collection_candidate":
            return "P0", "Candidato a inventário; validar paginação, filtros e permissões"
        return "P1", "Consulta parametrizada ou detalhamento de recurso"
    if domain in {"conversations", "analytics"}:
        return "P3", "Dados operacionais/históricos; evitar varredura automática"
    return "P2", "Avaliar relevância e custo antes de implementar"


def compare_coverage(
    catalog: Mapping[str, Any], inspection: Mapping[str, Any]
) -> dict[str, Any]:
    """Confronta verbo e rota, jamais apenas o nome da função."""
    available: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for call in inspection["calls"]:
        if call["path"] is not None:
            available[(call["method"], call["path"])].append(call)

    results: list[dict[str, Any]] = []
    unique_ids: set[str] = set()
    for operation in catalog.get("operations", []):
        method, path = operation["method"].upper(), operation["path"]
        identifier = f"{method} {path}"
        if identifier in unique_ids:
            raise ValueError(f"Operação duplicada no catálogo: {identifier}")
        unique_ids.add(identifier)
        matches = available.get((method, _normalize(path)), [])
        domain = _domain(path)
        priority, reason = _priority(operation, domain)
        results.append({
            "id": identifier,
            "method": method,
            "path": path,
            "operation_id": operation.get("operation_id"),
            "summary": operation.get("summary", ""),
            "tags": operation.get("tags", []),
            "deprecated": operation.get("deprecated", False),
            "classification": operation.get("classification"),
            "domain": domain,
            "priority": "implemented" if matches else priority,
            "reason": "Correspondência estática de verbo e rota" if matches else reason,
            "status": "implemented_static" if matches else "not_matched_static",
            "implementations": [
                {"method_name": match["source_method"], "line": match["line"]}
                for match in matches
            ],
        })
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "implemented": 4}
    results.sort(
        key=lambda row: (
            0 if row["status"] == "not_matched_static" else 1,
            order[row["priority"]],
            row["path"],
            row["method"],
        )
    )
    status_counts = Counter(row["status"] for row in results)
    priorities = Counter(
        row["priority"] for row in results if row["status"] == "not_matched_static"
    )
    return {
        "source_sha256": catalog.get("source_sha256"),
        "catalog_total": len(results),
        "static_matches": status_counts["implemented_static"],
        "not_matched_static": status_counts["not_matched_static"],
        "manual_review_calls": [
            call for call in inspection["calls"] if call["resolution"] == "manual_review"
        ],
        "priority_counts": dict(sorted(priorities.items())),
        "inspection": {
            key: inspection[key]
            for key in (
                "class_name", "source_file", "class_methods", "http_calls",
                "resolved_http_calls", "unresolved_http_calls",
            )
        },
        "operations": results,
    }


def export_coverage(
    report: Mapping[str, Any], output_dir: str | Path, *, top: int = 40
) -> None:
    """Gera três artefatos locais: JSON, CSV Excel-friendly e Markdown."""
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "coverage.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    fields = [
        "method", "path", "operation_id", "domain", "status",
        "priority", "classification", "deprecated", "implementations", "reason",
    ]
    with (folder / "coverage.csv").open(
        "w", encoding="utf-8-sig", newline=""
    ) as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for op in report["operations"]:
            writer.writerow({
                key: json.dumps(op.get(key), ensure_ascii=False)
                if key == "implementations" else op.get(key)
                for key in fields
            })

    missing = [
        op for op in report["operations"]
        if op["status"] == "not_matched_static"
    ]
    lines = [
        "# Genesys Cloud — cobertura estática de APIs",
        "",
        f"Operações no catálogo: **{report['catalog_total']}**.",
        f"Correspondências estáticas: **{report['static_matches']}**.",
        f"Não correspondidas: **{report['not_matched_static']}**.",
        f"Chamadas que exigem revisão: **{len(report['manual_review_calls'])}**.",
        "",
        "> Uma operação não correspondida NÃO está comprovadamente ausente. "
        "Wrappers, rotas dinâmicas e outras classes podem existir. "
        "Prioridades são heurísticas locais, não regras oficiais da Genesys.",
        "",
        "## Priorização sugerida", "",
        "| Prioridade | Domínio | Operação |", "|---|---|---|",
    ]
    for op in missing[:top]:
        lines.append(f"| {op['priority']} | {op['domain']} | "+f"\x60{op['id']}\x60 |")
    lines.extend(["", "## Chamadas para revisão manual", ""])
    for call in report["manual_review_calls"]:
        lines.append(
            "- "+f"\x60{call['method']}\x60 em \x60{call['source_method']}\x60 "
            f"(\x60{call['file']}:{call['line']}\x60)"
        )
    if not report["manual_review_calls"]:
        lines.append("Nenhuma.")
    (folder / "coverage.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
