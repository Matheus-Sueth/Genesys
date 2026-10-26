"""Gera catálogo GET da especificação oficial, sem autenticar em organizações."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Permite executar diretamente: python scripts/update_api_catalog.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from genesys.catalog import DEFAULT_SWAGGER_URL, build_catalog, diff_catalog, fetch_catalog, load_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description="Atualiza catálogo de operações Genesys Cloud")
    parser.add_argument("--swagger-file", type=Path, help="Arquivo Swagger local (sem rede)")
    parser.add_argument("--swagger-url", default=DEFAULT_SWAGGER_URL, help="URL da especificação oficial")
    parser.add_argument("--output", type=Path, help="Arquivo de destino, por padrão catalog/genesys_get_catalog.json")
    parser.add_argument("--all-methods", action="store_true", help="Inclui GET/POST/PUT/PATCH/DELETE")
    parser.add_argument("--diff-against", type=Path, help="Compara com catálogo anterior")
    args = parser.parse_args()

    methods = ("GET", "POST", "PUT", "PATCH", "DELETE") if args.all_methods else ("GET",)
    if args.swagger_file:
        document = json.loads(args.swagger_file.read_text(encoding="utf-8-sig"))
        result = build_catalog(document, methods=methods, source_url=str(args.swagger_file))
    else:
        result = fetch_catalog(methods=methods, swagger_url=args.swagger_url)
    output = args.output or Path("catalog/genesys_api_catalog.json" if args.all_methods else "catalog/genesys_get_catalog.json")
    print(f"Operações catalogadas: {result['total_operations']} | {result['method_counts']}")
    if args.diff_against:
        changes = diff_catalog(load_catalog(args.diff_against), result)
        print(f"Diff: +{len(changes['added'])} / -{len(changes['removed'])} / ~{len(changes['changed'])}")
        for name, values in changes.items():
            for item in values:
                print(f"  {name}: {item}")
    content = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.read_text(encoding="utf-8") == content:
        print(f"Sem alterações: {output}")
    else:
        output.write_text(content, encoding="utf-8")
        print(f"Catálogo salvo: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
