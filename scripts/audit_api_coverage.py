"""Auditoria offline da cobertura do Genesys Cloud catalog."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from genesys.catalog import load_catalog
from genesys.coverage import compare_coverage, export_coverage, inspect_library


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compara biblioteca com catálogo Swagger sem fazer chamadas à ORG"
    )
    parser.add_argument("--catalog", type=Path, default=Path("catalog/genesys_get_catalog.json"))
    parser.add_argument("--source", type=Path, default=Path("genesys/api.py"))
    parser.add_argument("--class-name", default="Genesys")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/api_coverage"))
    parser.add_argument("--top", type=int, default=40)
    args = parser.parse_args()

    if not args.catalog.exists():
        parser.error(
            f"Catálogo não existe: {args.catalog}. "
            "Execute python scripts/update_api_catalog.py primeiro"
        )
    if not args.source.exists():
        parser.error(f"Código-fonte não existe: {args.source}")
    catalog = load_catalog(args.catalog)
    inspection = inspect_library(
        args.source.read_text(encoding="utf-8-sig"),
        file_name=str(args.source),
        class_name=args.class_name,
    )
    result = compare_coverage(catalog, inspection)
    export_coverage(result, args.output_dir, top=max(0, args.top))
    print(
        f"Catálogo: {result['catalog_total']} | "
        f"Correspondências estáticas: {result['static_matches']} | "
        f"Não correspondidas: {result['not_matched_static']}"
    )
    print(f"Chamadas dinâmicas para revisão: {len(result['manual_review_calls'])}")
    print(f"Prioridades propostas: {result['priority_counts']}")
    print(f"Relatórios: {args.output_dir}/coverage.json, coverage.csv, coverage.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
