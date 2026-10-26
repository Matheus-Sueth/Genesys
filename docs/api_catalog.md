# Catálogo de APIs Genesys Cloud

O módulo `genesys.catalog` transforma a especificação Swagger/OpenAPI oficial em catálogo de operações versionável. Não exige client ID/secret nem acessa dados de nenhuma organização. Por padrão, seleciona somente operações GET.

## Gerar ou atualizar localmente (sem GitHub Actions)

```powershell
python scripts/update_api_catalog.py
# Para registrar GET/POST/PUT/PATCH/DELETE:
python scripts/update_api_catalog.py --all-methods
# Para uma especificação previamente baixada:
python scripts/update_api_catalog.py --swagger-file swagger.json
# Para comparar duas versões:
python scripts/update_api_catalog.py --swagger-file swagger.json --diff-against catalog/genesys_get_catalog.json --output catalog/genesys_get_catalog_new.json
```

Arquivos gerados: `catalog/genesys_get_catalog.json` (GET) ou `catalog/genesys_api_catalog.json` (todos os métodos configurados). Somente são reescritos quando seu conteúdo muda. Revise o JSON e faça commit manual quando desejar. Nenhum workflow agendado é criado.

## Consultar pela biblioteca

```python
from genesys.catalog import fetch_catalog, filter_catalog, load_catalog, diff_catalog

# Atualização sob demanda, sem autenticação:
catalogo = fetch_catalog()
print(catalogo["method_counts"])

# Ou utilizar snapshot gerado e versionado no GitHub:
catalogo = load_catalog("catalog/genesys_get_catalog.json")
filas = filter_catalog(catalogo, tag="Routing", text="queues")
print(filas)
```

Cada operação contém método, caminho, identificador, tags, resumo, parâmetros (inclusive obrigatórios e herdados), candidatos a paginação, possíveis escopos/permissões presentes no Swagger, estado de depreciação e classificação **heurística** (`collection_candidate`, `requires_path_ids` ou `requires_query`). Ausência de permissões/escopos no catálogo **não** significa que a API os dispense. Verifique no API Explorer.

**Atenção:** `collection_candidate` não indica endpoint seguro, barato ou adequado a varredura. O catálogo não executa operações e não faz inventário de uma organização. POSTs de consulta (por exemplo Analytics) também podem ser somente leitura, mas não aparecem no catálogo GET; use `--all-methods` quando necessário.

Especificação: https://api.mypurecloud.com/api/v2/docs/swagger
Documentação: https://developer.genesys.cloud/devapps/api-explorer
