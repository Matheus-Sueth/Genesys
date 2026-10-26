# Auditoria de cobertura de APIs Genesys Cloud

Objetivo: comparar **método HTTP + rota normalizada** das operações do [catálogo Swagger](api_catalog.md) com chamadas `requests.get/post/put/patch/delete` encontradas estaticamente em `genesys/api.py`.

## Execução sem OAuth ou consulta à organização

```powershell
git pull origin main
python scripts/update_api_catalog.py
python scripts/audit_api_coverage.py
```

Opcional: `python scripts/update_api_catalog.py --all-methods` e `python scripts/audit_api_coverage.py --catalog catalog/genesys_api_catalog.json --top 100`.

Para executar 100% offline, gere o catálogo a partir de um Swagger salvo previamente com `python scripts/update_api_catalog.py --swagger-file swagger.json`. A auditoria propriamente dita não faz chamadas de rede.

## Saídas

- `reports/api_coverage/coverage.json`: cobertura completa, referências às funções e chamadas dinâmicas a revisar.
- `reports/api_coverage/coverage.csv`: visão tabular, UTF-8 com BOM para Excel.
- `reports/api_coverage/coverage.md`: resumo e filas de implementação priorizadas.

## Critérios

- `implemented_static`: verbo e rota (ignorando nome de IDs de rota e query string) correspondem no código-fonte.
- `not_matched_static`: o detector não achou correspondência; **não significa inexistência comprovada**.
- `manual_review_calls`: chamadas cujo endereço não pôde ser resolvido com segurança por AST.
- `P0`: candidatos a listagem/inventário de identidade, roteamento, Architect, integrações e telefonia.
- `P1`: detalhes/consultas parametrizadas nessas áreas.
- `P2`: outras operações GET.
- `P3`: operações depreciadas, outros verbos e categorias operacionais/Analytics.

A classificação de inventário é **heurística**; requer revisão humana dos filtros, recursos de divisões, paginação, permissões e custos/rate limits. Uma operação GET não é necessariamente adequada a varredura massiva; alguns POSTs são apenas consultas analíticas.

A primeira versão analisa somente a classe `Genesys` do arquivo fornecido, chamadas diretas `requests.*`, strings literais, f-strings com bases conhecidas e aliases simples. Clientes dinâmicos, chamadas em outras classes, HTTP sessions, expressões compostas, roteamento condicional e caminhos dinâmicos desconhecidos não são declarados implementados.

**Não são adicionadas GitHub Actions nem feitas chamadas a organizações.** Os relatórios são gerados sob demanda, não publicam segredos e não alteram `genesys/api.py`.

Referência: https://developer.genesys.cloud/devapps/api-explorer
