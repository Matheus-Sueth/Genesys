# Genesys — Inventário de organizações (Onda 1)

Implementação baseada no catálogo Swagger capturado em **26/10/2026**, com hash de origem `42887d1f0f046390b5b3dc7a5d5fe697b2323e0bd2ceccecfe7c41aa41558e92` e no backlog `docs/inventory_api_backlog.md`.

## Escopo

Novos métodos da classe `genesys.api.Genesys`:

| Método Python | GET Genesys Cloud | Paginação |
|---|---|---|
| `get_inventory_organization` | `/api/v2/organizations/me` | Não |
| `get_inventory_users` | `/api/v2/users` | Sim |
| `get_inventory_groups` | `/api/v2/groups` | Sim |
| `get_inventory_routing_skills` | `/api/v2/routing/skills` | Sim |
| `get_inventory_routing_languages` | `/api/v2/routing/languages` | Sim |
| `get_inventory_data_tables` | `/api/v2/flows/datatables` | Sim |
| `get_inventory_schedules` | `/api/v2/architect/schedules` | Sim |
| `get_inventory_schedule_groups` | `/api/v2/architect/schedulegroups` | Sim |
| `get_inventory_emergency_groups` | `/api/v2/architect/emergencygroups` | Sim |
| `get_inventory_integrations` | `/api/v2/integrations` | Sim |
| `get_inventory_queue_division_views_all` | `/api/v2/routing/queues/divisionviews/all` | Sim |
| `get_inventory_telephony_sites` | `/api/v2/telephony/providers/edges/sites` | Sim |
| `get_inventory_routing_settings` | `/api/v2/routing/settings` | Não |
| `get_inventory_telephony_settings` | `/api/v2/telephony/settings` | Não |

## Exemplo (utilize seu TokenProvider existente)

```python
from genesys.api import Genesys

client = Genesys(token_provider)  # PKCE ou Client Credentials já configurado
org = client.get_inventory_organization()
primeira_pagina = client.get_inventory_users(page_size=50)
usuarios = client.get_inventory_users(all_pages=True, page_size=50, max_pages=20)
filas = client.get_inventory_queue_division_views_all(all_pages=True)
schedules = client.get_inventory_schedules(params={"name": "Plantao"})
```

**Comportamento:** por padrão, retorna o `dict` original do endpoint. `all_pages=True` retorna uma lista agregada, ordenada por páginas, ou lança erro se houver página repetida, estrutura incompatível ou limite `max_pages` atingido (não retorna silenciosamente uma amostra como inventário completo). O limite padrão é 25 páginas, a página padrão tem 100 registros; parâmetros variam por endpoint e são validados contra a lista extraída do Swagger. `max_pages` entre 1 e 500 e `page_size` entre 1 e 500 são limites da biblioteca, **não** máximos garantidos de cada endpoint Genesys.

### Segurança e desempenho

- Apenas os 14 endpoints GET permitidos; URLs arbitrárias, verbos de escrita ou parâmetros não documentados são rejeitados.
- Reutiliza `auth_headers()` da instância, respeitando PKCE ou Client Credentials já providos pela biblioteca. Não modifica as rotinas existentes.
- `timeout=(5,30)` por chamada. Retry somente de `429`, até 3 novas tentativas, interpretando o `Retry-After` numérico ou HTTP-date. Aborta quando o tempo indicado ultrapassa 60 segundos, em vez de ignorar o cabeçalho.
- HTTP `403`, `404`, demais erros HTTP e erros de conexão interrompem a varredura; mensagens próprias não incluem corpo da resposta nem token.
- **Limites conhecidos:** algumas APIs de integrações podem usar cursor `nextPage`; `all_pages=True` foi desenhado para `pageNumber` e pode sinalizar erro quando a API não oferece paginação numérica utilizável. Consulte a documentação antes de usar em produção.
- Dados pessoais de usuários e informações de infraestrutura podem estar presentes nos payloads brutos. Reduza campos na exportação e restrinja o armazenamento e acesso.
- Permissões RBAC não foram identificadas no campo `permissions` do catálogo fornecido; é obrigatório validar autorização no API Explorer e na ORG.
- Não há execução automática, coleta agendada, gravação, exportação de secrets ou acesso a qualquer ORG durante os testes.

### Testes e acompanhamento

```powershell
python -m unittest discover -s tests -v
python scripts/audit_api_coverage.py --catalog catalog/genesys_api_catalog.json
```

O analisador de cobertura reconhece agora chamadas explícitas a `self._inventory_get('/api/v2/...')`; isso é uma **correspondência estática**, não valida a permissão ou o retorno real. Reexecute a auditoria com o mesmo catálogo para medir a evolução dos 14 endpoints.

Fontes oficiais: [API Explorer](https://developer.genesys.cloud/devapps/api-explorer), [Swagger](https://api.mypurecloud.com/api/v2/docs/swagger).