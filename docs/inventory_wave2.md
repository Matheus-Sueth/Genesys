# Genesys Cloud — Inventário de organizações (Onda 2)

Ampliação da biblioteca `Genesys`, baseada no Swagger extraído em **26/10/2026** (`source_sha256=42887d1f0f046390b5b3dc7a5d5fe697b2323e0bd2ceccecfe7c41aa41558e92`). Novas operações **GET** são executadas apenas quando o usuário as invoca, sem consulta automática a uma organização.

## Endpoints implementados

| Método Python | GET `/api/v2/…` | Paginação |
|---|---|---|
| `get_inventory_skill_groups` | `routing/skillgroups` | Cursor `after` |
| `get_inventory_email_domains` | `routing/email/domains` | `pageNumber` |
| `get_inventory_sms_phone_numbers` | `routing/sms/phonenumbers` | `pageNumber` |
| `get_inventory_telephony_edge_groups` | `telephony/providers/edges/edgegroups` | `pageNumber` |
| `get_inventory_telephony_outbound_routes` | `telephony/providers/edges/outboundroutes` | `pageNumber` |
| `get_inventory_telephony_did_pools` | `telephony/providers/edges/didpools` | `pageNumber` |
| `get_inventory_telephony_dids` | `telephony/providers/edges/dids` | `pageNumber` |
| `get_inventory_oauth_clients` | `oauth/clients` | Sem paginação |
| `get_inventory_authorization_permissions` | `authorization/permissions` | `pageNumber` |
| `get_inventory_media_retention_policies` | `recording/mediaretentionpolicies` | `pageNumber` |
| `get_inventory_outbound_campaigns` | `outbound/campaigns` | `pageNumber` |
| `get_inventory_web_deployments` | `webdeployments/deployments` | Cursor `after` |
| `get_inventory_quality_evaluation_forms` | `quality/forms/evaluations` | `pageNumber` |
| `get_inventory_knowledge_bases` | `knowledge/knowledgebases` | Cursor `after` |
| `get_inventory_flow_milestones` | `flows/milestones` | `pageNumber` |
| `get_inventory_flow_outcomes` | `flows/outcomes` | `pageNumber` |

## Uso

```python
from genesys.api import Genesys

genesys = Genesys(token_provider)  # configuração OAuth já existente

# Página única, com metadados de paginação da API:
resultado = genesys.get_inventory_outbound_campaigns(page_size=50)

# Páginas numéricas: devolve lista completa ou interrompe ao atingir limites:
formularios = genesys.get_inventory_quality_evaluation_forms(
    all_pages=True, max_pages=15, page_size=50,
)

# Cursor after: segue cursors.after / nextUri validada no mesmo endpoint:
knowledge_bases = genesys.get_inventory_knowledge_bases(
    all_pages=True, page_size=50, max_pages=15,
)

# Aplica ocultação recursiva a chaves sensíveis de OAuth:
clientes = genesys.get_inventory_oauth_clients()
```

## Comportamento e segurança

- A API original de **primeira página** retorna `dict`, preservando o envelope. `all_pages=True` retorna uma lista consolidada; a classe evita truncar silenciosamente o inventário e falha quando não consegue determinar a próxima página com segurança.
- As três APIs com cursor (`routing/skillgroups`, `webdeployments/deployments`, `knowledge/knowledgebases`) aceitam `after` e `before` no Swagger; `all_pages=True` percorre apenas `after`. Extraímos `after` de `cursors.after` ou `nextUri` **da mesma rota permitida**, sem seguir links arbitrários.
- Consultas por `pageNumber` reconhecem `pageCount` quando informado e detectam páginas idênticas. Em casos excepcionais com paginação não padrão, o processo falha em vez de afirmar um resultado completo.
- `GET /api/v2/oauth/clients` mascara recursivamente chaves como `clientSecret`, `secret`, `apiKey`, `accessToken`, `refreshToken`, `credentials` e `privateKey` antes do retorno. Isso não substitui controles de acesso no destino do inventário.
- Utiliza o `auth_headers()` existente (PKCE ou Client Credentials), reaproveitando o tratamento de `429` e `Retry-After` da Onda 1, timeout de conexão/leitura `5s/30s`, parâmetros restritos ao Swagger e nenhuma rota GET genérica exposta.
- O limite padrão é de **25 páginas** de **100 itens**; os limites 1–500 são validações internas, não promessas de aceitação de `pageSize` pela Genesys. Serviços podem impor limites menores.
- O Swagger disponibilizado não continha permissões RBAC de forma estruturada; `oauth_scopes` não representa autorização suficiente. Verifique divisões, permissões, disponibilidade da feature e restrições de licenciamento em cada ORG antes de uso em produção.
- Pode haver dados pessoais, telefônicos, credenciais referenciadas e detalhes de configurações. Evite exportar dados brutos desnecessários; revise controles de retenção, logs, permissões e mascaramento no consumidor.
- Os testes locais são **simulados**: não validam o comportamento real de todas as respostas ou cada estratégia de paginação Genesys. Recomenda-se confirmar os tipos de resposta em uma ORG autorizada e trazer exemplos de divergências para ajustes.

## Verificação local

```powershell
python -m unittest discover -s tests -v
python scripts/audit_api_coverage.py --catalog catalog/genesys_api_catalog.json
```

O analisador de cobertura passa a reconhecer as chamadas explícitas de `self._inventory_get_wave2("/api/v2/…")` como GET, assim como os wrappers da primeira onda. Cobertura **estática** não comprova acesso real.

**Referências:** [API Explorer](https://developer.genesys.cloud/devapps/api-explorer), [Swagger Genesys Cloud](https://api.mypurecloud.com/api/v2/docs/swagger), [API Paging](https://developer.genesys.cloud/api/rest/tips/#api-paging).