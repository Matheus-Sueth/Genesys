# Genesys Python — cobertura de toda a Platform API

## Direção de produto

A biblioteca `Genesys` não é apenas um módulo de inventário. Seu objetivo é abranger **todas as operações** da Genesys Cloud Platform API, independentemente do verbo HTTP ou do contexto funcional. O snapshot Swagger enviado em 26/10/2026 contém **3.286 operações**: **1.528 GET, 878 POST, 272 PUT, 256 PATCH e 352 DELETE**.

A implementação combina três camadas:

1. **Engine universal declarativa** `genesys.platform_api.PlatformAPIClient`, com dispatch por operação registrada no catálogo, parâmetros de rota, query, body, região, OAuth, timeouts e tratamento de erros.
2. **Métodos especializados** em `genesys.api.Genesys`, preservando a interface histórica e mantendo chamadas de alto nível para operações frequentes.
3. **Catálogo + auditoria** gerados do Swagger; medem tanto a cobertura declarativa quanto as implementações de métodos de conveniência, além das mudanças entre versões.

A implementação oficial `PureCloudPlatformClientV2` também gera suas APIs a partir de Swagger/OpenAPI. Referência: https://github.com/MyPureCloud/platform-client-sdk-python . Ela permanece como opção de consulta/compatibilidade; não é uma dependência obrigatória da biblioteca própria.

## Usar o cliente universal (opt-in)

Gere primeiro um catálogo com todos os métodos e mantenha o JSON local, sem chaves ou tokens:

```powershell
python scripts/update_api_catalog.py --all-methods
```

```python
from genesys.api import Genesys
from genesys.platform_api import PlatformAPIClient

# Genesys já deve estar autenticado usando seu TokenProvider existente.
api = PlatformAPIClient(genesys_client, "catalog/genesys_api_catalog.json")
print(api.operation_count) # 3286 no snapshot de 26/10/2026

users = api.request("GET /api/v2/users", query={"pageSize": 50, "pageNumber": 1})
user = api.request("GET /api/v2/users/{userId}", path_params={"userId": "ID"})

# Operações de escrita exigem opt-in explícito por chamada.
# Não executar abaixo sem autorização para alteração da organização:
# api.request("POST /api/v2/routing/wrapupcodes", json_body={...}, allow_mutation=True)
```

### Garantias e limites do MVP

- Funciona com OAuth Client Credentials ou PKCE já suportados por `genesys.api.Genesys`; não gera token nem consulta organizações até `request()` ser chamado.
- Valida operação catalogada, nomes de `path_params`, parâmetros de query documentados e presença de body quando obrigatório. **Não é validação completa de JSON Schema**: o catálogo v1 não contém esquemas completos de payload e resposta.
- O engine aceita os cinco verbos do snapshot, mas `POST` exige `allow_mutation=True` mesmo quando é uma consulta analítica read-only; não inferir segurança somente pelo verbo.
- Usa GET com retries limitados em `429`, respeitando `Retry-After`. **Não repete mutações automaticamente**; evita duplicações e efeitos colaterais.
- Não segue redirecionamentos automaticamente para evitar encaminhamento inadvertido do token. JSON, texto e binários de resposta são tratados por `response_mode`; uploads multipart e endpoints especiais exigem adaptadores de contrato específicos.
- Não coleta dados em massa automaticamente. Paginação permanece explícita ou encapsulada em métodos especializados, conforme regras do endpoint; rate limits variam por rota.
- **Executável em teoria não equivale a validado em produção:** feature flag, permissões RBAC, OAuth scopes, versões preview, contratos específicos e disponibilidade regional ainda devem ser verificados.
- Catálogo é informado pelo chamador; não é obrigatório embutir o snapshot de 3,3 MB no pacote nem fazer download da especificação a cada requisição.

## Roadmap recomendado

- **Fase 1 — Engine universal (iniciada):** dispatch das 3.286 operações, validação estrutural, autenticação reaproveitada, erros seguros, verbos HTTP e testes com mocks.
- **Fase 2 — Contratos completos:** extrair request/response schemas, enums, formatos e `consumes/produces` do Swagger; tratamento de multipart, media downloads, preview APIs e validação opcional.
- **Fase 3 — Geração de wrappers:** gerar métodos de conveniência por tag/domínio com nomenclatura estável, evitando milhares de alterações manuais em `genesys/api.py`.
- **Fase 4 — Qualidade e compatibilidade:** testes de contrato e snapshot diff, paginação por endpoint, rate limits, retries idempotentes, detecção de breaking changes e documentação/coverage por domínio.
- **Fase 5 — Integrações:** utilização no Sueth CX Forge e ferramentas MCP sem acoplamento a uma única organização; políticas de autorização por domínio e observabilidade segura.

O catálogo não contém dados pessoais de organizações, mas operações que o utilizam podem retornar dados pessoais ou segredos. Evitar logs completos e exigir revisão humana para operações sensíveis.

## Métricas corretas de cobertura

1. **Catalogadas:** operações presentes no Swagger (`3286/3286` na foto de 26/10/2026).
2. **Elegíveis para despacho genérico:** operações suportadas estruturalmente pelo engine e com contratos HTTP básicos (não confundir com funcionais).
3. **Wrappers Python:** operações com métodos especializados na biblioteca (auditadas separadamente).
4. **Testadas:** operações validadas por testes de contrato, sandbox/ORG autorizada ou integração.