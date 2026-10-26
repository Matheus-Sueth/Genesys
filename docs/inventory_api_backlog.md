# Genesys Cloud — Backlog revisado para inventário de organizações

Base documental: `genesys_api_catalog.json` e `coverage(1).json` fornecidos em 26/10/2026.

- 1528 operações GET no catálogo, 44 correspondências estáticas, 1484 sem correspondência.
- 127 operações P0 heurísticas; seleção revisada: 30 endpoints.
- 0 de 3286 operações apresentam metadados de RBAC no campo extraído `permissions`; valores vazios não indicam ausência de permissão.

## Endpoints selecionados

A ordem sugerida não é uma garantia de execução segura; validar escopos, permissões, disponibilidade regional, paginação e exportação sensível.

### Onda 1 — Núcleo de inventário

| Recurso | Endpoint | Estado da biblioteca | Observação |
|---|---|---|---|
| Identificação da organização | `GET /api/v2/organizations/me` | not_matched_static | Perfil organizacional; evitar retenção de dados desnecessários |
| Inventário de usuários | `GET /api/v2/users` | not_matched_static | Dados pessoais; aplicar minimização na exportação |
| Grupos | `GET /api/v2/groups` | not_matched_static | Paginar e observar divisões |
| Skills de roteamento | `GET /api/v2/routing/skills` | not_matched_static | Relacionar agentes e skills futuramente |
| Idiomas de roteamento | `GET /api/v2/routing/languages` | not_matched_static | Inventariar configurações |
| Data Tables | `GET /api/v2/flows/datatables` | not_matched_static | Inventariar schemas antes das linhas |
| Schedules | `GET /api/v2/architect/schedules` | not_matched_static | Cobrir agendamentos |
| Schedule Groups | `GET /api/v2/architect/schedulegroups` | not_matched_static | Correlacionar com schedules e URAs |
| Emergency Groups | `GET /api/v2/architect/emergencygroups` | not_matched_static | Cobrir exceções operacionais |
| Integrações | `GET /api/v2/integrations` | not_matched_static | Não coletar segredos e credenciais |
| Filas (digest organizacional) | `GET /api/v2/routing/queues/divisionviews/all` | not_matched_static | Retorno simplificado; conferir divisões |
| Sites de telefonia | `GET /api/v2/telephony/providers/edges/sites` | not_matched_static | Validar disponibilidade por arquitetura de telefonia |
| Configuração global de roteamento | `GET /api/v2/routing/settings` | not_matched_static | Configuração, não listagem |
| Configuração global de telefonia | `GET /api/v2/telephony/settings` | not_matched_static | Configuração, não listagem |

### Onda 2 — Cobertura operacional e governança

| Recurso | Endpoint | Estado da biblioteca | Observação |
|---|---|---|---|
| Skill Groups | `GET /api/v2/routing/skillgroups` | not_matched_static | Dependências e membros |
| Domínios de e-mail | `GET /api/v2/routing/email/domains` | not_matched_static | Parâmetros e roteamento |
| Números SMS | `GET /api/v2/routing/sms/phonenumbers` | not_matched_static | Minimizar dados de telecom |
| Edge Groups | `GET /api/v2/telephony/providers/edges/edgegroups` | not_matched_static | Verificar aplicabilidade à arquitetura |
| Rotas de saída | `GET /api/v2/telephony/providers/edges/outboundroutes` | not_matched_static | Configuração de telefonia |
| Pools DID | `GET /api/v2/telephony/providers/edges/didpools` | not_matched_static | Números telefônicos podem ser sensíveis |
| DIDs | `GET /api/v2/telephony/providers/edges/dids` | not_matched_static | Paginação e minimização |
| Clientes OAuth | `GET /api/v2/oauth/clients` | not_matched_static | Revisar cuidadosamente exportação de dados sensíveis |
| Permissões disponíveis | `GET /api/v2/authorization/permissions` | not_matched_static | Metadados de autorização |
| Políticas de retenção | `GET /api/v2/recording/mediaretentionpolicies` | not_matched_static | Somente configuração, não gravações |
| Campanhas outbound | `GET /api/v2/outbound/campaigns` | not_matched_static | Somente metadados de campanhas |
| Deployments digitais | `GET /api/v2/webdeployments/deployments` | not_matched_static | Validar recursos habilitados |
| Formulários de qualidade | `GET /api/v2/quality/forms/evaluations` | not_matched_static | Não coletar avaliações pessoais |
| Bases de conhecimento | `GET /api/v2/knowledge/knowledgebases` | not_matched_static | Metadados antes de conteúdo |
| Flow Milestones | `GET /api/v2/flows/milestones` | not_matched_static | Dependências de fluxos |
| Flow Outcomes | `GET /api/v2/flows/outcomes` | not_matched_static | Dependências de fluxos |

## Critérios de implementação

- Criar métodos de leitura explícitos, com `timeout`, paginação controlada e tratamento para `429` respeitando `Retry-After`.
- Não coletar senhas, secrets, tokens, conteúdo de gravações nem dados pessoais além dos estritamente necessários.
- Preservar a biblioteca existente; testes simulados para comportamento HTTP, paginação e erros antes de qualquer execução em ORG.
- Revisar RBAC no API Explorer e em organização autorizada, pois o Swagger fornecido não traz permissões por operação.
- Reexecutar a auditoria após cada lote e acompanhar aumento de correspondências com o mesmo snapshot do Swagger.

## Observações sobre o relatório original

- `P0` foi atribuído por domínio e ausência de parâmetros obrigatórios, incluindo consultas que não são inventários; não deve ser usado como fila automática de implementação.
- Duas chamadas POST ficaram para revisão manual: `upload_user_prompt_resource_by_url` e `get_usage_events`; isso não afeta diretamente a cobertura GET.
- O script atual analisa correspondências estáticas apenas na classe `Genesys` em `genesys/api.py`, não toda a biblioteca.
