# Métodos explícitos da Platform API (v3.7.0)

As operações da especificação Swagger 26/10/2026 foram confrontadas com os métodos preexistentes em `genesys/api.py`. Esta versão preserva os métodos originais e insere 3175 wrappers identificados como ausentes, de um catálogo de 3286 operações. 111 rotas foram identificadas no código existente e mantidas. 0 nomes conflitantes ganharam o sufixo `_platform` para não sobrescrever funções.

Cada wrapper possui nome Python derivado do `operationId` oficial, parâmetros de caminho explícitos quando necessário, `params` opcional para query string, `body` opcional para JSON em POST/PUT/PATCH/DELETE e `**kwargs` para recursos do executor HTTP. O executor `_request_platform_api` pertence à classe `Genesys` e compartilha o TokenProvider da instância. Uploads exigem `data` ou `files`, com cabeçalhos adequados; downloads podem usar `response_mode='bytes'` ou `'response'`.

**Limitação:** os métodos não garantem os schemas completos e as permissões RBAC; o catálogo original traz nomes e tipos dos parâmetros, mas não o modelo completo de request/response. Algumas operações exigem tratamento especial de `content-type`, validações, filtros e comportamento assíncrono. A existência do wrapper não equivale a teste funcional em ORG. Especificações devem ser consultadas no API Explorer oficial antes de uso em produção.

Escritas nunca recebem retry automático. GETs podem repetir HTTP 429 respeitando Retry-After. A biblioteca não executa qualquer operação automaticamente. O `PlatformAPIClient` foi preservado para uso alternativo enquanto os wrappers especializados forem validados.
