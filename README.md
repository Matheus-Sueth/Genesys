# Genesys

## Descrição
Genesys é uma biblioteca Python para consumir **toda a Genesys Cloud Platform API** a partir da especificação oficial Swagger/OpenAPI, além de fornecer métodos especializados para APIs frequentes e recursos de Archy. O inventário de organizações é apenas um caso de uso da biblioteca.

## Funcionalidades
- Métodos explícitos de todas as operações ainda não implementadas do catálogo Swagger diretamente em `genesys/api.py`; executor HTTP compartilhado e cliente universal opcional.
- Cliente universal declarativo para todas as operações GET, POST, PUT, PATCH e DELETE catalogadas, com autorização explícita para escrita ([arquitetura e limitações](docs/platform_api_architecture.md)).
- Criar novas URAs e BOTS
- Ler informações existentes de URAs e BOTS
- Atualizar as informações das URAs e BOTS
- Excluir URAs e BOTS não mais necessários
- Consumo das APIs do Genesys Cloud.
- Catálogo consultável das operações Genesys Cloud baseado no Swagger oficial (consulte [a documentação](docs/api_catalog.md)).
- Auditoria estática de cobertura e prioridades de novas APIs ([instruções](docs/api_coverage.md)).
- Inventário de organizações, primeira onda de 14 recursos GET ([uso e limites](docs/inventory_wave1.md)).
- Inventário de governança e canais, Onda 2 com 16 GET ([documentação](docs/inventory_wave2.md)).

## Requisitos
É necessário ter o Python 3.12+, Python 3.11 não pode ser usado ou versões anteriores e Docker instalado na máquina.

## Instalação
Para instalar o projeto Genesys execute o seguinte comando:

        python setup.py install

Ou

        pip install git+https://github.com/Matheus-Sueth/Genesys.git@main
