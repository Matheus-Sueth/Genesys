# Genesys

## Descrição
O projeto Genesys é uma ferramenta para gerenciar aplicação do Archy e as APIs do Genesys Cloud. Fornece uma interface para gerenciar eficientemente esses recursos diretamente no Genesys Cloud e no banco de dados local.

## Funcionalidades
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
