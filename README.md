# Tag Alert

Bootstrap enxuto de uma API Laravel 13 em PHP 8.3, executada localmente com
Laravel Sail e PostgreSQL privado na rede Docker do projeto.

## Escopo atual

Este repositório ainda não implementa funcionalidades de negócio. Não há
frontend, dependências Node do projeto, Redis, Horizon, login, pareamento,
autenticação, FCM, alertas, agendador, outbox ou implantação de produção.
Embora a imagem oficial do Sail possa incluir ferramentas Node, elas não são
dependências ou etapas de build da aplicação.

O endpoint `GET http://localhost:8088/api/health` responde
`200 {"status":"ok"}`. É somente uma verificação de liveness; não testa a
conexão com o banco e não é uma readiness check. O endpoint padrão `/up` do
Laravel também continua disponível como liveness. A raiz `/` retorna 404 (não
há página frontend), e rotas de API desconhecidas retornam 404 JSON.

Nenhuma migration foi executada neste bootstrap. Os arquivos padrão de usuário
e migrations do Laravel continuam pendentes e não representam uma
implementação de autenticação.

## Requisitos locais

- PHP 8.3 e Composer no host para instalar dependências com `composer install`.
  O host não precisa de `pdo_pgsql`; os comandos da aplicação rodam no Sail.
- Docker disponível no contexto `default`.

O alvo de runtime planejado para um VPS é PHP 8.3; até aqui, essa versão foi
verificada no Sail, não em um VPS. Os comandos abaixo selecionam o contexto
`default` e o projeto `tag-alert` por execução, sem configurar alias ou alterar
o contexto global do Docker.

O Compose contém somente a aplicação (`laravel.test`) e o PostgreSQL (`pgsql`).
O HTTP é publicado apenas em `127.0.0.1:8088`; o PostgreSQL fica privado na rede
Docker, acessível pela aplicação em `pgsql:5432`, sem porta publicada no host.
A imagem da aplicação é `tag-alert-sail-8.3/app`; o PostgreSQL usa a tag
flutuante `postgres:18-alpine`, que pode avançar dentro da major 18. A versão
18.7 foi observada na verificação local, não está fixada. A major do PostgreSQL
que será usada em um VPS ainda não foi definida nem comparada.

## Primeiro uso e inicialização

Execute na raiz do repositório:

```sh
composer install
test -f .env || cp .env.example .env
DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail up -d --build
if ! grep -q '^APP_KEY=' .env || grep -Eq "^APP_KEY=(\"\"|'')?$" .env; then
    DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail artisan key:generate --no-interaction
fi
```

O `.env` existente é preservado. Gere uma chave somente se `APP_KEY` não
existir ou estiver vazia (sem valor, `""` ou `''`); uma chave existente é
mantida. Não compartilhe nem registre os valores privados desse arquivo. A
inicialização não executa migrations nem instala dependências frontend. Não
rode `sail:install` novamente: o `compose.yaml` já é versionado e essa
instalação pode recriar a configuração e a imagem padrão compartilhada do Sail.

As variáveis `APP_PORT` e `APP_URL` são independentes: altere ambas no `.env`
para manter a porta HTTP e a URL consistentes (não há sincronização automática).
Por exemplo, para usar a porta 8089, defina `APP_PORT=8089` e
`APP_URL=http://localhost:8089` e recrie somente os serviços deste projeto:

```sh
DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail up -d --force-recreate
```

## Testes e verificações

O PHPUnit usa um banco PostgreSQL real chamado `testing`, separado do banco de
desenvolvimento `tag_alert`. Os testes confirmam essa conexão. Execute:

```sh
DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail artisan test --compact
DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail composer validate --strict
DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail composer audit
vendor/bin/pint --dirty --format agent
```

Para salvar o relatório JUnit dos testes:

```sh
DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail artisan test --compact --log-junit storage/logs/task3-results.xml
```

O `composer audit` deve ser avaliado pelo resultado atual do Composer; não
ignore avisos para fazer a verificação parecer aprovada.

## Laravel Boost para OpenCode

Laravel Boost é uma dependência de desenvolvimento. A configuração V2 do
OpenCode em `opencode.json` inicia, a partir da raiz do repositório,
`bash vendor/bin/sail artisan boost:mcp --no-interaction` dentro do ambiente
Sail, onde o driver PostgreSQL está disponível. O Docker local precisa estar
ativo para usar essa integração. A conectividade do arquivo `.mcp.json` com
Claude Code não foi verificada.

## Parar os serviços

Para parar somente os serviços deste projeto, preservando o volume local do
PostgreSQL:

```sh
DOCKER_CONTEXT=default COMPOSE_PROJECT_NAME=tag-alert ./vendor/bin/sail stop
```

Não use `down -v` para a parada rotineira: isso remove o volume do banco.
