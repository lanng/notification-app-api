# Tag Alert API (Backend)

API REST desenvolvida em **Laravel 13 + PHP 8.3 + PostgreSQL** para dar suporte ao aplicativo Android **Tag Alert**, responsável por autenticação do proprietário, pareamento seguro entre aparelho principal (**Host**) e aparelhos de apoio (**Convidado/Suporte**), sincronização sanitizada de saldo/histórico e disparo de alertas remotos em tempo real via **Firebase Cloud Messaging (FCM)**.

> **Aviso:** projeto pessoal e independente, sem vínculo oficial com o C6 Bank. A API nunca recebe nem armazena senhas bancárias, dados de conta ou textos brutos de notificações do banco.

---

## Principais responsabilidades

- **Autenticação do proprietário (Host):** validação estrita de ID tokens do **Firebase Auth (Google)** com verificação de `project_id`, `uid` configurado manualmente no servidor e autenticação recente para ativação ou troca de aparelho Host (com incremento de geração e revogação automática do Host anterior).
- **Pareamento seguro Host ↔ Suporte (Convidado):**
  - Emissão de convites temporários (15 min) com segredo armazenado apenas em hash SHA-256.
  - Resgate por convite com criação de solicitação pendente e aprovação/rejeição explícita pelo Host.
  - Controle de limite de suportes ativos por monitor, listagem e revogação imediata de credenciais Sanctum e tokens FCM.
- **Sincronização sanitizada de saldo e histórico:**
  - O Host publica apenas dados numéricos e metadados sanitizados (saldo estimado em centavos, limite configurado, intervalo de repetição, estado do ciclo de alerta e movimentações do tipo `Reference`, `TagDebit` e `PixCredit`).
  - Convidados autorizados consultam saldo e histórico paginado/filtrável em modo **somente leitura**.
- **Motor de escalonamento de alertas e push FCM:**
  - **Normal** (`saldo >= limite`): encerra alertas ativos e envia evento `alert_cleared`.
  - **Atenção** (`metade <= saldo < limite`): mantém o 1º aviso apenas no Host; a partir do 2º aviso (ou decorrido o intervalo configurado, independentemente de pausa local do Host) ativa o alerta para Convidados e envia push FCM.
  - **Crítico** (`saldo < metade do limite`): ativa imediatamente para Convidados e dispara push FCM de alta prioridade (`alert_escalated`) para acionamento do alarme crítico.
  - Limpeza automática de tokens FCM inválidos/expirados retornados pelo Google e degradação segura em caso de indisponibilidade do serviço de push.

---

## Endpoints principais (`/api/v1`)

### Saúde
- `GET /api/health` — verificação simples de liveness (`{"status":"ok"}`)

### Proprietário e instalação
- `GET /api/v1/owner/monitor` — consulta o monitor configurado para a identidade Google/Firebase verificada
- `POST /api/v1/owner/host-activations` — ativa ou substitui o aparelho Host (controle otimista por geração)
- `GET /api/v1/installation` — valida a credencial Sanctum atual e retorna o papel ativo (`Host` ou `Support`)

### Pareamento e gestão de suportes
- `POST /api/v1/monitors/{monitor}/invitations` — gera convite temporário (Host)
- `GET /api/v1/monitors/{monitor}/invitations` — lista convites disponíveis (Host)
- `DELETE /api/v1/monitors/{monitor}/invitations/{invitation}` — cancela convite (Host)
- `POST /api/v1/pairing-requests` — resgata convite e cria solicitação pendente (público com rate limiting)
- `GET /api/v1/pairing-requests/current` — consulta o status da solicitação pendente
- `GET /api/v1/monitors/{monitor}/pairing-requests` — lista pedidos pendentes (Host)
- `POST /api/v1/monitors/{monitor}/pairing-requests/{pairingRequest}/approval` — aprova suporte (Host)
- `POST /api/v1/monitors/{monitor}/pairing-requests/{pairingRequest}/rejection` — rejeita pedido (Host)
- `GET /api/v1/monitors/{monitor}/supports` — lista suportes ativos (Host)
- `DELETE /api/v1/monitors/{monitor}/supports/{membership}` — revoga suporte e limpa token FCM (Host)

### Sincronização compartilhada e push
- `PUT /api/v1/monitors/{monitor}/snapshot` — publica snapshot sanitizado e entradas recentes do histórico (Host)
- `GET /api/v1/monitors/{monitor}/snapshot` — consulta o último snapshot e severidade calculada (Host ou Suporte)
- `GET /api/v1/monitors/{monitor}/history` — lista histórico sanitizado com paginação por cursor e filtro (`all`, `entries`, `exits`, `adjustments`)
- `PUT /api/v1/installation/push-token` — registra/atualiza o token FCM da instalação ativa
- `DELETE /api/v1/installation/push-token` — remove o token FCM da instalação ativa

---

## Stack e segurança

- **Runtime e framework:** PHP 8.3, Laravel 13, Laravel Sanctum 4, PostgreSQL 18 (Docker / Laravel Sail)
- **Integrações Firebase:** `kreait/firebase-php` 8 (verificação de ID tokens Google/Firebase + envio multicast FCM V1 `data-only` de alta prioridade)
- **Validação e contratos estritos:** middleware `v1.json` com parser JSON estrito, códigos de erro padronizados, rate limiting por IP/identidade/segredo, transações PostgreSQL com `SELECT ... FOR UPDATE` para serialização de mutações e guarda de rollback contra remoção acidental de dados
- **Qualidade e testes:** **479 testes PHPUnit** (3.200+ asserções) executados contra um banco PostgreSQL real isolado (`testing`) protegido por guarda explícita para nunca atingir o banco de desenvolvimento, além de formatação padronizada com **Laravel Pint**

---

## Como executar localmente

### Requisitos
- PHP 8.3 e Composer
- Docker (Laravel Sail)

### Inicialização
```bash
composer install
cp .env.example .env
./vendor/bin/sail up -d --build
./vendor/bin/sail artisan key:generate --no-interaction
./vendor/bin/sail artisan migrate --no-interaction
```

### Configuração do Firebase (opcional para uso com autenticação real e FCM)
Defina no `.env` local (nunca versionado):
- `ACCESS_PAIRING_FIREBASE_ENABLED=true`
- `ACCESS_PAIRING_OWNER_FIREBASE_PROJECT_ID=<id-do-projeto-firebase>`
- `ACCESS_PAIRING_OWNER_FIREBASE_UID=<uid-do-proprietario>`
- `ACCESS_PAIRING_FIREBASE_CREDENTIALS=<caminho-para-service-account.json>`

> Para envio de pushes em tempo real via FCM, a conta de serviço configurada precisa do papel **Firebase Cloud Messaging API Admin** (`cloudmessaging.messages.create`) no Google Cloud IAM.

### Rodar testes e formatação
```bash
./vendor/bin/sail artisan test --compact
./vendor/bin/sail php vendor/bin/pint --dirty
```

---

## Repositório complementar

- **Aplicativo Android (Kotlin + Jetpack Compose):** `notofication-app`
