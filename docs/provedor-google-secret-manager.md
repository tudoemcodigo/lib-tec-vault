[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › 🔷 Provedor Google Secret Manager

# 🔷 Provedor Google Secret Manager

> Lê e grava segredos no Google Cloud Secret Manager pela API REST v1, sem o Google Cloud SDK. A autenticação usa token estático, Service Account JSON (JWT assinado no processo) ou o Metadata Server do Google. Atende só segredos.

---

## 📑 Sumário

- [🎯 Visão geral](#-visão-geral)
- [🚀 Uso](#-uso)
- [🔐 Autenticação](#-autenticação)
- [⚙️ Opções](#️-opções)
- [🧭 Operações](#-operações)
- [⚠️ Limitações](#️-limitações)
- [❌ Mapeamento de erros](#-mapeamento-de-erros)

---

## 🎯 Visão geral

O pacote `TEC.Vault.GoogleSecretManager` implementa `ISecretStore` (e, por herança, `ISecretReader`) e `IVaultHealthProbe` em `GoogleSecretManagerSecretStore`. Não há lixeira (`ISecretRecycleBin`) nem backup (`ISecretBackup`), chaves nem certificados: pedir essas interfaces ao container falha na resolução.

| Aspecto | Comportamento |
|---|---|
| Transporte | `VaultHttpClient`, o mesmo do HashiCorp Vault e do Infisical: retentativa, tempo limite por tentativa e na leitura do corpo, teto de resposta (`MaxResponseBytes`) e redirecionamento desligado |
| Endereço | `Endpoint` conferido na subida com `VaultEndpoint.Validate`: HTTPS, só o servidor (HTTP só em localhost no ambiente Development) |
| Token | `VaultTokenSource`: cache, renovação antes de expirar, um login por vez em concorrência e intervalo de 2 s depois de uma falha. Um 401 descarta o token em cache e repete a chamada uma vez com um token novo |
| Circuit breaker | Ligado por padrão, um por instância (`Http.CircuitBreaker`) |
| Native AOT | JSON escrito com `Utf8JsonWriter` e lido com `JsonDocument`, sem reflexão; valor gravado em Base64 direto dos bytes, que são zerados depois |

---

## 🚀 Uso

### Via código

```csharp
using TEC.Vault.DependencyInjection;
using TEC.Vault.GoogleSecretManager;

builder.Services.AddTecVault(vault => vault
    .UseGoogleSecretManager(options =>
    {
        options.ProjectId = "meu-projeto-gcp";
    }));
```

### Via configuração (`appsettings.json`)

```json
{
  "Vault": {
    "Provider": "GoogleSecretManager",
    "GoogleSecretManager": {
      "ProjectId": "meu-projeto-gcp"
    }
  }
}
```

```csharp
builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers.AddGoogleSecretManager());
```

---

## 🔐 Autenticação

A fonte do token é escolhida na subida, nesta ordem (vale a primeira configurada):

1. **Token estático**: `AccessToken` (só em código) ou a variável indicada em `AccessTokenVariable`. A variável é relida quando o Google recusa o token (401).
2. **Service Account JSON**: o conteúdo da variável `CredentialsJsonVariable` ou o arquivo `CredentialsJsonFile` (padrão: `GOOGLE_APPLICATION_CREDENTIALS`), lido com teto de 64 KB (`BoundedFileReader`) a cada renovação. O provedor assina um JWT RS256 com a chave privada (escopo `cloud-platform`, validade de 1 hora) e o troca por um token no `token_uri` do JSON (padrão `https://oauth2.googleapis.com/token`). Só Service Account: outro `type` (ex.: `authorized_user`, do `gcloud auth application-default login`) é recusado.
3. **Metadata Server** (`metadata.google.internal`), se `UseMetadataServer` for `true` (padrão). Serve Compute Engine, GKE e Cloud Run. A resposta precisa trazer `Metadata-Flavor: Google`; sem ele, o token é recusado.

O `token_uri` do JSON é conferido antes de o JWT sair do processo: precisa ser HTTPS, na porta padrão, sem usuário, query ou fragmento, e o host precisa estar em `AllowedTokenHosts` (padrão: só `oauth2.googleapis.com`; arquivos antigos com `accounts.google.com` pedem esse host na lista). Um arquivo adulterado não consegue mandar a credencial para outro servidor.

Um arquivo de credenciais configurado (opção ou `GOOGLE_APPLICATION_CREDENTIALS`) que não existe derruba a subida, em vez de cair no Metadata Server em silêncio. Sem nenhuma fonte, o construtor lança `InvalidOperationException`. Um login recusado vira `VAULT_AUTENTICACAO_FALHOU` com o código OAuth2 no log (ex.: `400 invalid_grant`); Metadata Server ou endpoint de token fora do ar, `VAULT_INDISPONIVEL`, com a causa no log.

> [!CAUTION]
> `AccessToken` em texto na configuração (`Vault:GoogleSecretManager`) derruba a subida, como nos outros provedores: use `AccessTokenVariable`, uma Service Account em arquivo montado ou o Metadata Server. Em produção, prefira o Metadata Server (Workload Identity no GKE).

---

## ⚙️ Opções

`GoogleSecretManagerOptions`, em `TEC.Vault.GoogleSecretManager`.

| Opção | Padrão | Descrição |
|---|---|---|
| `ProjectId` | `GOOGLE_CLOUD_PROJECT` ou `GCP_PROJECT` | ID ou número do projeto (obrigatório): letras minúsculas, dígitos, `-`, `.` e `:` |
| `Endpoint` | `https://secretmanager.googleapis.com/` | Endereço da API. HTTPS, sem caminho, usuário, query ou fragmento |
| `AccessToken` / `AccessTokenVariable` | `null` | Token OAuth2 estático (`AccessToken` só em código) |
| `CredentialsJsonFile` | `GOOGLE_APPLICATION_CREDENTIALS` | Arquivo da Service Account |
| `CredentialsJsonVariable` | `null` | Variável com o JSON da Service Account |
| `UseMetadataServer` | `true` | Usa o Metadata Server quando não há outra credencial |
| `AllowedTokenHosts` | `oauth2.googleapis.com` | Hosts aceitos no `token_uri` (só em código) |
| `MaxListItems` | `10000` | Teto de itens de uma listagem, de 1 a 1.000.000. Acima dele, `VAULT_LISTAGEM_ACIMA_DO_LIMITE` |
| `Http.MaxRetries` / `Http.NetworkTimeout` / `Http.MaxRetryDelay` / `Http.MaxResponseBytes` | 3 / 30 s / 30 s / 4 MB | Transporte, como nos demais provedores HTTP ([🔁 Resiliência](resiliencia.md)) |
| `Http.Handler` | `null` | Handler próprio (proxy, CA interna); com ele, desligue `AllowAutoRedirect` |
| `Http.CircuitBreaker` | ligado | Veja [🔁 Resiliência](resiliencia.md) |
| `HostEnvironment` | o do container | Libera HTTP em localhost só em Development |
| `TimeProvider` | sistema | Relógio do JWT, do cache de token e do circuito |

O Metadata Server usa tempo limite de no máximo 5 s, até duas retentativas e teto de 64 KB.

Pela configuração são lidas `ProjectId`, `Endpoint`, `AccessTokenVariable`, `CredentialsJsonFile`, `CredentialsJsonVariable`, `UseMetadataServer`, `MaxListItems`, `MaxRetries`, `NetworkTimeout` e a subseção `CircuitBreaker` ([⚙️ Escolha do cofre pela configuração](configuracao-por-appsettings.md)). Chave desconhecida derruba a subida. `AddGoogleSecretManager(o => ...)` aceita um ajuste em código depois da configuração (ex.: `AllowedTokenHosts`, `Http.Handler`).

---

## 🧭 Operações

| Método | Chamada à API | Observações |
|---|---|---|
| `GetSecretAsync` | `GET .../versions/{versão}:access` | Sem `version`, usa `latest`. O valor vem em Base64 e é decodificado como UTF-8; os bytes decodificados são zerados |
| `ExistsAsync` | `GET .../secrets/{nome}` | |
| `ListSecretsAsync` | `GET .../secrets`, página a página | Nome, data de criação e labels (como tags). Acima de `MaxListItems`, `VAULT_LISTAGEM_ACIMA_DO_LIMITE` (nunca uma lista cortada) |
| `ListSecretVersionsAsync` | `GET .../versions`, página a página | `state` diferente de `ENABLED` vira `Enabled = false`; mesmo limite |
| `SetSecretAsync` | `:addVersion`; se o segredo não existir, cria (replicação automática, tags como labels) e grava | Com `Tags` e o segredo já existente, as labels passam a ser exatamente essas (`PATCH`). Tipo de conteúdo, `Enabled = false`, `ExpiresOn` e `NotBefore` voltam `VAULT_ENTRADA_INVALIDA` |
| `UpdateSecretPropertiesAsync` | `PATCH .../secrets/{nome}?updateMask=labels`, `:enable`/`:disable` da versão | `Tags` substitui as labels do segredo; `Enabled` habilita ou desabilita a versão (`latest` se `version` for `null`). Com só tags, não informe `version`. O retorno traz o estado real da versão. Tipo de conteúdo e validade voltam `VAULT_ENTRADA_INVALIDA` |
| `DeleteSecretAsync` | `DELETE .../secrets/{nome}` | Remove o segredo e todas as versões, **sem recuperação**; `ScheduledPurgeDate` fica `null` |
| `CheckAccessAsync` | `GET .../secrets?pageSize=1` | Passa pela base do provedor: circuit breaker, métrica (`secret.health`) e cancelamento propagado |

Limites validados antes da chamada: nome de 1 a 255 caracteres em `[0-9a-zA-Z_-]`, versão `latest` ou só dígitos, valor de até 64 KB, até 50 tags. As tags seguem as regras de labels do Google e são conferidas antes da chamada: chave começando por letra minúscula, só letras minúsculas, dígitos, `_` e `-`, até 63 caracteres (o valor pode ser vazio). Fora disso, `VAULT_ENTRADA_INVALIDA` (campo `tags`).

---

## ⚠️ Limitações

- **Sem lixeira.** A exclusão remove o segredo e todas as versões.
- **Rotação com validade não existe**: `RotateSecretAsync` com `validity` falha, porque a gravação recusa `ExpiresOn`. A desabilitação das versões anteriores funciona.
- **Nomes diferenciam maiúsculas**, como no Google: o cache de segredos trata `Db` e `DB` como itens diferentes.
- **`Enabled` e `Tags` juntos não são atômicos**: as labels são gravadas antes da versão; se a segunda chamada falhar, a primeira já valeu.

---

## ❌ Mapeamento de erros

Conversão padrão dos provedores HTTP; o `error.status` do Google (ex.: `PERMISSION_DENIED`) vai para o log como detalhe, a mensagem não.

| Situação | Código |
|---|---|
| HTTP 404 | `VAULT_ITEM_NAO_ENCONTRADO` (em `ExistsAsync`, `false`) |
| HTTP 409 | `VAULT_CONFLITO` |
| HTTP 400 (ex.: versão desabilitada, `FAILED_PRECONDITION`) | `VAULT_REQUISICAO_RECUSADA` |
| HTTP 403 | `VAULT_ACESSO_NEGADO` |
| HTTP 401 | Token descartado e uma nova tentativa; persistindo, `VAULT_AUTENTICACAO_FALHOU` |
| Login recusado (token estático vazio, Service Account inválida, `token_uri` fora da lista, resposta sem `Metadata-Flavor`) | `VAULT_AUTENTICACAO_FALHOU` |
| HTTP 429 | Repetida com backoff; persistindo, `VAULT_LIMITE_EXCEDIDO` |
| HTTP 5xx, falha de rede e tempo limite (também na leitura do corpo) | `VAULT_INDISPONIVEL` |
| Resposta acima de `MaxResponseBytes`, fora do formato ou com Base64 inválido | `VAULT_FALHA` |
| Listagem acima de `MaxListItems` | `VAULT_LISTAGEM_ACIMA_DO_LIMITE` |

Tabela completa em [❌ Erros](erros.md).

---
⬅️ [☁️ Provedor AWS Secrets Manager](provedor-aws-secrets-manager.md) · [📚 Índice](README.md) · [🔗 Provedor Encadeado](provedor-encadeado.md) ➡️
