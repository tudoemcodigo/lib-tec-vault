[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › ☁️ Provedor AWS Secrets Manager

# ☁️ Provedor AWS Secrets Manager

> Lê e grava segredos no AWS Secrets Manager pela API REST da AWS (protocolo JSON 1.1), com assinatura AWS Signature Version 4 (SigV4) feita no próprio pacote, sem o SDK oficial. Atende só segredos.

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

O pacote `TEC.Vault.AwsSecretsManager` implementa `ISecretStore` (e, por herança, `ISecretReader`) e `IVaultHealthProbe` em `AwsSecretsManagerSecretStore`. Não há lixeira (`ISecretRecycleBin`) nem backup (`ISecretBackup`), chaves nem certificados: pedir essas interfaces ao container falha na resolução.

| Aspecto | Comportamento |
|---|---|
| Transporte | `VaultHttpClient`, o mesmo do HashiCorp Vault e do Infisical: retentativa, tempo limite por tentativa e na leitura do corpo, teto de resposta (`MaxResponseBytes`) e redirecionamento desligado |
| Endereço | `Endpoint` conferido na subida com `VaultEndpoint.Validate`: HTTPS, só o servidor (HTTP só em localhost no ambiente Development, para o LocalStack) |
| Assinatura | SigV4 com `HMACSHA256` e `SHA256` do runtime, serviço `secretsmanager`; cada tentativa é assinada de novo e as chaves derivadas são zeradas depois do uso |
| Credenciais | `VaultTokenSource`: cache, renovação antes de expirar, um login por vez em concorrência e intervalo de 2 s depois de uma falha ([🔐 Autenticação](#-autenticação)) |
| Erros da AWS | A AWS responde quase todo erro com HTTP 400 e o tipo no campo `__type`. O provedor lê o tipo e usa o status equivalente: `ThrottlingException` vira 429 (repetida e contada no circuito) e `ExpiredTokenException` vira 401 (credencial descartada, renovada e chamada repetida uma vez) |
| Circuit breaker | Ligado por padrão, um por instância (`Http.CircuitBreaker`) |
| Native AOT | JSON escrito com `Utf8JsonWriter` e lido com `JsonDocument`; resposta do STS lida com `XmlReader` sem DTD |

---

## 🚀 Uso

### Via código

```csharp
using TEC.Vault.AwsSecretsManager;
using TEC.Vault.DependencyInjection;

builder.Services.AddTecVault(vault => vault
    .UseAwsSecretsManager(options =>
    {
        options.Region = "sa-east-1";
        // Credenciais: IRSA, container, IMDS ou variáveis de ambiente (veja Autenticação)
    }));
```

### Via configuração (`appsettings.json`)

```json
{
  "Vault": {
    "Provider": "AwsSecretsManager",
    "AwsSecretsManager": {
      "Region": "sa-east-1",
      "MaxListItems": 1000
    }
  }
}
```

```csharp
builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers.AddAwsSecretsManager());
```

---

## 🔐 Autenticação

A fonte da credencial é escolhida na subida, nesta ordem (vale a primeira configurada):

| # | Fonte | Quando vale | Como funciona |
|:---:|---|---|---|
| 1 | **Web identity** (IRSA no EKS) | `RoleArn` e `WebIdentityTokenFile` (padrão: `AWS_ROLE_ARN` e `AWS_WEB_IDENTITY_TOKEN_FILE`) | `AssumeRoleWithWebIdentity` no STS regional (`StsEndpoint`), sem assinatura. O arquivo do token é relido a cada renovação, acompanhando a troca feita pelo Kubernetes |
| 2 | **Container** (ECS e EKS Pod Identity) | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` ou `AWS_CONTAINER_CREDENTIALS_FULL_URI`, com `UseContainerCredentials` ligado | `GET` no endpoint do agente, com o cabeçalho `Authorization` de `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` (relido a cada renovação) ou `AWS_CONTAINER_AUTHORIZATION_TOKEN` |
| 3 | **IMDSv2** (EC2) | `UseInstanceMetadata` ligado e `AWS_EC2_METADATA_DISABLED` diferente de `true` | Token de sessão (`PUT /latest/api/token`), depois o papel e a credencial do perfil da instância |
| 4 | **Chaves estáticas**, último recurso | `AccessKeyId`/`SecretAccessKey`/`SessionToken` em código ou as variáveis `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` e `AWS_SESSION_TOKEN` (nomes em `AccessKeyIdVariable`, `SecretAccessKeyVariable` e `SessionTokenVariable`) | Relidas a cada login: depois de uma recusa da AWS (401), a variável é lida de novo |

Credenciais temporárias (STS, container e IMDS) trazem a expiração e são renovadas antes dela: com a validade de 1 hora do STS, 5 minutos antes. Um `ExpiredTokenException` no meio do caminho descarta a credencial em cache e refaz o login uma vez.

Com o IMDS ligado (o padrão) e chaves estáticas configuradas, o IMDS é tentado primeiro, com tempo limite curto. Se ele não responder na primeira vez (fora do EC2, ou instância sem perfil do IAM), o processo passa a usar as chaves estáticas e registra o evento 3101. Um IMDS que já respondeu não é trocado pelas chaves estáticas depois de uma falha. Fora da AWS, desligue o IMDS (`UseInstanceMetadata = false` ou `AWS_EC2_METADATA_DISABLED=true`) para não esperar por ele na primeira chamada.

Endereços aceitos para o container, como nos SDKs da AWS: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` vai sempre para `169.254.170.2`, e `AWS_CONTAINER_CREDENTIALS_FULL_URI` só aceita HTTPS, ou HTTP para loopback, `169.254.170.2`, `169.254.170.23` e `fd00:ec2::23`. Outro endereço derruba a subida.

Sem nenhuma fonte (IMDS desligado e nada mais configurado) ou com chaves estáticas pela metade, o construtor lança `InvalidOperationException`. Uma credencial recusada no login (STS, container ou IMDS) vira `VAULT_AUTENTICACAO_FALHOU` com o código da AWS no log (ex.: `400 InvalidIdentityToken`); fora do ar, `VAULT_INDISPONIVEL`.

> [!CAUTION]
> `SecretAccessKey` e `SessionToken` em texto na configuração (`Vault:AwsSecretsManager`) derrubam a subida, como nos outros provedores: use `SecretAccessKeyVariable` e `SessionTokenVariable`, ou uma fonte sem segredo (IRSA, container, IMDS). `AccessKeyId` é um identificador e continua aceito.

---

## ⚙️ Opções

`AwsSecretsManagerOptions`, em `TEC.Vault.AwsSecretsManager`.

| Opção | Padrão | Descrição |
|---|---|---|
| `Region` | `AWS_REGION`, `AWS_DEFAULT_REGION` ou `us-east-1` | Região: letras minúsculas, dígitos e hífen (vai para o host e para o escopo da assinatura) |
| `Endpoint` | `https://secretsmanager.{Region}.amazonaws.com/` (`.com.cn` na China) | Endereço da API (VPC endpoint, LocalStack). HTTPS, sem caminho, usuário, query ou fragmento |
| `StsEndpoint` | `https://sts.{Region}.amazonaws.com/` | STS do web identity. Mesmas regras de `Endpoint` |
| `RoleArn` / `WebIdentityTokenFile` / `RoleSessionName` | `AWS_ROLE_ARN` / `AWS_WEB_IDENTITY_TOKEN_FILE` / `AWS_ROLE_SESSION_NAME` ou `tec-vault-<número>` | Web identity (IRSA) |
| `UseContainerCredentials` | `true` | Usa as variáveis de credenciais de container quando existem |
| `UseInstanceMetadata` | `true` | Usa o IMDSv2 |
| `AccessKeyId` / `SecretAccessKey` / `SessionToken` | `null` | Chaves estáticas em código (`SecretAccessKey` e `SessionToken` não são aceitos na configuração) |
| `AccessKeyIdVariable` / `SecretAccessKeyVariable` / `SessionTokenVariable` | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | Variáveis das chaves estáticas |
| `MaxListItems` | `10000` | Teto de itens de uma listagem, de 1 a 1.000.000. Acima dele, `VAULT_LISTAGEM_ACIMA_DO_LIMITE` |
| `Http.MaxRetries` / `Http.NetworkTimeout` / `Http.MaxRetryDelay` / `Http.MaxResponseBytes` | 3 / 30 s / 30 s / 4 MB | Transporte, como nos demais provedores HTTP ([🔁 Resiliência](resiliencia.md)) |
| `Http.Handler` | `null` | Handler próprio (proxy, CA interna); com ele, desligue `AllowAutoRedirect` |
| `Http.CircuitBreaker` | ligado | Veja [🔁 Resiliência](resiliencia.md) |
| `HostEnvironment` | o do container | Libera HTTP em localhost só em Development |
| `TimeProvider` | sistema | Relógio da assinatura, da expiração das credenciais e do circuito |

Os endpoints locais de credenciais (container e IMDS) usam tempo limite de no máximo 5 s e 2 s, uma retentativa e teto de 64 KB.

Pela configuração são lidas `Region`, `Endpoint`, `StsEndpoint`, `RoleArn`, `WebIdentityTokenFile`, `RoleSessionName`, `UseContainerCredentials`, `UseInstanceMetadata`, `AccessKeyId`, `AccessKeyIdVariable`, `SecretAccessKeyVariable`, `SessionTokenVariable`, `MaxListItems`, `MaxRetries`, `NetworkTimeout` e a subseção `CircuitBreaker` ([⚙️ Escolha do cofre pela configuração](configuracao-por-appsettings.md)). Chave desconhecida derruba a subida. `AddAwsSecretsManager(o => ...)` aceita um ajuste em código depois da configuração (ex.: `Http.Handler`).

---

## 🧭 Operações

| Método | Chamada à AWS | Observações |
|---|---|---|
| `GetSecretAsync` | `GetSecretValue` | `version` vira `VersionId`. Só `SecretString`: segredo binário volta `VAULT_ENTRADA_INVALIDA` (campo `SecretString`) |
| `ExistsAsync` | `DescribeSecret` | Segredo agendado para exclusão conta como inexistente |
| `ListSecretsAsync` | `ListSecrets`, página a página | Nome, versão atual (`AWSCURRENT`), datas e tags. Acima de `MaxListItems`, `VAULT_LISTAGEM_ACIMA_DO_LIMITE` (nunca uma lista cortada) |
| `ListSecretVersionsAsync` | `ListSecretVersionIds`, página a página | Versões com rótulo; mesmo limite |
| `SetSecretAsync` | `CreateSecret`; se existir, `PutSecretValue` | Leva um `ClientRequestToken`, então a retentativa não cria versão duplicada (o token vira o `VersionId`). Com `Tags`, as tags do segredo passam a ser exatamente essas, também quando ele já existia. Tipo de conteúdo, `Enabled = false`, `ExpiresOn` e `NotBefore` voltam `VAULT_ENTRADA_INVALIDA` |
| `UpdateSecretPropertiesAsync` | `DescribeSecret`, `UntagResource` e `TagResource` | Só tags, e elas valem para o segredo inteiro: com tags, não informe `version` (`VAULT_ENTRADA_INVALIDA`). As tags passam a ser exatamente as informadas (as duas chamadas não são atômicas). `Enabled`, validade e tipo de conteúdo voltam `VAULT_ENTRADA_INVALIDA` |
| `DeleteSecretAsync` | `DeleteSecret` | Janela de recuperação padrão da AWS (30 dias); `ScheduledPurgeDate` é a data devolvida pela AWS. O provedor não expõe recuperação |
| `CheckAccessAsync` | `ListSecrets` com `MaxResults = 1` | Passa pela base do provedor: circuit breaker, métrica (`secret.health`) e cancelamento propagado |

Limites validados antes da chamada: nome de 1 a 512 caracteres em `[0-9a-zA-Z/_+=.@-]`, versão de 1 a 64 caracteres em `[0-9a-zA-Z_-]`, valor de até 64 KB, até 50 tags (chave até 128 e valor até 256 caracteres).

Permissões IAM usadas: `secretsmanager:GetSecretValue`, `DescribeSecret`, `ListSecrets`, `ListSecretVersionIds`, `CreateSecret`, `PutSecretValue`, `TagResource`, `UntagResource` e `DeleteSecret`. Uma aplicação que só lê precisa das quatro primeiras; `TagResource` e `UntagResource` só entram quando a aplicação grava tags.

---

## ⚠️ Limitações

- **Rotação limitada.** `RotateSecretAsync` com `validity` falha, porque a gravação recusa `ExpiresOn`. Com `disablePreviousVersions: true`, cada versão anterior é desabilitada por `UpdateSecretPropertiesAsync(Enabled = false)`, que a AWS não tem: o resultado volta com `IsComplete = false` e uma falha por versão. A AWS controla versões por rótulos de estágio (`AWSCURRENT`, `AWSPREVIOUS`), que o provedor não expõe.
- **Sem segredo binário.** Só `SecretString` é lido e gravado.
- **Nomes diferenciam maiúsculas**, como na AWS: o cache de segredos trata `Db` e `DB` como itens diferentes.

---

## ❌ Mapeamento de erros

O tipo do erro (`__type`, sem o namespace) decide o status equivalente, e o status decide o código, como nos demais provedores HTTP. O tipo vai para o log como detalhe; a mensagem da AWS, não.

| Situação | Código |
|---|---|
| `ResourceNotFoundException` | `VAULT_ITEM_NAO_ENCONTRADO` (em `ExistsAsync`, `false`) |
| `ResourceExistsException` | `VAULT_CONFLITO` |
| `AccessDeniedException`, `NotAuthorized`, `DecryptionFailure`, `EncryptionFailure` | `VAULT_ACESSO_NEGADO` |
| `ExpiredTokenException`, `UnrecognizedClientException`, `InvalidClientTokenId`, `InvalidSignatureException`, `IncompleteSignature`, `RequestExpired` | Credencial descartada e uma nova tentativa; persistindo, `VAULT_AUTENTICACAO_FALHOU` |
| `ThrottlingException`, `TooManyRequestsException`, `RequestLimitExceeded` | Repetida com backoff; persistindo, `VAULT_LIMITE_EXCEDIDO` |
| `InvalidRequestException`, `InvalidParameterException`, `LimitExceededException` e outros HTTP 400 | `VAULT_REQUISICAO_RECUSADA` |
| `InternalServiceError`, HTTP 5xx, falha de rede e tempo limite (também na leitura do corpo) | `VAULT_INDISPONIVEL` |
| Resposta acima de `MaxResponseBytes` ou fora do formato | `VAULT_FALHA` |
| Listagem acima de `MaxListItems` | `VAULT_LISTAGEM_ACIMA_DO_LIMITE` |

Tabela completa em [❌ Erros](erros.md).

---
⬅️ [📚 Índice](README.md) · [🔷 Provedor Google Secret Manager](provedor-google-secret-manager.md) ➡️
