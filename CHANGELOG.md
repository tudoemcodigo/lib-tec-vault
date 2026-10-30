# 📝 Changelog

Todas as mudanças relevantes do **TEC.Vault** são registradas aqui. O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/). Os pacotes da plataforma TEC.Vault saem sempre com a mesma versão alinhada.

## [0.0.1] - 2026-10-30

Primeira publicação pública oficial da plataforma **TEC.Vault**. Os oito pacotes têm um único alvo, `net10.0` (ADR 0013), sem `#if` de TFM.

### ✨ Adicionado

#### 🔐 TEC.Vault (Núcleo)
- **Prefixo obrigatório na fonte de `IConfiguration`** (ADR 0014): `VaultConfigurationOptions.Prefix` (ou `Vault:Configuration:Prefix`) ausente, vazio ou só com espaços derruba a subida com `InvalidOperationException`, para que nem todo segredo visível vire configuração e sobrescreva qualquer chave. Dê um prefixo por aplicação aos segredos (ex.: `MinhaApi--ConnectionStrings--Db`) e informe-o.
- **`VaultHttpClient` e `VaultTokenSource`**, base dos provedores HTTP (HashiCorp Vault, Infisical, AWS e Google): retentativa padronizada, teto de resposta (`MaxResponseBytes`), tempo limite como `VAULT_INDISPONIVEL` (abre o circuito) também na leitura do corpo (um cofre que manda os cabeçalhos e para vira `TimeoutException`), token em cache com renovação e intervalo de falha, 401 descarta o token, buffers com valores zerados e `CheckAccessAsync` pela base do provedor (circuit breaker, métrica `secret.health` e cancelamento propagado). O login tem teto (`VaultTokenSource.DefaultLoginTimeout`, 2 minutos, ajustável pelo parâmetro opcional `loginTimeout`), para um login que nunca termina não ficar compartilhado para sempre. `VaultHttpClient.ErrorStatusMapper` atende cofres que informam o tipo do erro no corpo e não no status.
- **`VaultProviderBase.NameComparer`**: o provedor declara como compara nomes, e o cache de segredos usa a mesma regra na chave.
- **Listagem acima do limite falha em todos os provedores** (`VAULT_LISTAGEM_ACIMA_DO_LIMITE`), em vez de devolver só os primeiros itens.
- **Interfaces Segregadas por Responsabilidade**: Segredos (`ISecretReader`, `ISecretStore`, `ISecretRecycleBin`, `ISecretBackup`), Chaves (`IKeyReader`, `IKeyStore`, `IKeyCryptography`, `IKeyRecycleBin`, `IKeyBackup`), Certificados (`ICertificateReader`, `ICertificateStore`, `ICertificateRecycleBin`, `ICertificateBackup`) e Saúde (`IVaultHealthProbe`).
- **Result Pattern Nativo**: Todos os métodos públicos retornam `Result`/`Result<T>` do `TEC.Core`. Erros padronizados em `VaultErrors` eliminam o vazamento de detalhes de infraestrutura ou URLs ao consumidor.
- **Provedor Composto / Encadeado (`ChainedSecretReader`)**: Permite fallback em cascata de leituras de segredos (ex.: sobrescrever via variáveis de ambiente com fallback transparente para cofre remoto).
- **Resiliência em Duas Camadas**:
  - Retentativas com backoff exponencial e jitter restritas a operações idempotentes.
  - Circuit Breaker por cofre com `Polly.Core` 8.8.0, compartilhando estado entre segredos, chaves e certificados e gerando erro `VAULT_CIRCUITO_ABERTO` na borda.
- **Cache de Segredos Anti-Stampede**: Coalescência de leituras simultâneas na mesma chave via Single-Flight e invalidação imediata em operações de escrita/deleção. A chave segue o `NameComparer` do provedor, e a leitura compartilhada do `CachingSecretReader` tem teto de 2 minutos (não usa `CancellationToken.None`).
- **Criptografia Envelope**: Suporte nativo a `EncryptEnvelopeAsync` e `DecryptEnvelopeAsync` utilizando AES-256-GCM com chaves de dados (DEK) protegidas por chaves mestras (KEK) no cofre.
- **Integração com IConfiguration**: Recarga incremental orientada por hash/versão HMAC sem expor credenciais em texto claro.
- **Observabilidade**: Instrumentação nativa de OpenTelemetry (`ActivitySource` e `Meter` `TEC.Vault`) e mascaramento estruturado de segredos (`SensitiveDataMasker`).

#### 🌐 TEC.Vault.AzureKeyVault
- Suporte a segredos, chaves e certificados digitais no Azure Key Vault.
- Autenticação por Identidade Gerenciada (`ManagedIdentity`), Identidade Federada de Workload (`WorkloadIdentity`) e credenciais de desenvolvedor (`Developer`, restrito a ambiente de desenvolvimento).
- Lixeira com recuperação e purga, backup seguro e sonda de saúde leve.

#### 🏛️ TEC.Vault.HashiCorpVault
- Integração nativa de alta performance com HashiCorp Vault e OpenBao via HTTP puro sem SDKs externos (100% Native AOT).
- Segredos via KV v2, Chaves via Transit (RSA, ECDSA) e Certificados emitidos via PKI com CSR.
- Segregação de chaves privadas de certificados em rota protegida (`_certificates-keys`) com controle de acesso granular.
- Autenticação via Kubernetes Auth, JWT, AppRole e Tokens de acesso.

#### 🟣 TEC.Vault.Infisical
- Integração nativa com a API REST v4 do Infisical sem SDKs de terceiros.
- Autenticação Universal Auth, Kubernetes Auth e Access Token.

#### ☁️ TEC.Vault.AwsSecretsManager (Novo)
- Integração nativa com AWS Secrets Manager via HTTP puro e JSON Protocol 1.1 sem o SDK oficial pesado da AWS, sobre `VaultHttpClient` e `VaultTokenSource` (a configuração lê `MaxRetries`, `NetworkTimeout` e a subseção `CircuitBreaker`). `AddAwsSecretsManager` tem um `configure` opcional.
- Assinatura criptográfica nativa de requisições **AWS Signature Version 4 (SigV4)** com HMAC-SHA256.
- Cadeia de credenciais com renovação: web identity/IRSA (`AssumeRoleWithWebIdentity`, relendo o arquivo do token), credenciais de container do ECS e do EKS Pod Identity (token de autorização relido a cada renovação), IMDSv2 e, por último, chaves estáticas (variáveis padrão `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`). Credenciais temporárias são renovadas antes de expirar, e um `ExpiredTokenException` descarta a credencial e repete a chamada uma vez. Evento de log 3101 quando o IMDS não responde e as chaves estáticas entram em uso.
- Credencial em texto na configuração é recusada, como nos demais provedores: `Vault:AwsSecretsManager:SecretAccessKey` e `SessionToken` derrubam a subida (use `SecretAccessKeyVariable`, `SessionTokenVariable` ou uma fonte sem segredo), assim como chave desconhecida na seção. `Endpoint` e `StsEndpoint` precisam ser HTTPS e só o servidor (HTTP só em localhost no Development), e a região tem o formato conferido.
- Leitura, gravação, listagem e exclusão de segredos. Listagem com a versão atual (`AWSCURRENT`), datas e tags (a recarga do `IConfiguration` é incremental); `ListSecretVersionsAsync` com todas as páginas; `ScheduledPurgeDate` com a data devolvida pela AWS; `MaxListItems` padrão 10.000, validado de 1 a 1.000.000.
- `ThrottlingException` repetida como um 429; gravações com `ClientRequestToken`, para a retentativa não criar versão duplicada. HTTP 400 genérico (`InvalidRequestException`, `InvalidParameterException`) vira `VAULT_REQUISICAO_RECUSADA`, como nos outros provedores HTTP.
- Tags: `UpdateSecretPropertiesAsync` com `Tags` aplica as tags, e `Tags` com `version` é recusado; `SetSecretAsync` com `Tags` substitui também as tags de um segredo que já existia, e `Enabled = false` é recusado.

#### 🔷 TEC.Vault.GoogleSecretManager (Novo)
- Integração nativa com Google Cloud Secret Manager via API REST v1 sem dependências pesadas do Google Cloud SDK, sobre `VaultHttpClient` e `VaultTokenSource` (a configuração lê `MaxRetries`, `NetworkTimeout` e a subseção `CircuitBreaker`). `AddGoogleSecretManager` tem um `configure` opcional.
- Autenticação por token em variável de ambiente (`AccessTokenVariable`; `Vault:GoogleSecretManager:AccessToken` em texto derruba a subida), Service Account JSON (`GOOGLE_APPLICATION_CREDENTIALS` ou opções) e Metadata Server do Google (Compute Engine, GKE, Cloud Run). O arquivo de credenciais do `gcloud auth application-default login` não é lido, e credencial que não é Service Account (`authorized_user`) é recusada.
- Service Account: o `token_uri` é conferido (HTTPS, porta padrão, host em `AllowedTokenHosts`) antes de o JWT sair do processo; o JSON é lido com `BoundedFileReader` (64 KB) a cada renovação; o JWT é montado com `Utf8JsonWriter`. Arquivo de credenciais configurado e ausente derruba a subida, sem cair no Metadata Server. O Metadata Server não tem falhas engolidas e só vale com `Metadata-Flavor: Google`.
- Validação na subida: `Endpoint` HTTPS e só o servidor (HTTP só em localhost no Development), formato do projeto conferido, chave desconhecida na seção recusada; `ProjectId` e `CredentialsJsonFile` leem as variáveis de ambiente na validação. `MaxListItems`: padrão 10.000, validado.
- Leitura, adição de versões, exclusão do segredo e habilitar/desabilitar versões, com labels na listagem. `UpdateSecretPropertiesAsync` com `Tags` grava as labels e devolve o estado real da versão; labels fora das regras do Google e `Tags` com `version` sem `Enabled` são recusados antes da chamada. `SetSecretAsync` com `Tags` substitui as labels de um segredo existente, e `Enabled = false` é recusado. HTTP 400 vira `VAULT_REQUISICAO_RECUSADA`, e uma resposta de acesso sem `payload.data`, `VAULT_FALHA`. Sem lixeira.

#### 📂 TEC.Vault.Synced
- Leitura de segredos entregues por agentes externos sem credenciais de nuvem no container:
  - `DirectorySecretStore`: diretórios montados por Kubernetes Secrets ou CSI Driver com suporte a links atômicos (`..data`). O link é resolvido por inteiro (inclusive destinos relativos) e o handle aberto é conferido de novo antes da leitura (no Linux, pelo `/proc/self/fd`); link trocado durante a abertura gera o evento de log 3002. A leitura abre o nome exato sem listar a pasta: com dois arquivos que só diferem em maiúsculas (Linux), o nome exato é lido; a listagem e as outras grafias falham.
  - `EnvironmentSecretStore`: variáveis de ambiente com prefixo obrigatório sanitizado (`TECVAULT_`).
  - `FileSecretStore`: arquivos centralizados nos formatos JSON e `.env`. A troca do arquivo é detectada pelo hash SHA-256 do conteúdo.
  - `MaxItems` estourado na listagem gera `VAULT_LISTAGEM_ACIMA_DO_LIMITE`.

#### 🧠 TEC.Vault.InMemory
- Implementação integral em memória de todas as interfaces e operações criptográficas reais para desenvolvimento e testes, com trava estrita de segurança que impede sua execução em ambientes de Produção.

### 🛠️ Manutenção
- `packages.lock.json` só com `net10.0`; CI documentado com os unitários em `net10.0` e em `net10.0` sem ICU.
- `AGENTS.md`: Native AOT do Azure coerente com o README e o csproj, e a dependência `Polly.Core` do núcleo citada.

[0.0.1]: https://github.com/tudoemcodigo/lib-tec-vault/releases/tag/v0.0.1
