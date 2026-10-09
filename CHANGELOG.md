# 📝 Changelog

Todas as mudanças relevantes do **TEC.Vault** são registradas aqui. O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/). Enquanto a versão for `0.x`, mudanças incompatíveis podem ocorrer em versões MINOR. Os seis pacotes saem sempre com a mesma versão.

## [0.1.0] - 2026-10-09

### ✨ Adicionado

#### 🔐 TEC.Vault

- **Circuit breaker por cofre** (`VaultCircuitBreaker`, `VaultCircuitBreakerOptions`, com `Polly.Core`), ligado por padrão nos provedores de rede (Azure Key Vault, HashiCorp Vault, Infisical) e por fora das retentativas que já existiam. Abre com falhas repetidas de `VAULT_INDISPONIVEL`/`VAULT_LIMITE_EXCEDIDO` e recusa as chamadas seguintes com o novo erro `VAULT_CIRCUITO_ABERTO`, sem consultar o cofre. Um circuito por cofre, compartilhado por segredos, chaves e certificados. Na chamada de teste (meia-abertura) só uma resposta do cofre fecha o circuito: cancelamento ou `VAULT_FALHA` o reabrem.
- Subseção `CircuitBreaker` (`Enabled`, `FailureRatio`, `MinimumThroughput`, `SamplingDuration`, `BreakDuration`) na configuração de cada provedor, com validação estrita; `AzureKeyVaultOptions.CircuitBreaker` e `VaultHttpSettings.CircuitBreaker` em código.
- Métrica `vault.circuit.state_changes` e eventos de log 2011–2014. `VaultSettings.GetDouble` para provedores.
- Documentação: [🔁 Resiliência](docs/resiliencia.md).

### 🔁 Alterado

- Construtores de `VaultProviderBase` e `VaultHttpProviderBase` aceitam o `VaultCircuitBreaker` do cofre (parâmetro opcional).
- Nova dependência: `Polly.Core` 8.8.0 (sem dependências próprias em net8/net10, compatível com Native AOT).

## [0.0.1] - 2026-10-08

Primeira versão. Nada foi publicado ainda: esta entrada descreve o que os pacotes oferecem.

### ✨ Adicionado

#### 🔐 TEC.Vault (núcleo, sem SDK de nuvem)

- **Interfaces por responsabilidade:** segredos (`ISecretReader`, `ISecretStore`, `ISecretRecycleBin`, `ISecretBackup`), chaves (`IKeyReader`, `IKeyStore`, `IKeyCryptography`, `IKeyRecycleBin`, `IKeyBackup`), certificados (`ICertificateReader`, `ICertificateStore`, `ICertificateRecycleBin`, `ICertificateBackup`) e `IVaultHealthProbe`. Todo método assíncrono retorna `Result`/`Result<T>` do TEC.Core.
- **Erros padronizados** em `VaultErrors` (`VAULT_ENTRADA_INVALIDA`, `VAULT_ITEM_NAO_ENCONTRADO`, `VAULT_CONFLITO`, `VAULT_ITEM_DESABILITADO`, `VAULT_CERTIFICADO_NAO_EXPORTAVEL`, `VAULT_REQUISICAO_RECUSADA`, `VAULT_ACESSO_NEGADO`, `VAULT_AUTENTICACAO_FALHOU`, `VAULT_LIMITE_EXCEDIDO`, `VAULT_INDISPONIVEL`, `VAULT_OPERACAO_NAO_SUPORTADA`, `VAULT_FALHA`, `VAULT_OPERACAO_CANCELADA`, `VAULT_LISTAGEM_ACIMA_DO_LIMITE`); falhas de infraestrutura nunca expõem detalhes ao cliente.
- **Segredos:** geração e rotação (`GenerateSecretAsync`, `RotateSecretAsync`, `DisablePreviousSecretVersionsAsync`).
- **Chaves:** cifra, *wrap* e assinatura no cofre; criptografia envelope (`EncryptEnvelopeAsync`/`DecryptEnvelopeAsync`, AES-GCM com chave de dados protegida pelo cofre).
- **Certificados:** criação, importação PFX/PEM (até 1 MB, `MaxCertificateBytes`), download controlado e `VaultCertificateFactory` (par de chaves, CSR, autoassinado, junção com o certificado emitido).
- **Registro:** `AddTecVault(Action<VaultBuilder>)` em código e `AddTecVault(IConfiguration, Action<VaultProviderCatalog>)` com escolha do provedor por ambiente e por família (`Vault:Provider`, `Vault:Secrets|Keys|Certificates:Provider`, `None`), leitura estrita e compatível com Native AOT (`VaultSettings`). Configuração inválida falha na subida com `InvalidOperationException` citando o caminho da chave; chamar `AddTecVault` duas vezes lança exceção (nunca ignora uma configuração em silêncio).
- **`IConfiguration`:** fonte de configuração com segredos por prefixo e recarga incremental (`VaultConfigurationOptions`).
- **Cache de segredos** opcional (`EnableSecretCache`, `Vault:Cache:Duration`), com invalidação nas escritas e uma única leitura por chave sob rajada.
- **Health check** (`AddHealthChecks().AddTecVault()`, tags `ready` e `vault`) que verifica cada store registrado sem ler valores.
- **Observabilidade:** `ActivitySource` e `Meter` `TEC.Vault` (spans e métricas sem nome de item), eventos de log com `LoggerMessage` e auditoria de escritas e downloads de chave privada; nomes recusados registrados só como tamanho + HMAC com chave do processo.
- **Base para provedores:** `VaultProviderBase` (validação, `Result`, auditoria, telemetria, `EnsureListLimit` e `VaultListLimitExceededException` para limitar listagens), regras comuns de entrada (regex com timeout: timeout vira entrada recusada) e base HTTP sem SDK (`VaultHttpProviderBase`, `VaultHttpClient` com `SocketsHttpHandler` de vida longa e renovação de conexões, retentativa só de operações idempotentes, `Retry-After`, sem redirecionamento, respostas limitadas por `MaxResponseBytes` com `VaultResponseTooLargeException`; `VaultTokenSource`; `VaultEndpoint`; `VaultCredentialInput` com arquivo de credencial limitado a 64 KB).

#### 🌐 TEC.Vault.AzureKeyVault

- Segredos, chaves e certificados no Azure Key Vault, com lixeira, backup e sonda de saúde; autenticação `ManagedIdentity`, `WorkloadIdentity` ou `Developer` (só em Development); endereço validado.
- Listagens limitadas por `MaxListItems` (padrão 10.000; `Vault:AzureKeyVault:MaxListItems`), relógio injetável (`TimeProvider`) e tolerância a tags malformadas vindas do servidor.
- `AddTecVaultAzureKeyVault` para a fonte de `IConfiguration` e `AzureKeyVaultStores` para uso sem DI.

#### 🏛️ TEC.Vault.HashiCorpVault

- HashiCorp Vault e OpenBao por HTTP, sem SDK: segredos no KV v2 com lixeira, chaves no Transit (RSA-OAEP-256, RSA-PSS, ECDSA) e certificados no KV emitidos pelo PKI a partir de CSR.
- Login Kubernetes, JWT, AppRole ou token, compartilhado pelos três stores; listagens limitadas por `MaxListItems` (padrão 10.000; `Vault:HashiCorpVault:MaxListItems`), conferido antes de ler os metadados e aplicado também às listagens de versões e à busca de nome sem diferenciar maiúsculas.

#### 🟣 TEC.Vault.Infisical

- Leitura e gravação de segredos pela API REST do Infisical, sem SDK: Universal Auth, Kubernetes Auth ou token pronto; credencial só de arquivo ou variável; respostas limitadas a 4 MB e versões às 100 mais recentes.

#### 📂 TEC.Vault.Synced

- Leitura de segredos entregues por um agente externo, sem SDK: `Directory` (um arquivo por segredo, layout do Kubernetes, links confinados), `EnvironmentVariables` (prefixo obrigatório) e `SecretsFile` (JSON ou .env); teto de itens (`MaxItems`) e versão por HMAC.

#### 🧠 TEC.Vault.InMemory

- Cofre em memória com todas as interfaces e criptografia real, para desenvolvimento e testes; bloqueado fora de Development. Opções sem equivalente (emissor, HSM, renovação automática) retornam `VAULT_OPERACAO_NAO_SUPORTADA`.

#### 🧪 Qualidade

- Testes de contrato compartilhados pelos provedores, fuzzing, vazamento sob carga e abuso de recursos (TUnit); integração com HashiCorp Vault real em container e com o Key Vault de testes; carga rápida (`Carga-CI`) e pesada (`Carga-Pesada`); samples `TEC.Vault.ConfigSelection` e `TEC.Vault.LoadGenerator`.

[0.0.1]: https://github.com/tudoemcodigo/lib-tec-vault
