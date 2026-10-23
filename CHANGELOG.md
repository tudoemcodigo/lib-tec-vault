# 📝 Changelog

Todas as mudanças relevantes do **TEC.Vault** são registradas aqui. O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/). Os pacotes da plataforma TEC.Vault saem sempre com a mesma versão alinhada.

## [0.0.1] - 2026-10-23

Primeira publicação pública oficial da plataforma **TEC.Vault**.

### ✨ Adicionado

#### 🔐 TEC.Vault (Núcleo)
- **Interfaces Segregadas por Responsabilidade**: Segredos (`ISecretReader`, `ISecretStore`, `ISecretRecycleBin`, `ISecretBackup`), Chaves (`IKeyReader`, `IKeyStore`, `IKeyCryptography`, `IKeyRecycleBin`, `IKeyBackup`), Certificados (`ICertificateReader`, `ICertificateStore`, `ICertificateRecycleBin`, `ICertificateBackup`) e Saúde (`IVaultHealthProbe`).
- **Result Pattern Nativo**: Todos os métodos públicos retornam `Result`/`Result<T>` do `TEC.Core`. Erros padronizados em `VaultErrors` eliminam o vazamento de detalhes de infraestrutura ou URLs ao consumidor.
- **Provedor Composto / Encadeado (`ChainedSecretReader`)**: Permite fallback em cascata de leituras de segredos (ex.: sobrescrever via variáveis de ambiente com fallback transparente para cofre remoto).
- **Resiliência em Duas Camadas**:
  - Retentativas com backoff exponencial e jitter restritas a operações idempotentes.
  - Circuit Breaker por cofre com `Polly.Core` 8.8.0, compartilhando estado entre segredos, chaves e certificados e gerando erro `VAULT_CIRCUITO_ABERTO` na borda.
- **Cache de Segredos Anti-Stampede**: Coalescência de leituras simultâneas na mesma chave via Single-Flight e invalidação imediata em operações de escrita/deleção.
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
- Integração nativa com AWS Secrets Manager via HTTP puro e JSON Protocol 1.1 sem o SDK oficial pesado da AWS.
- Assinatura criptográfica nativa de requisições **AWS Signature Version 4 (SigV4)** com HMAC-SHA256.
- Suporte a credenciais estáticas, variáveis padrão AWS (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`), Web Identity Token e IRSA em clusters EKS.
- Operações completas de leitura, gravação, listagem e exclusão de segredos com suporte a rotação e tags.

#### 🔷 TEC.Vault.GoogleSecretManager (Novo)
- Integração nativa com Google Cloud Secret Manager via API REST v1 sem dependências pesadas do Google Cloud SDK.
- Autenticação compatível com Google Application Default Credentials (ADC), Service Account JSON Key e Google Compute/GKE/Cloud Run Metadata Server.
- Leitura, adição de versões, destruição e gerenciamento seguro de segredos.

#### 📂 TEC.Vault.Synced
- Leitura de segredos entregues por agentes externos sem credenciais de nuvem no container:
  - `DirectorySecretStore`: diretórios montados por Kubernetes Secrets ou CSI Driver com suporte a links atômicos (`..data`).
  - `EnvironmentSecretStore`: variáveis de ambiente com prefixo obrigatório sanitizado (`TECVAULT_`).
  - `FileSecretStore`: arquivos centralizados nos formatos JSON e `.env`.

#### 🧠 TEC.Vault.InMemory
- Implementação integral em memória de todas as interfaces e operações criptográficas reais para desenvolvimento e testes, com trava estrita de segurança que impede sua execução em ambientes de Produção.

[0.0.1]: https://github.com/tudoemcodigo/lib-tec-vault/releases/tag/v0.0.1
