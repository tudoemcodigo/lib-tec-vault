<div align="center">
<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="Tudo em Código" width="90" />
</div>

# 🏛️ Registros de Decisões de Arquitetura (ADR) — TEC.Vault

Este diretório contém os Registros de Decisões de Arquitetura (**Architecture Decision Records — ADRs**) do componente **TEC.Vault**.

O objetivo destes registros é documentar de forma clara, contextualizada e justificada as escolhas técnicas, de engenharia de software e de segurança adotadas na biblioteca, orientando a manutenção, evolução e auditoria contínua da plataforma.

---

## 📑 Índice de Decisões

| ADR | Título | Status | Data | Contexto Resumido |
|:---:|:---|:---:|:---:|:---|
| [0001](0001-api-unificada-de-cofres-por-responsabilidade.md) | **API Unificada de Cofres Segregada por Responsabilidade** | Aprovado | 2026-10-08 | Interfaces segregadas (`ISecretReader`, `ISecretStore`, `IKeyStore`, etc.) permitindo trocar o cofre sem alterar o código de negócio. |
| [0002](0002-adocao-do-result-pattern-e-eliminacao-de-excecoes.md) | **Adoção do Result Pattern e Eliminação de Exceções de Infraestrutura** | Aprovado | 2026-10-08 | Uso do `Result`/`Result<T>` do `TEC.Core`; falhas de rede e provedor saem como códigos padronizados sem vazar URLs ou credenciais. |
| [0003](0003-provedores-http-nativos-sem-sdks-pesados.md) | **Provedores HTTP Nativos sem SDKs Pesados de Terceiros** | Aprovado | 2026-10-08 | HashiCorp Vault e Infisical implementados via `SocketsHttpHandler` e `System.Text.Json` para Native AOT e zero dependências transitivas. |
| [0004](0004-provedor-synced-para-ambientes-kubernetes-e-agentes.md) | **Provedor Synced para Ambientes Kubernetes e Agentes Externos** | Aprovado | 2026-10-08 | Leitura de segredos montados por ESO, CSI, Vault Agent ou BWS (`Directory`, `SecretsFile`, `EnvironmentVariables`) sem credencial na app. |
| [0005](0005-isolamento-de-segredos-em-variaveis-de-ambiente.md) | **Isolamento e Blindagem de Segredos em Variáveis de Ambiente** | Aprovado | 2026-10-08 | Prefixo obrigatório, sanitização estrita, tetos de tamanho e geração de versão por HMAC para mitigar riscos de vazamento em variáveis. |
| [0006](0006-resiliencia-retentativas-idempotentes-e-circuit-breaker.md) | **Resiliência em Camadas: Retentativa Idempotente e Circuit Breaker por Cofre** | Aprovado | 2026-10-09 | Retentativas estritas apenas para chamadas idempotentes e circuit breaker com `Polly.Core` evitando saturação do cofre e cascata de falhas. |
| [0007](0007-cache-em-memoria-invalidacao-e-coalescencia-de-leituras.md) | **Cache em Memória com Invalidação por Escrita e Proteção Anti-Stampede** | Aprovado | 2026-10-08 | Single-flight de leitura por chave para evitar rajadas (*stampede*) contra o cofre e invalidação imediata em mutações. |
| [0008](0008-criptografia-envelope-com-chaves-no-cofre.md) | **Criptografia Envelope no Cliente com Chaves Mestras no Cofre** | Aprovado | 2026-10-08 | Uso de `EncryptEnvelopeAsync` com AES-GCM local e DEKs protegidas pelo cofre, unindo alta performance a zero trânsito de chaves mestras. |
| [0009](0009-segregacao-e-isolamento-de-chaves-privadas-no-hashicorp-vault.md) | **Segregação de Chaves Privadas de Certificados no HashiCorp Vault** | Aprovado | 2026-10-19 | Separação física em `_certificates-keys` com RBAC independente para evitar vazamento acidental de chave privada em listagens públicas. |
| [0010](0010-auditoria-sem-vazamento-de-segredos-e-opentelemetry.md) | **Auditoria e Observabilidade Sem Vazamento de Segredos** | Aprovado | 2026-10-08 | Spans e métricas OpenTelemetry sem dados sensíveis; logs com dados não confiáveis mascarados e valores nunca registrados. |
| [0011](0011-provedor-encadeado-com-fallback-em-camadas.md) | **Provedor Encadeado com Fallback em Camadas** | Aprovado | 2026-10-23 | Encadeamento ordenado de leitores permitindo fallback transparente de variáveis locais para cofres remotos. |
| [0012](0012-provedores-nativos-aws-e-google-sem-sdks-de-terceiros.md) | **Provedores Nativos AWS e Google Cloud Sem SDKs de Terceiros** | Aprovado (revisto em 2026-10-29) | 2026-10-23 | Integração nativa com AWS Secrets Manager (SigV4) e Google Secret Manager via REST puro, sobre `VaultHttpClient` e `VaultTokenSource`, com cadeia de credenciais renovável na AWS. |
| [0013](0013-alvo-unico-net10.md) | **Alvo Único .NET 10** | Aprovado | 2026-10-29 | Os pacotes deixam o `net8.0`: sem código condicional, carga de certificados só com `X509CertificateLoader`, lock files e CI com um alvo. |
| [0014](0014-prefixo-obrigatorio-na-fonte-de-iconfiguration.md) | **Prefixo Obrigatório na Fonte de IConfiguration** | Aprovado | 2026-10-29 | `VaultConfigurationOptions.Prefix` obrigatório, conferido na subida, para o cofre não sobrescrever chaves arbitrárias da configuração. |
