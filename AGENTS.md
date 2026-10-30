# Instruções para agentes — TEC.Vault

Este arquivo complementa as instruções herdadas de `AGENT_BASE.md`. O TEC.Vault guarda segredos, chaves e certificados com uma única API: troque de cofre sem mudar o código, criptografe sem expor chaves e audite cada acesso sem registrar valores.

## Escopo e segurança de alterações

- O escopo padrão é este repositório. Não altere outros repositórios `TEC.*`, não publique pacotes/tags/releases e não rode sincronizações que escrevam fora daqui sem pedido explícito.
- Antes de editar, confira `git status` e `git diff`. Preserve alterações não commitadas; não use reset, checkout destrutivo ou limpeza para descartar trabalho existente.
- Mudanças em APIs públicas (`ISecretReader`, `ISecretStore`, `IKeyCryptography`, `ICertificateReader`, `IVaultHealthProbe`, `VaultErrors`, `VaultProviderBase`, `AddTecVault`, `VaultSettings`, provedores de cache/health check/configuração) ou alvos .NET exigem revisão de compatibilidade, documentação, changelog e consumidores.
- Testes devem atravessar contratos públicos e verificar resultados observáveis. Para mudanças de comportamento, cubra entradas inválidas, limites, falhas e concorrência quando aplicável.
- Trate todo dado externo como não confiável. Não exponha segredos, PII ou conteúdo controlado pelo usuário em exceções, logs, URLs ou sumários.
- Zero Trust: nome, versão, tags e respostas do cofre são tratados como não confiáveis. Endereços HTTPS validados (o token nunca vai a outro servidor), autenticação sem segredo, entrada validada antes da chamada, listagens limitadas (`MaxListItems`, padrão 10.000), respostas e arquivos de credencial com teto, valores nunca em log e erros de infraestrutura ocultos do cliente (HTTP 502).
- Configuração validada na subida (`ValidateOnStart`): provedor desconhecido, chave digitada errado ou endereço inválido derrubam a **subida** com `InvalidOperationException` (citando o caminho da chave).
- Client secret só em Development; produção usa identidade gerenciada, federada ou Kubernetes.
- Chaves privadas nunca saem do cofre: cifra, *wrap* e assinatura no próprio cofre; envelope para dados grandes.

## Mapa da implementação

- `TEC.Vault/`: biblioteca `net10.0` (alvo único), interfaces, modelos, `VaultErrors`, validação, auditoria, métricas, cache com proteção contra *stampede*, `IConfiguration` com recarga, health check, envelope, provedor encadeado (fallback), escolha por configuração e base para provedores. Depende só de `TEC.Core`, `Polly.Core` (circuit breaker) e `Microsoft.Extensions.*` (sem SDK de nuvem).
- `TEC.Vault.AzureKeyVault/`: Azure Key Vault (segredos, chaves, certificados), autenticação sem segredo (Managed Identity, Workload Identity, Developer). `IsAotCompatible` como os demais; o `Azure.Core` gera avisos de trimming (IL2026/IL2075) só no decodificador de PKCS#8 EC, usado por credenciais com certificado EC em PEM.
- `TEC.Vault.AwsSecretsManager/`: AWS Secrets Manager via HTTP SigV4 nativo (JSON protocol 1.1, sem SDK pesado) sobre `VaultHttpClient` e `VaultTokenSource`; credenciais por web identity (IRSA), container (ECS/EKS Pod Identity), IMDSv2 e, por último, chaves estáticas, renovadas antes de expirar. ✅ 100% Native AOT.
- `TEC.Vault.GoogleSecretManager/`: Google Cloud Secret Manager via API REST v1 nativa sobre `VaultHttpClient` e `VaultTokenSource` (token em variável, Service Account JSON com `token_uri` conferido ou Metadata Server GKE/Cloud Run). ✅ 100% Native AOT.
- `TEC.Vault.HashiCorpVault/`: HashiCorp Vault e OpenBao (KV v2 com lixeira, Transit, certificados com PKI; login Kubernetes, JWT, AppRole ou token). HTTP, sem SDK.
- `TEC.Vault.Infisical/`: Infisical (nuvem ou self-hosted), leitura e gravação de segredos via API. HTTP, sem SDK.
- `TEC.Vault.Synced/`: Segredos já entregues por agente externo (pasta montada, variáveis de ambiente, arquivo JSON/.env — só leitura). ESO, CSI driver, Vault Agent, `infisical run`, `bws run` (Bitwarden).
- `TEC.Vault.InMemory/`: Cofre em memória com o mesmo comportamento dos reais (criptografia real). Bloqueado fora de Development.
- `TEC.Vault.Tests/`: testes unitários (TUnit, testes de contrato, fuzzing, vazamento sob carga, AWS e Google sobre cofres simulados em HTTP), 37 de integração (`[Category=Integracao]`: HashiCorp Vault real em container e Key Vault de testes, pulados com motivo sem ambiente).
- `TEC.Vault.LoadTests/`: 7 de carga rápida (`Carga-CI`) e 13 pesados (`Carga-Pesada`) sob demanda no `performance.yml`.
- `samples/`: exemplos de uso (escolha do cofre por ambiente e gerador de carga).
- `build/`: props/targets compartilhados.
- `docs/adr/`: decisões arquiteturais.
- `docs/`: guias por segredos, chaves, certificados, injeção de dependências, configuração por appsettings, segredos no IConfiguration, cache e health check, provedores (Azure, HashiCorp, Infisical, AWS, Google, Encadeado, Synced, Em memória), novo provedor, observabilidade, resiliência, erros, segurança, testes, desenvolvimento.

## Contratos relevantes

- `Directory.Build.props` é a fonte única de versão do pacote (uma versão para os oito pacotes). A versão inicial é `0.0.1`; não introduza versões nos `.csproj`.
- `Directory.Packages.props` declara uma versão por pacote: o alvo é só `net10.0` (ADR 0013).
- Dependências TEC.* são declaradas com `<TecReference Include="..." />`, não com `PackageReference` direto.
- `TEC.Vault` **não depende de nenhum TEC.\*** em produção (só `TEC.Core`); as outras bibliotecas pedem segredos, chaves e certificados a ele em vez de lê-los da configuração.
- `TEC.Vault.AzureKeyVault` depende de `Azure.Identity` e `Azure.Security.KeyVault.*`; `TEC.Vault.HashiCorpVault`, `TEC.Vault.AwsSecretsManager`, `TEC.Vault.GoogleSecretManager`, `TEC.Vault.Infisical`, `TEC.Vault.Synced`, `TEC.Vault.InMemory` dependem só de `TEC.Vault` e HTTP nativo.
- Native AOT: ✅ `IsAotCompatible` em todos os pacotes, inclusive `TEC.Vault.AzureKeyVault` (configuração lida com `VaultSettings`, JSON com source generator/`Utf8JsonWriter`). No Azure, o `Azure.Core` gera avisos de trimming no decodificador PKCS#8 EC, usado só por credenciais com certificado EC em PEM; `ManagedIdentity`, `WorkloadIdentity` e `Developer` não passam por ele (o mesmo que o README e `docs/provedor-azure-key-vault.md` dizem).
- Workflows dos consumidores chamam `tudoemcodigo/tec-workflows`; confira as tags realmente publicadas antes de alterar referências.
- A licença é Apache-2.0. Mantenha `LICENSE`, `NOTICE`, badge/README e `<PackageLicenseExpression>` coerentes; o pacote inclui `NOTICE` quando presente.

## Documentação

- `README.md` e `CHANGELOG.md` têm conteúdo próprio do TEC.Vault: siga o padrão do template, mantenha a marca Tudo em Código em todos os READMEs e não substitua o conteúdo específico por placeholders genéricos.
- Atualize `README.md`, `CHANGELOG.md` e os guias em `docs/` quando uma mudança alterar comportamento ou contrato.
- Registre decisões transversais em um ADR numerado e mantenha `docs/adr/README.md` e `docs/README.md` atualizados.
- Consulte `docs/revisao-tecnica.md` como relatório de auditoria com data e escopo; não trate resultados históricos como estado atual sem nova verificação.
- Workflows e configurações centrais do consumidor estão em `.github/workflows/`; mantenha `.github/workflows/README.md` fiel aos gatilhos, permissões e inputs reais.

## Verificação local

```powershell
dotnet restore TEC.Vault.slnx
dotnet build TEC.Vault.slnx -c Release
dotnet test --solution TEC.Vault.slnx -c Release
$env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"; dotnet test --solution TEC.Vault.slnx -c Release; Remove-Item Env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT
git diff --check
```

O CI também valida convenções, pacote e workflows reutilizáveis. Não afirme que o CI está funcional apenas com build/testes locais: confirme que as tags chamadas existem e que os `permissions` do chamador incluem o mínimo exigido pelo workflow reutilizável.