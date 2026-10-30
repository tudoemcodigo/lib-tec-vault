<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Vault" width="120" />

# 🔷 TEC.Vault.GoogleSecretManager

**Provedor nativo para o Google Cloud Secret Manager: leitura, gravação, exclusão e habilitar/desabilitar versões de segredos pela API REST v1 do Google Cloud, sem SDKs pesados de terceiros e compatível com Native AOT.**

[📚 Documentação Completa](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-google-secret-manager.md) · [📝 Changelog](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/CHANGELOG.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

---

## 🎯 Visão Geral

- **Sem SDKs Pesados do Google Cloud:** Comunicação REST direta com a API Secret Manager v1, sobre o mesmo `VaultHttpClient` do HashiCorp Vault e do Infisical.
- **Autenticação:** token estático em variável de ambiente, Service Account JSON (`GOOGLE_APPLICATION_CREDENTIALS` ou opções, com `token_uri` conferido) ou o Metadata Server do Google (GKE, Cloud Run, Compute Engine). O token fica em cache, é renovado antes de expirar e é descartado quando o Google responde 401.
- **Assinador JWT RSA-SHA256 Interno:** Criação e assinatura de tokens de acesso OAuth2 internamente, sem bibliotecas de terceiros.
- **Native AOT e Trimming:** Zero reflexão dinâmica (`PublishAot` e trimming 100% validados sem avisos de compilação).
- **Escopo:** só segredos (`ISecretStore`), com labels aplicadas de verdade (`PATCH`) e habilitar/desabilitar versões. Não há lixeira nem backup: `DeleteSecretAsync` remove o segredo e todas as versões sem recuperação. Detalhes e limitações em [docs/provedor-google-secret-manager.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-google-secret-manager.md).
- **Resiliência e observabilidade:** retentativa com backoff, tempo limite na leitura do corpo, teto de resposta, circuit breaker e telemetria OpenTelemetry (`ActivitySource` e `Meter`).

---

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault.GoogleSecretManager --version 0.0.1
```

---

## 🚀 Uso

### Registro em Código

```csharp
using TEC.Vault.GoogleSecretManager;
using TEC.Vault.Abstractions;

builder.Services.AddTecVault(vault => vault
    .UseGoogleSecretManager(options =>
    {
        options.ProjectId = "meu-projeto-gcp";
        // Ordem das credenciais: token estático (AccessToken em código ou AccessTokenVariable), depois
        // Service Account JSON (CredentialsJsonVariable, CredentialsJsonFile ou GOOGLE_APPLICATION_CREDENTIALS),
        // depois o Metadata Server (UseMetadataServer)
    })
    .EnableSecretCache(TimeSpan.FromMinutes(5)));
```

### Registro via `appsettings.json`

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
builder.Services.AddTecVault(
    builder.Configuration.GetSection("Vault"),
    providers => providers.AddGoogleSecretManager());
```

---

## 📄 Licença

Distribuído sob a licença [Apache 2.0](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE). Copyright © Tudo em Código.
