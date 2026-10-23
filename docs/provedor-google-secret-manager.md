[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › 🔷 Provedor Google Secret Manager

# 🔷 Provedor Google Secret Manager

> Lê e gerencia segredos no Google Cloud Secret Manager através da API REST v1 nativa do GCP, sem o pesado Google Cloud SDK, compatível com OAuth2 Service Account JSON, Google Metadata Server e 100% **Native AOT**.

---

## 📑 Sumário

- [🎯 Visão geral](#-visão-geral)
- [🚀 Uso](#-uso)
- [⚙️ Opções](#️-opções)
- [🔐 Autenticação](#-autenticação)

---

## 🎯 Visão geral

O pacote `TEC.Vault.GoogleSecretManager` implementa `ISecretStore`, `ISecretReader` e `IVaultHealthProbe`.

Vantagens:
- **Zero SDK do Google**: Sem dependências pesadas de `Google.Cloud.SecretManager.V1` e gRPC monolítico.
- **Native AOT Ready**: Totalmente livre de reflection e código dinâmico.
- **Metadata Server Nativo**: Autenticação automática sem arquivos nem credenciais ao rodar em GKE, Cloud Run e Compute Engine.

---

## 🚀 Uso

### Via Código

```csharp
using TEC.Vault.GoogleSecretManager;

builder.Services.AddTecVault(vault => vault
    .UseGoogleSecretManager(options =>
    {
        options.ProjectId = "meu-projeto-gcp";
    }));
```

### Via Configuração (`appsettings.json`)

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

---

## 🔐 Autenticação

1. **Google Metadata Server** (padrão em ambientes gerenciados GCP: Cloud Run, GKE, Compute Engine): obtém tokens automaticamente sem qualquer configuração.
2. **Service Account JSON**: via caminho de arquivo em `GOOGLE_APPLICATION_CREDENTIALS` ou `CredentialsJsonFile`. Gera e assina o JWT com RSA-SHA256 diretamente no processo.
3. **Token Estático**: via `AccessToken` ou variável configurada.
