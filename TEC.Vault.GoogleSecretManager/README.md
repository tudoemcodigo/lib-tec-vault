<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Vault" width="120" />

# 🔷 TEC.Vault.GoogleSecretManager

**Provedor nativo para o Google Cloud Secret Manager: leitura, gravação e destruição de versões de segredos via API REST v1 oficial do Google Cloud, sem SDKs pesados de terceiros e 100% compatível com Native AOT.**

[📚 Documentação Completa](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-google-secret-manager.md) · [📝 Changelog](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/CHANGELOG.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

---

## 🎯 Visão Geral

- **Sem SDKs Pesados do Google Cloud:** Comunicação REST direta via `SocketsHttpHandler` com a API Secret Manager v1.
- **Autenticação Automática e Sem Segredos:** Suporte nativo ao Google Cloud Metadata Server (Google Kubernetes Engine, Cloud Run, Compute Engine) ou Service Account JSON (via `GOOGLE_APPLICATION_CREDENTIALS` ou options).
- **Assinador JWT RSA-SHA256 Interno:** Criação e assinatura de tokens de acesso OAuth2 internamente, sem bibliotecas de terceiros.
- **Native AOT e Trimming:** Zero reflexão dinâmica (`PublishAot` e trimming 100% validados sem avisos de compilação).
- **Lixeira e Destruição Segura:** Suporte a destruição de versões e listagem de versões desativadas/destruídas através da interface `ISecretRecycleBin`.
- **Resiliência e Observabilidade:** Retentativas exponenciais com jitter, circuit breaker e métricas OpenTelemetry (`ActivitySource` e `Meter`).

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
        // Credenciais resolvidas do Google Metadata Server ou Service Account JSON
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

Distribuído sob a licença [MIT](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE). Copyright © Tudo em Código.
