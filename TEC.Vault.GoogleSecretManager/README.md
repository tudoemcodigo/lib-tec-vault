<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Vault" width="120" />

# 🔷 TEC.Vault.GoogleSecretManager

**Provedor nativo para o Google Cloud Secret Manager: leitura e gravação de segredos via API REST v1 oficial do GCP, sem SDKs pesados de terceiros e 100% compatível com Native AOT.**

</div>

---

## 🚀 Uso

```csharp
using TEC.Vault.GoogleSecretManager;

builder.Services.AddTecVault(vault => vault
    .UseGoogleSecretManager(options =>
    {
        options.ProjectId = "meu-projeto-gcp";
        // Credenciais automáticas via Metadata Server (GKE, Cloud Run) ou GOOGLE_APPLICATION_CREDENTIALS
    }));
```

Ou via `appsettings.json`:

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
