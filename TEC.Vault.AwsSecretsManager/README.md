<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Vault" width="120" />

# ☁️ TEC.Vault.AwsSecretsManager

**Provedor nativo para o AWS Secrets Manager: leitura e gravação de segredos via HTTP puro e protocolo JSON 1.1 da AWS com assinatura SigV4, sem SDK externo e 100% compatível com Native AOT.**

</div>

---

## 🚀 Uso

```csharp
using TEC.Vault.AwsSecretsManager;

builder.Services.AddTecVault(vault => vault
    .UseAwsSecretsManager(options =>
    {
        options.Region = "sa-east-1";
        // Credenciais estáticas ou resolvidas de AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
    }));
```

Ou via `appsettings.json`:

```json
{
  "Vault": {
    "Provider": "AwsSecretsManager",
    "AwsSecretsManager": {
      "Region": "sa-east-1"
    }
  }
}
```
