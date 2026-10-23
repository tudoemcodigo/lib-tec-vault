[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › ☁️ Provedor AWS Secrets Manager

# ☁️ Provedor AWS Secrets Manager

> Lê e gerencia segredos no AWS Secrets Manager diretamente pela API REST da AWS (protocolo JSON 1.1) com assinatura criptográfica **AWS Signature Version 4 (SigV4)** nativa, sem o pesado SDK oficial da AWS, com zero dependências externas e 100% compatível com **Native AOT**.

---

## 📑 Sumário

- [🎯 Visão geral](#-visão-geral)
- [🚀 Uso](#-uso)
- [⚙️ Opções](#️-opções)
- [🔐 Autenticação](#-autenticação)
- [❌ Mapeamento de Erros](#-mapeamento-de-erros)

---

## 🎯 Visão geral

O pacote `TEC.Vault.AwsSecretsManager` implementa `ISecretStore`, `ISecretReader` e `IVaultHealthProbe`.

Vantagens:
- **Zero SDK da AWS**: Binário ultraleve, dispensando mais de 20 MB de DLLs do AWS SDK.
- **Native AOT Ready**: Totalmente livre de reflection e código dinâmico.
- **Assinatura SigV4 Nativa**: Assina requisições em alta velocidade usando primitivas criptográficas `HMACSHA256` e `SHA256` nativas do runtime .NET.

---

## 🚀 Uso

### Via Código

```csharp
using TEC.Vault.AwsSecretsManager;

builder.Services.AddTecVault(vault => vault
    .UseAwsSecretsManager(options =>
    {
        options.Region = "sa-east-1";
        // Credenciais estáticas ou resolvidas automaticamente das variáveis de ambiente padrão AWS
    }));
```

### Via Configuração (`appsettings.json`)

```json
{
  "Vault": {
    "Provider": "AwsSecretsManager",
    "AwsSecretsManager": {
      "Region": "sa-east-1",
      "MaxListItems": 1000
    }
  }
}
```

---

## 🔐 Autenticação

O provedor resolve as credenciais na seguinte ordem:
1. Propriedades explícitas em código: `AccessKeyId`, `SecretAccessKey`, `SessionToken`.
2. Variáveis de ambiente padrão da AWS:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `AWS_SESSION_TOKEN` (opcional, para credenciais temporárias via STS/IRSA).
   - `AWS_REGION` ou `AWS_DEFAULT_REGION`.
