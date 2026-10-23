<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Vault" width="120" />

# ☁️ TEC.Vault.AwsSecretsManager

**Provedor nativo para o AWS Secrets Manager: leitura e gravação de segredos via HTTP puro e protocolo JSON 1.1 da AWS com assinatura SigV4, sem SDK externo e 100% compatível com Native AOT.**

[📚 Documentação Completa](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-aws-secrets-manager.md) · [📝 Changelog](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/CHANGELOG.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

---

## 🎯 Visão Geral

- **Sem SDK Pesado da AWS:** Comunicação REST direta via `SocketsHttpHandler` com protocolo JSON 1.1 da AWS.
- **Assinatura SigV4 Nativa:** Assinador HMAC-SHA256 e SHA-256 nativo, em conformidade com o padrão oficial da AWS (AWS4-HMAC-SHA256).
- **Native AOT e Trimming:** Zero reflexão dinâmica (`PublishAot` e trimming 100% seguros sem avisos IL2026/IL3050).
- **Credenciais Automáticas:** Suporte a chaves explícitas ou resolução direta das variáveis padrão do ambiente (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`).
- **Resiliência e Observabilidade:** Retentativas exponenciais com jitter, circuit breaker e métricas OpenTelemetry (`ActivitySource` e `Meter`).

---

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault.AwsSecretsManager --version 0.0.1
```

---

## 🚀 Uso

### Registro em Código

```csharp
using TEC.Vault.AwsSecretsManager;
using TEC.Vault.Abstractions;

builder.Services.AddTecVault(vault => vault
    .UseAwsSecretsManager(options =>
    {
        options.Region = "sa-east-1";
        // Credenciais explícitas ou resolvidas automaticamente do ambiente AWS
    })
    .EnableSecretCache(TimeSpan.FromMinutes(5)));
```

### Registro via `appsettings.json`

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

```csharp
builder.Services.AddTecVault(
    builder.Configuration.GetSection("Vault"),
    providers => providers.AddAwsSecretsManager());
```

---

## 📄 Licença

Distribuído sob a licença [MIT](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE). Copyright © Tudo em Código.
