<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Vault" width="120" />

# ☁️ TEC.Vault.AwsSecretsManager

**Provedor nativo para o AWS Secrets Manager: leitura e gravação de segredos via HTTP puro e protocolo JSON 1.1 da AWS com assinatura SigV4, sem SDK externo e 100% compatível com Native AOT.**

[📚 Documentação Completa](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-aws-secrets-manager.md) · [📝 Changelog](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/CHANGELOG.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

---

## 🎯 Visão Geral

- **Sem SDK Pesado da AWS:** Comunicação REST direta com o protocolo JSON 1.1 da AWS, sobre o mesmo `VaultHttpClient` do HashiCorp Vault e do Infisical.
- **Assinatura SigV4 Nativa:** Assinador HMAC-SHA256 e SHA-256 nativo, em conformidade com o padrão oficial da AWS (AWS4-HMAC-SHA256); cada tentativa é assinada de novo.
- **Native AOT e Trimming:** Zero reflexão dinâmica (`PublishAot` e trimming 100% seguros sem avisos IL2026/IL3050).
- **Credenciais sem segredo na aplicação:** IRSA (web identity com o token projetado do EKS), credenciais de container do ECS e do EKS Pod Identity, IMDSv2 do EC2 e, como último recurso, chaves em variáveis de ambiente. Credenciais temporárias ficam em cache e são renovadas antes de expirar.
- **Resiliência e observabilidade:** retentativa com backoff (também para `ThrottlingException`), tempo limite na leitura do corpo, teto de resposta, circuit breaker e telemetria OpenTelemetry (`ActivitySource` e `Meter`).
- **Escopo:** só segredos (`ISecretStore`), com tags aplicadas de verdade (`TagResource`/`UntagResource`). Sem lixeira nem backup. Detalhes e limitações em [docs/provedor-aws-secrets-manager.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-aws-secrets-manager.md).

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
        // Credenciais: IRSA, container do ECS, IMDSv2 ou variáveis de ambiente, nessa ordem
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

Distribuído sob a licença [Apache 2.0](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE). Copyright © Tudo em Código.
