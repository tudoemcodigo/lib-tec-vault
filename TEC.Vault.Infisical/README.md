<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-vault/main/Images/Logo.png" alt="TEC.Vault" width="100" />

# 🟣 TEC.Vault.Infisical

**Provedor Infisical do TEC.Vault: leitura e gravação de segredos pela API REST, na nuvem ou self-hosted, sem SDK.**

[📚 Documentação do provedor](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-infisical.md) · [📚 TEC.Vault](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

## ✨ O que é

Implementa `ISecretStore` e `IVaultHealthProbe` sobre a API do Infisical (um projeto, um ambiente e uma pasta por instância).

| Autenticação (`Authentication`) | Credencial |
|---|---|
| `UniversalAuth` (padrão) | `ClientId` + client secret lido de arquivo (`ClientSecretFile`) ou variável (`ClientSecretVariable`) |
| `Kubernetes` | Token da service account (`IdentityId`) |
| `AccessToken` | Token pronto, de arquivo ou variável |

Credencial em texto na configuração é recusada; o arquivo de credencial é relido a cada login e limitado a 64 KB. Respostas limitadas a 4 MB e listagem de versões às 100 mais recentes. Escrita pendente de aprovação (política do Infisical) volta como `VAULT_OPERACAO_NAO_SUPORTADA`.

## 🎯 Quando usar

Aplicações que precisam **ler e gravar** segredos no Infisical pela API. Se a aplicação só lê e um agente já entrega os segredos (`infisical run`, External Secrets Operator), prefira o [`TEC.Vault.Synced`](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/TEC.Vault.Synced/README.md).

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault.Infisical --version 0.0.1
```

O pacote traz o `TEC.Vault` junto.

## 🚀 Início rápido

Pela configuração (`appsettings.Production.json`); o client secret chega por um arquivo montado:

```json
{
  "Vault": {
    "Provider": "Infisical",
    "Infisical": {
      "ProjectId": "<id-do-projeto>",
      "Environment": "prod",
      "ClientId": "<client-id>",
      "ClientSecretFile": "/run/secrets/infisical-client-secret"
    }
  }
}
```

```csharp
using TEC.Vault.DependencyInjection;
using TEC.Vault.Infisical;

builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers.AddInfisical());
```

Ou em código, com Kubernetes Auth:

```csharp
builder.Services.AddTecVault(vault => vault.UseInfisical(o =>
{
    o.ProjectId = "<id-do-projeto>";
    o.Environment = "prod";
    o.Authentication = InfisicalAuthentication.Kubernetes;
    o.IdentityId = "<id-da-identidade>";
}));
```

## 📚 Documentação

Todas as opções (`SiteUrl`, `SecretPath`, `ExpandSecretReferences`, `IncludeImports`, `Http`...), comportamento de versões e tags, conversão de erros e permissões: [docs/provedor-infisical.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-infisical.md).

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
