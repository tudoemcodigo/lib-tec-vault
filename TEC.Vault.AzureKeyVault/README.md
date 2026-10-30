<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Vault" width="100" />

# 🌐 TEC.Vault.AzureKeyVault

**Provedor Azure Key Vault do TEC.Vault: segredos, chaves e certificados com autenticação sem segredo.**

[📚 Documentação do provedor](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-azure-key-vault.md) · [📚 TEC.Vault](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

## ✨ O que é

Implementa `ISecretStore`, `IKeyStore`, `IKeyCryptography`, `ICertificateStore`, lixeira, backup e `IVaultHealthProbe` sobre o Azure SDK. As chaves do `IKeyStore` não saem do cofre (cifra, *wrap* e assinatura no Key Vault). Certificados são diferentes: `DownloadCertificateAsync` traz a chave privada para o processo quando o certificado foi criado como exportável. Para isso o SDK lê o segredo vinculado ao certificado, então a identidade precisa de permissão de leitura de segredos (`secrets/get`, ou o papel *Key Vault Secrets User* no RBAC) além da leitura de certificados. O endereço é validado (HTTPS, domínio oficial do Key Vault) e as listagens são limitadas (`MaxListItems`, padrão 10.000).

| Autenticação (`Authentication`) | Quando usar |
|---|---|
| `ManagedIdentity` (padrão) | Serviços no Azure (App Service, Container Apps, VMs, AKS com identidade gerenciada) |
| `WorkloadIdentity` | Kubernetes com Workload Identity federada |
| `Developer` | Máquina do desenvolvedor (`az login`, Visual Studio); bloqueada fora de Development |

## 🎯 Quando usar

Aplicações hospedadas no Azure (produção e homologação). Para desenvolvimento local sem cofre, combine com `TEC.Vault.InMemory`.

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault.AzureKeyVault --version 0.0.1
```

O pacote traz o `TEC.Vault` junto.

## 🚀 Início rápido

Pela configuração (`appsettings.Production.json`):

```json
{ "Vault": { "Provider": "AzureKeyVault", "AzureKeyVault": { "VaultUri": "https://<nome-do-cofre>.vault.azure.net/" } } }
```

```csharp
using TEC.Vault.AzureKeyVault;
using TEC.Vault.DependencyInjection;

builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers.AddAzureKeyVault());
```

Ou em código:

```csharp
builder.Services.AddTecVault(vault => vault.UseAzureKeyVault(o =>
{
    o.VaultUri = new Uri("https://<nome-do-cofre>.vault.azure.net/");
    o.Authentication = builder.Environment.IsDevelopment()
        ? AzureKeyVaultAuthentication.Developer          // az login / Visual Studio
        : AzureKeyVaultAuthentication.ManagedIdentity;   // produção: nenhum segredo
}));
```

Depois, injete `ISecretReader`, `IKeyCryptography` ou `ICertificateReader` onde precisar. Conceda à identidade só o papel mínimo (ex.: *Key Vault Secrets User* para ler segredos).

## 📚 Documentação

Opções (`MaxRetries`, `NetworkTimeout`, `OperationTimeout`, `MaxListItems`, `Stores`, `TimeProvider`...), RBAC, limites, conversão de erros e Native AOT: [docs/provedor-azure-key-vault.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-azure-key-vault.md).

`net10.0` · Native AOT · [Apache 2.0](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
