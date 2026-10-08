<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-vault/main/Images/Logo.png" alt="TEC.Vault" width="100" />

# 🏛️ TEC.Vault.HashiCorpVault

**Provedor HashiCorp Vault (e OpenBao) do TEC.Vault: segredos no KV v2, chaves no Transit e certificados com PKI, por HTTP e sem SDK.**

[📚 Documentação do provedor](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-hashicorp-vault.md) · [📚 TEC.Vault](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

## ✨ O que é

| Família | Motor do Vault | Interfaces |
|---|---|---|
| 🔑 Segredos | KV v2 (versões, `custom_metadata`, lixeira com delete/undelete/destroy) | `ISecretStore`, `ISecretRecycleBin` |
| 🔐 Chaves | Transit (RSA-OAEP-256, RSA-PSS, ECDSA; a chave nunca sai do Vault) | `IKeyStore`, `IKeyCryptography` |
| 📜 Certificados | Guardados no KV, emitidos pelo PKI a partir de CSR (ou autoassinados) | `ICertificateStore`, `ICertificateRecycleBin` |

Login por **Kubernetes** (padrão), **JWT**, **AppRole** ou **token**, compartilhado pelos três stores, com credencial lida de arquivo ou variável a cada login (arquivo limitado a 64 KB). Listagens limitadas por `MaxListItems` (padrão 10.000): acima disso, `VAULT_LISTAGEM_ACIMA_DO_LIMITE` sem ler os metadados dos itens. Testado a cada PR contra um HashiCorp Vault real em container.

## 🎯 Quando usar

Aplicações com HashiCorp Vault ou OpenBao (on-premises, Kubernetes, HCP Vault) que precisam ler e gravar segredos, usar chaves do Transit ou emitir certificados.

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault.HashiCorpVault --version 0.0.1
```

O pacote traz o `TEC.Vault` junto.

## 🚀 Início rápido

Pela configuração (`appsettings.Production.json`), com login Kubernetes:

```json
{
  "Vault": {
    "Provider": "HashiCorpVault",
    "HashiCorpVault": {
      "Address": "https://<endereco-do-vault>:8200",
      "Auth": { "Method": "Kubernetes", "Role": "minha-api" },
      "Kv": { "Mount": "secret", "BasePath": "minha-api" },
      "Transit": { "Mount": "transit" }
    }
  }
}
```

```csharp
using TEC.Vault.DependencyInjection;
using TEC.Vault.HashiCorpVault;

builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers.AddHashiCorpVault());
```

Ou em código:

```csharp
builder.Services.AddTecVault(vault => vault.UseHashiCorpVault(o =>
{
    o.Address = new Uri("https://<endereco-do-vault>:8200");
    o.Auth.Method = HashiCorpVaultAuthMethod.Kubernetes;
    o.Auth.Role = "minha-api";
    o.Kv.BasePath = "minha-api";
}));
```

## 📚 Documentação

Todas as opções (`Namespace`, `Kv`, `Transit`, `Pki`, `Stores`, `MaxListItems`, `Http`...), política de menor privilégio, conversão de erros, OpenBao e desenvolvimento local: [docs/provedor-hashicorp-vault.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-hashicorp-vault.md).

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
