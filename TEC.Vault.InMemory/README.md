<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-vault/main/Images/Logo.png" alt="TEC.Vault" width="100" />

# 🧠 TEC.Vault.InMemory

**Cofre em memória do TEC.Vault, com o mesmo comportamento dos provedores reais: para desenvolvimento local e testes automatizados.**

[📚 Documentação do provedor](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-em-memoria.md) · [📚 TEC.Vault](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

## ✨ O que é

Implementa todas as interfaces do TEC.Vault (segredos, chaves, certificados, lixeira, backup e sonda de saúde) em memória, com criptografia real (RSA e EC), versões, validação de entrada e os mesmos códigos de `VaultErrors`. Passa nos mesmos testes de contrato dos provedores reais.

> [!WARNING]
> Bloqueado fora de **Development**: em outro ambiente a subida falha com `InvalidOperationException`, a não ser que `AllowOutsideDevelopment = true` (só para testes automatizados). Os dados somem quando o processo termina.

## 🎯 Quando usar

- Rodar a aplicação localmente sem cofre nem credencial.
- Testes de unidade e de integração da aplicação que dependem de `ISecretReader`, `IKeyCryptography` ou `ICertificateReader`.

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault.InMemory --version 0.0.1
```

O pacote traz o `TEC.Vault` junto.

## 🚀 Início rápido

Pela configuração (`appsettings.Development.json`):

```json
{ "Vault": { "Provider": "InMemory", "InMemory": { "InitialSecrets": { "db-senha": "senha-local" } } } }
```

```csharp
using TEC.Vault.DependencyInjection;
using TEC.Vault.InMemory;

builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers.AddInMemory());
```

Ou em código:

```csharp
builder.Services.AddTecVault(vault => vault.UseInMemory(o => o.InitialSecrets["db-senha"] = "senha-local"));
```

## 📚 Documentação

Opções (`InitialSecrets`, `MaxBackups`, `Stores`, `TimeProvider`...), diferenças de um cofre real e a trava de ambiente: [docs/provedor-em-memoria.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-em-memoria.md).

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
