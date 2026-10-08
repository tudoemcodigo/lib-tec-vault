<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-vault/main/Images/Logo.png" alt="TEC.Vault" width="100" />

# 🔐 TEC.Vault

**Uma única API para segredos, chaves e certificados: troque de cofre sem mudar o código, criptografe sem expor chaves e audite cada acesso sem registrar valores.**

[📚 Documentação](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/README.md) · [📝 Changelog](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/CHANGELOG.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

## ✨ O que é

O pacote base do TEC.Vault, **sem SDK de nuvem**: interfaces (`ISecretReader`, `ISecretStore`, `IKeyCryptography`, `ICertificateReader`...), modelos, erros padronizados (`VaultErrors`), validação de entrada, auditoria, métricas, cache de segredos, fonte de `IConfiguration`, health check, geração/rotação de segredos, criptografia envelope, escolha do provedor pela configuração e a base para escrever provedores (`VaultProviderBase`, `VaultHttpProviderBase`).

Todo método assíncrono retorna `Result`/`Result<T>` do [TEC.Core](https://github.com/tudoemcodigo/lib-tec-core): falhas do cofre nunca viram exceção para o chamador.

## 🎯 Quando usar

| Situação | Instale |
|---|---|
| Aplicação que lê ou grava segredos | Um provedor (ele traz este pacote junto): `TEC.Vault.AzureKeyVault`, `TEC.Vault.HashiCorpVault`, `TEC.Vault.Infisical`, `TEC.Vault.Synced` ou `TEC.Vault.InMemory` |
| Biblioteca que só recebe `ISecretReader`/`IKeyCryptography` por injeção | Só `TEC.Vault` |
| Escrever um provedor para outro cofre | Só `TEC.Vault` ([guia](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/novo-provedor.md)) |

## 📥 Instalação

Feed do GitHub Packages da organização `tudoemcodigo` (PAT *classic* com `read:packages`):

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault --version 0.0.1
```

## 🚀 Início rápido

Uma biblioteca que depende só da abstração e deixa a aplicação escolher o cofre:

```csharp
using TEC.Core.Common.Results;
using TEC.Vault.Abstractions;

public sealed class PartnerClient(ISecretReader vault)
{
    public async Task<Result<string>> GetTokenAsync(CancellationToken cancellationToken)
    {
        var secret = await vault.GetSecretAsync("parceiro-api-token", cancellationToken: cancellationToken);
        return secret.IsFailure
            ? secret.ToFailure<string>()   // VAULT_ITEM_NAO_ENCONTRADO, VAULT_INDISPONIVEL...
            : Result<string>.Success(secret.Value.Value);
    }
}
```

Na aplicação, o cofre é escolhido no `appsettings` (`"Vault": { "Provider": "..." }`) com `services.AddTecVault(configuration.GetSection("Vault"), providers => ...)`, ou em código com `services.AddTecVault(vault => vault.UseXxx(...))`.

## 📚 Documentação

| Tema | Link |
|---|---|
| Segredos, chaves e certificados | [segredos](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/segredos.md) · [chaves](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/chaves.md) · [certificados](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/certificados.md) |
| Registro e configuração | [injeção de dependências](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/injecao-de-dependencias.md) · [escolha pelo appsettings](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/configuracao-por-appsettings.md) · [IConfiguration](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/configuracao.md) · [cache e health check](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/cache-e-health-check.md) |
| Erros, telemetria e segurança | [erros](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/erros.md) · [observabilidade](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/observabilidade.md) · [segurança](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/seguranca.md) |
| Índice completo | [docs/README.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/README.md) |

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
