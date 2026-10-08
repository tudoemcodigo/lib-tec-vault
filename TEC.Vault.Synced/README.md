<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-vault/main/Images/Logo.png" alt="TEC.Vault" width="100" />

# 📂 TEC.Vault.Synced

**Lê segredos que um agente externo já entregou à aplicação (pasta montada, variáveis de ambiente, arquivo JSON ou .env), com a mesma API do TEC.Vault e sem SDK de terceiros.**

[📚 Documentação do provedor](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-synced.md) · [📚 TEC.Vault](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-vault)

</div>

## ✨ O que é

Três leitores de segredos **somente leitura** (`ISecretReader`), escolhidos pelo formato que o agente entrega:

| Provedor | Registro | Fonte |
|---|---|---|
| `Directory` | `UseDirectory` | Uma pasta com um arquivo por segredo (volume do Kubernetes, CSI driver, Vault Agent); links simbólicos confinados à pasta |
| `EnvironmentVariables` | `UseEnvironmentVariables` | Variáveis com prefixo obrigatório (`infisical run`, `bws run`); `__` vira `--` |
| `SecretsFile` | `UseSecretsFile` | Um arquivo JSON (aninhado) ou .env |

Cada fonte tem teto de itens (`MaxItems`, padrão 1.000) e de tamanho; a versão de cada segredo é um HMAC com chave da instância (nunca o valor).

## 🎯 Quando usar

Kubernetes com **External Secrets Operator**, **Secrets Store CSI driver** ou **Vault Agent**; processos iniciados por **`infisical run`** ou **`bws run`** (Bitwarden Secrets Manager); qualquer cofre sem provedor nativo, desde que algo entregue os segredos como arquivos ou variáveis.

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Vault.Synced --version 0.0.1
```

O pacote traz o `TEC.Vault` junto.

## 🚀 Início rápido

Pela configuração (segredos montados em `/mnt/secrets`):

```json
{ "Vault": { "Provider": "Directory", "Directory": { "Path": "/mnt/secrets" } } }
```

```csharp
using TEC.Vault.DependencyInjection;
using TEC.Vault.Synced;

builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers.AddSynced());
```

Ou em código:

```csharp
builder.Services.AddTecVault(vault => vault.UseDirectory(o => o.Path = "/mnt/secrets"));
// builder.Services.AddTecVault(vault => vault.UseEnvironmentVariables(o => o.Prefix = "TECVAULT_"));
// builder.Services.AddTecVault(vault => vault.UseSecretsFile(o => o.Path = "/vault/secrets/app.json"));
```

## 📚 Documentação

Opções de cada fonte, layout `..data` do Kubernetes, versão por HMAC e receitas prontas (ESO + Bitwarden, ESO + Infisical, Vault Agent, CSI driver, `infisical run`, `bws run`): [docs/provedor-synced.md](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/docs/provedor-synced.md).

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-vault/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
