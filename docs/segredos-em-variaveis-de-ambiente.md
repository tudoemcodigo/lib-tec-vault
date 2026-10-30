[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › 🌐 Segredos em Variáveis de Ambiente

# 🌐 Segredos em Variáveis de Ambiente

> Guia de uso, convenções de mapeamento, isolamento de escopo e estratégia de fallback em camadas para segredos injetados via variáveis de ambiente.

## 📑 Sumário

- [🎯 Visão Geral](#-visão-geral)
- [🔒 Segurança e Isolamento](#-segurança-e-isolamento)
  - [Por que o prefixo obrigatório?](#por-que-o-prefixo-obrigatório)
  - [Mapeamento e Normalização de Nomes](#mapeamento-e-normalização-de-nomes)
- [🚀 Como Usar](#-como-usar)
  - [1. Provedor Direto (`UseEnvironmentVariables`)](#1-provedor-direto-useenvironmentvariables)
  - [2. Provedor Encadeado (Ambiente como Fallback ou Override)](#2-provedor-encadeado-ambiente-como-fallback-ou-override)
  - [3. Configuração via `appsettings.json`](#3-configuração-via-appsettingsjson)
- [📦 Native AOT e Zero Reflection](#-native-aot-e-zero-reflection)
- [🧪 Testabilidade](#-testabilidade)

---

## 🎯 Visão Geral

Em ambientes conteinerizados (Kubernetes, AWS ECS, Google Cloud Run, Docker Swarm) ou pipelines de CI/CD, agentes externos frequentemente injetam segredos no processo como **variáveis de ambiente** (`envFrom`, GitHub Secrets, Vault Agent, Infisical CLI).

O `TEC.Vault.Synced` disponibiliza o `EnvironmentSecretStore`, que implementa:
- [`ISecretReader`](segredos.md): permite ler segredos através da mesma API unificada (`GetSecretAsync`, `ExistsAsync`, `ListSecretsAsync`).
- [`IVaultHealthProbe`](cache-e-health-check.md): reporta o status de saúde e a contagem de segredos carregados no processo.

---

## 🔒 Segurança e Isolamento

### Por que o prefixo obrigatório?

A especificação de segurança do `TEC.Vault` **exige** um prefixo. Não há valor padrão: sem `Prefix` (ou com menos de 2 caracteres, ou com algo além de letras, números e `_`), a subida falha com `InvalidOperationException`. Os exemplos abaixo usam `TECVAULT_`, mas escolha o seu:
1. **Evita vazamento de variáveis do sistema:** Impede que chamadas como `ListSecretsAsync()` listem inadvertidamente caminhos do SO (`PATH`, `TEMP`), credenciais do runtime ou variáveis internas da aplicação.
2. **Isola o escopo de segurança:** Apenas as variáveis explicitamente designadas como segredos de cofre são tratadas pelo componente.

### Mapeamento e Normalização de Nomes

O nome do segredo é o nome da variável sem o prefixo. A única troca feita é `__` por `--`, o separador de seção do `IConfiguration`. Um `_` simples continua `_` e não vira hífen. A busca não diferencia maiúsculas de minúsculas.

| Variável de Ambiente (`Prefix = "TECVAULT_"`) | Nome do Segredo (`ISecretReader`) |
|---|---|
| `TECVAULT_db-senha` | `db-senha` |
| `TECVAULT_db_senha` | `db_senha` (não é `db-senha`) |
| `TECVAULT_ConnectionStrings__Db` | `ConnectionStrings--Db` |

> [!NOTE]
> Se a sua shell não aceita hífen em nome de variável, dê ao segredo um nome sem hífen (ex.: `db_senha`) e leia-o com esse mesmo nome.

---

## 🚀 Como Usar

### 1. Provedor Direto (`UseEnvironmentVariables`)

```csharp
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault;
using TEC.Vault.Synced;
using TEC.Vault.Abstractions;

var services = new ServiceCollection();

// Configura o cofre para ler variáveis de ambiente
services.AddTecVault(vault => vault
    .UseEnvironmentVariables(options =>
    {
        options.Prefix = "TECVAULT_"; // Prefixo obrigatório
    })
    .EnableSecretCache(TimeSpan.FromMinutes(10))); // Cache em memória opcional

var provider = services.BuildServiceProvider();
var secretReader = provider.GetRequiredService<ISecretReader>();

// Lê a variável 'TECVAULT_db-password'
var result = await secretReader.GetSecretAsync("db-password");
if (result.IsSuccess)
{
    Console.WriteLine($"Segredo lido com sucesso: versão {result.Value.Version}");
    string secretValue = result.Value.Value;
}
```

---

### 2. Provedor Encadeado (Ambiente como Fallback ou Override)

O cenário mais poderoso em arquiteturas modernas de nuvem é o **encadeamento em camadas**:
1. **Camada Local / Variáveis de Ambiente:** Permite override local pelo desenvolvedor ou injeção em CI.
2. **Camada de Nuvem Remota:** Busca no AWS Secrets Manager, Azure Key Vault, HashiCorp Vault ou Google Secret Manager se não estiver no ambiente.

```csharp
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault;
using TEC.Vault.Synced;
using TEC.Vault.AwsSecretsManager;
using TEC.Vault.Abstractions;

var services = new ServiceCollection();

services.AddTecVault(vault => vault
    .UseChainedSecrets(
        // Camada 1: Variáveis de Ambiente (prioridade ou override local)
        _ => new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "TECVAULT_" }),
        // Camada 2: AWS Secrets Manager (fallback em produção)
        _ => new AwsSecretsManagerSecretStore(new AwsSecretsManagerOptions
        {
            Region = "us-east-1",
            AccessKeyId = "AKIA...",
            SecretAccessKey = "wJalr..."
        })
    )
    .EnableSecretCache(TimeSpan.FromMinutes(5)));

var provider = services.BuildServiceProvider();
var reader = provider.GetRequiredService<ISecretReader>();

// Busca primeiro em TECVAULT_jwt-secret; se não existir (VAULT_ITEM_NAO_ENCONTRADO), busca na AWS
var jwtSecret = await reader.GetSecretAsync("jwt-secret");
```

---

### 3. Configuração via `appsettings.json`

Você também pode configurar o provedor por arquivo de configuração sem acoplar o código:

```json
{
  "Vault": {
    "Secrets": {
      "Provider": "EnvironmentVariables"
    },
    "EnvironmentVariables": {
      "Prefix": "TECVAULT_"
    }
  }
}
```

```csharp
builder.Services.AddTecVault(
    builder.Configuration.GetSection("Vault"),
    providers => providers.AddSynced());
```

---

## 📦 Native AOT e Zero Reflection

O `EnvironmentSecretStore` foi projetado especificamente para:
- **Zero Reflection:** Leitura direta de `Environment.GetEnvironmentVariables()` sem serializadores dinâmicos.
- **Native AOT:** Compatibilidade total com compilação antecipada (`PublishAot`), sem avisos `IL2026` ou `IL3050`.
- **Alocação Mínima:** Reutilização de buffers e ausência de overhead em loops de leitura.

---

## 🧪 Testabilidade

Para testes de unidade sem poluir as variáveis de ambiente reais do sistema operacional, você pode definir variáveis no processo corrente:

```csharp
Environment.SetEnvironmentVariable("TECVAULT_api-token", "segredo-de-teste");

var store = new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "TECVAULT_" });
var result = await store.GetSecretAsync("api-token");

Assert.True(result.IsSuccess);
Assert.Equal("segredo-de-teste", result.Value.Value);
```
