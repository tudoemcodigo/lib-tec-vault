[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › 🔗 Provedor Encadeado (Fallback)

# 🔗 Provedor Encadeado (Fallback Multicamadas)

> Encadeia vários leitores de segredos em ordem de prioridade. Serve, por exemplo, para sobrescrever um valor com variáveis de ambiente e cair para um cofre corporativo (Azure Key Vault, HashiCorp Vault, AWS Secrets Manager, Google Secret Manager) quando o segredo não existe localmente.

---

## 🚀 Uso

### Via código

```csharp
using TEC.Vault.AzureKeyVault;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Synced;

builder.Services.AddTecVault(vault => vault
    .UseChainedSecrets(
        // 1. Prioridade alta: variáveis de ambiente locais (ex.: TECVAULT_ConnectionStrings__Db)
        sp => new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "TECVAULT_" }),
        // 2. Fallback: Azure Key Vault corporativo
        sp => AzureKeyVaultStores.CreateSecretStore(o => o.VaultUri = new Uri("https://meu-cofre.vault.azure.net/"))
    ));
```

O `AzureKeyVaultSecretStore` não tem construtor público: crie-o por `AzureKeyVaultStores.CreateSecretStore`. O `ChainedSecretReader` descarta (`Dispose`) os leitores da cadeia junto com o container. O registro só expõe `ISecretReader` (e a sonda de saúde): a cadeia não é um `ISecretStore`.

### Comportamento de resolução

1. **`GetSecretAsync(name)`**:
   - Tenta o primeiro leitor da cadeia e devolve o segredo assim que um deles responde com sucesso.
   - Com `VAULT_ITEM_NAO_ENCONTRADO` ou `VAULT_ENTRADA_INVALIDA`, consulta o leitor seguinte. O segundo caso cobre um nome que uma camada recusa pela regra própria (por exemplo, um nome com `/`, que o `EnvironmentSecretStore` recusa e o cofre em memória aceita).
   - Com qualquer outro erro (`VAULT_ACESSO_NEGADO`, `VAULT_INDISPONIVEL`, `VAULT_ITEM_DESABILITADO`...), interrompe a busca e devolve a falha, para não mascarar um problema de segurança com o valor de uma camada menos confiável.
   - Se todos os leitores responderem `NotFound`, devolve o último erro.
2. **`ExistsAsync(name)`**: `true` assim que um leitor confirma; erros diferentes de não encontrado ou entrada inválida encerram a busca.
3. **`ListSecretsAsync()`**: junta os itens de todos os leitores, sem repetir nomes (vale o do leitor de maior prioridade), ordenados por nome. Um erro grave em qualquer camada falha a listagem inteira, para não limpar chaves do `IConfiguration`.
4. **`ListSecretVersionsAsync(name)`**: devolve as versões do primeiro leitor que conhece o nome.
5. **`CheckAccessAsync()`**: chama a sonda de cada leitor que a implementa e devolve a primeira falha.

> [!NOTE]
> `version` é repassada a todas as camadas. Um leitor que não conhece aquela versão (como o `Directory`, que só tem a atual) responde `NotFound` e a busca segue para a camada seguinte.

---
[📚 Índice](README.md) · [🌐 Segredos em variáveis de ambiente](segredos-em-variaveis-de-ambiente.md)
