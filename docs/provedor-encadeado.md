[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › 🔗 Provedor Encadeado (Fallback)

# 🔗 Provedor Encadeado (Fallback Multicamadas)

> Permite encadear múltiplos provedores de segredos em ordem de prioridade. Ideal para sobrescrever valores locais em variáveis de ambiente com fallback automático para cofres corporativos (Azure Key Vault, HashiCorp Vault, AWS Secrets Manager, Google Secret Manager).

---

## 🚀 Uso

### Via Código

```csharp
using TEC.Vault.DependencyInjection;
using TEC.Vault.Synced;
using TEC.Vault.AzureKeyVault;

builder.Services.AddTecVault(vault => vault
    .UseChainedSecrets(
        // 1. Prioridade alta: variáveis de ambiente locais (ex.: TECVAULT_ConnectionStrings__Db)
        sp => new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "TECVAULT_" }),
        // 2. Fallback: Azure Key Vault corporativo
        sp => new AzureKeyVaultSecretStore(new AzureKeyVaultOptions { VaultUri = new Uri("https://meu-cofre.vault.azure.net/") })
    ));
```

### Comportamento de Resolução

1. **`GetSecretAsync(name)`**:
   - Tenta ler do primeiro provedor da cadeia.
   - Se encontrar com sucesso, retorna o segredo imediatamente.
   - Se o provedor retornar `VAULT_ITEM_NAO_ENCONTRADO`, consulta o próximo provedor.
   - Se ocorrer um erro crítico de infraestrutura ou permissão (`VAULT_ACESSO_NEGADO`, `VAULT_INDISPONIVEL`), interrompe o encadeamento e propaga a falha.
2. **`ListSecretsAsync()`**:
   - Agrega e deduplica os nomes e propriedades de todos os provedores da cadeia.
3. **`CheckAccessAsync()`**:
   - Verifica a saúde de todos os provedores encadeados.
