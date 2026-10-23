namespace TEC.Vault.DependencyInjection;

/// <summary>
/// Escolha do provedor de cada família pela configuração: <c>Vault:&lt;Família&gt;:Provider</c> ou, sem ele, <c>Vault:Provider</c>.
/// </summary>
internal sealed class VaultProviderSelection
{
    internal const string ProviderKey = "Provider";
    internal const string CacheKey = "Cache";
    internal const string ConfigurationKey = "Configuration";

    private static readonly (VaultStores Store, string Key, string Label)[] Families =
    [
        (VaultStores.Secrets, "Secrets", "segredos"),
        (VaultStores.Keys, "Keys", "chaves"),
        (VaultStores.Certificates, "Certificates", "certificados")
    ];

    private VaultProviderSelection(VaultSettings root, List<(VaultProviderRegistration Provider, VaultStores Stores)> groups)
    {
        Root = root;
        Groups = groups;
    }

    /// <summary>Seção raiz (<c>Vault</c>), para ler as demais chaves e validar as desconhecidas no fim.</summary>
    internal VaultSettings Root { get; }

    /// <summary>Um item por provedor escolhido, com todas as famílias atribuídas a ele.</summary>
    internal IReadOnlyList<(VaultProviderRegistration Provider, VaultStores Stores)> Groups { get; }

    /// <summary>Provedor escolhido para segredos, se houver.</summary>
    internal VaultProviderRegistration? SecretsProvider =>
        Groups.FirstOrDefault(g => g.Stores.HasFlag(VaultStores.Secrets)).Provider;

    /// <summary>Lê e valida a escolha. As seções de provedores disponíveis e não escolhidos são aceitas sem validação.</summary>
    /// <exception cref="InvalidOperationException">Provedor desconhecido, ou família pedida explicitamente a um provedor que não a atende.</exception>
    internal static VaultProviderSelection Resolve(VaultSettings root, VaultProviderCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(catalog);

        var defaultName = root.GetString(ProviderKey);
        var assigned = new Dictionary<VaultProviderRegistration, VaultStores>();

        foreach (var (store, key, label) in Families)
        {
            var family = root.GetSection(key);
            var explicitName = family.GetString(ProviderKey);
            var name = explicitName ?? defaultName;
            if (name is null || string.Equals(name, VaultProviderCatalog.None, StringComparison.OrdinalIgnoreCase))
                continue;

            var path = explicitName is null ? $"{root.Path}:{ProviderKey}".TrimStart(':') : $"{family.Path}:{ProviderKey}";
            if (!catalog.TryGet(name, out var provider))
            {
                throw new InvalidOperationException(
                    $"{path}: o provedor '{name}' não está disponível. Disponíveis: {string.Join(", ", catalog.Names.Order(StringComparer.Ordinal))}. " +
                    "Adicione o pacote do provedor e chame providers.AddXxx() no AddTecVault.");
            }

            if (!provider.SupportedStores.HasFlag(store))
            {
                if (explicitName is null)
                    continue;   // provedor padrão sem esta família (ex.: Directory em chaves): a família fica sem provedor
                throw new InvalidOperationException($"{path}: o provedor '{provider.Name}' não atende {label}.");
            }

            assigned[provider] = assigned.GetValueOrDefault(provider) | store;
        }

        foreach (var name in catalog.Names)
        {
            if (!catalog.TryGet(name, out var provider) || !assigned.ContainsKey(provider))
                root.Ignore(name);
        }

        return new VaultProviderSelection(root, assigned.Select(kv => (kv.Key, kv.Value)).ToList());
    }

    /// <summary>Registra cada provedor escolhido no <paramref name="builder"/>, com a sua seção de opções.</summary>
    internal void Apply(VaultBuilder builder)
    {
        foreach (var (provider, stores) in Groups)
            provider.Use(builder, Root.GetSection(provider.Name), stores);
    }
}
