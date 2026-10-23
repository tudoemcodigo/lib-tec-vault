using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;

namespace TEC.Vault.DependencyInjection;

/// <summary>
/// Provedor disponível para escolha pela configuração (<c>Vault:Provider</c>). Cada pacote de provedor expõe um
/// <c>AddXxx()</c> em <see cref="VaultProviderCatalog"/> que cria esta descrição.
/// </summary>
public sealed class VaultProviderRegistration
{
    /// <summary>Cria a descrição do provedor.</summary>
    /// <param name="name">Nome usado na configuração (ex.: <c>"AzureKeyVault"</c>), sem diferenciar maiúsculas.</param>
    /// <param name="supportedStores">Famílias que o provedor atende.</param>
    /// <param name="use">
    /// Registra o provedor no <see cref="VaultBuilder"/> para as famílias escolhidas (sempre um subconjunto de
    /// <paramref name="supportedStores"/>), lendo as opções da seção <c>Vault:&lt;nome&gt;</c>. Chamado uma única vez por
    /// aplicação, com todas as famílias que a configuração atribuiu a este provedor.
    /// </param>
    /// <param name="createSecretReader">
    /// Cria o leitor de segredos sem injeção de dependência, para a fonte de <c>IConfiguration</c>. <c>null</c>: o provedor não
    /// pode ser usado como fonte de configuração.
    /// </param>
    /// <exception cref="ArgumentException">Nome vazio, igual a <c>None</c> ou com caracteres fora de letras, dígitos, <c>.</c>, <c>-</c> e <c>_</c>; ou nenhuma família.</exception>
    public VaultProviderRegistration(string name, VaultStores supportedStores, Action<VaultBuilder, VaultSettings, VaultStores> use,
        Func<VaultSettings, ILoggerFactory?, ISecretReader>? createSecretReader = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(use);
        if (!name.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_') ||
            string.Equals(name, VaultProviderCatalog.None, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException($"Nome de provedor inválido: '{name}'.", nameof(name));
        if (supportedStores == VaultStores.None || (supportedStores & ~VaultStores.All) != 0)
            throw new ArgumentException("Informe ao menos uma família válida.", nameof(supportedStores));
        if (createSecretReader is not null && !supportedStores.HasFlag(VaultStores.Secrets))
            throw new ArgumentException("Só um provedor de segredos pode criar o leitor da fonte de configuração.", nameof(createSecretReader));

        Name = name;
        SupportedStores = supportedStores;
        Use = use;
        CreateSecretReader = createSecretReader;
    }

    /// <summary>Nome usado na configuração.</summary>
    public string Name { get; }

    /// <summary>Famílias que o provedor atende.</summary>
    public VaultStores SupportedStores { get; }

    /// <summary>Registro no <see cref="VaultBuilder"/>.</summary>
    public Action<VaultBuilder, VaultSettings, VaultStores> Use { get; }

    /// <summary>Criação do leitor de segredos para a fonte de <c>IConfiguration</c> (<c>null</c> = não suportado).</summary>
    public Func<VaultSettings, ILoggerFactory?, ISecretReader>? CreateSecretReader { get; }
}

/// <summary>
/// Provedores que a aplicação deixa disponíveis para a configuração escolher. Compatível com Native AOT: só os provedores
/// adicionados aqui (código referenciado explicitamente) podem ser escolhidos; nada é descoberto por reflexão.
/// </summary>
/// <example>
/// <code>
/// builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers
///     .AddAzureKeyVault()
///     .AddSynced()
///     .AddInMemory());
/// </code>
/// </example>
public sealed class VaultProviderCatalog
{
    /// <summary>Valor de <c>Provider</c> que desliga a família.</summary>
    public const string None = "None";

    private readonly Dictionary<string, VaultProviderRegistration> _providers = new(StringComparer.OrdinalIgnoreCase);

    internal VaultProviderCatalog()
    {
    }

    /// <summary>Adiciona um provedor (uso pelos pacotes de provedor).</summary>
    /// <exception cref="InvalidOperationException">Já existe um provedor com o mesmo nome.</exception>
    public VaultProviderCatalog Add(VaultProviderRegistration provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (!_providers.TryAdd(provider.Name, provider))
            throw new InvalidOperationException($"O provedor '{provider.Name}' já foi adicionado.");
        return this;
    }

    /// <summary>Nomes dos provedores disponíveis.</summary>
    public IReadOnlyCollection<string> Names => _providers.Keys;

    internal bool TryGet(string name, out VaultProviderRegistration provider) => _providers.TryGetValue(name, out provider!);

    internal static VaultProviderCatalog Create(Action<VaultProviderCatalog> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var catalog = new VaultProviderCatalog();
        configure(catalog);
        if (catalog._providers.Count == 0)
            throw new InvalidOperationException("Nenhum provedor disponível. Ex.: providers.AddAzureKeyVault().");
        return catalog;
    }
}
