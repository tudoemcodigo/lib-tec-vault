using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault.Internal;
using TEC.Vault.Configuration;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Providers;

namespace TEC.Vault.AzureKeyVault;

/// <summary>Registro do provedor Azure Key Vault.</summary>
public static class AzureKeyVaultExtensions
{
    /// <summary>
    /// Usa o Azure Key Vault como provedor de segredos, chaves e certificados (os escolhidos em
    /// <see cref="AzureKeyVaultOptions.Stores"/>; padrão: todos). As opções são validadas aqui
    /// (falha na inicialização, não na primeira requisição).
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseAzureKeyVault(o =>
    /// {
    ///     o.VaultUri = new Uri(builder.Configuration["Cofre:VaultUri"]!);
    ///     o.Authentication = builder.Environment.IsDevelopment()
    ///         ? AzureKeyVaultAuthentication.Developer
    ///         : AzureKeyVaultAuthentication.ManagedIdentity;
    /// }));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas (ex.: endereço fora do domínio do Key Vault).</exception>
    public static VaultBuilder UseAzureKeyVault(this VaultBuilder builder, Action<AzureKeyVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AzureKeyVaultOptions();
        configure(options);

        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);

        var clients = new AzureKeyVaultClients(options);   // valida as opções, inclusive Stores

        return builder.UseStores(options.Stores,
            sp => new AzureKeyVaultSecretStore(clients, sp.GetService<ILogger<AzureKeyVaultSecretStore>>()),
            sp => new AzureKeyVaultKeyStore(clients, sp.GetService<ILogger<AzureKeyVaultKeyStore>>()),
            sp => new AzureKeyVaultCertificateStore(clients, sp.GetService<ILogger<AzureKeyVaultCertificateStore>>()));
    }

    /// <summary>
    /// Adiciona os segredos do Azure Key Vault à configuração. Veja <see cref="VaultConfigurationBuilderExtensions.AddTecVault"/>.
    /// </summary>
    /// <remarks>
    /// <paramref name="loggerFactory"/> é usado pelo store (auditoria) e pelo provedor de configuração (falhas de carga e
    /// recarga, tempo limite e estouro de <see cref="VaultConfigurationOptions.MaxSecrets"/>). Recomendado informar.
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Configuration.AddTecVaultAzureKeyVault(
    ///     o => o.VaultUri = new Uri("https://kv-minha-app.vault.azure.net/"),
    ///     c => c.Prefix = "MinhaApi--",
    ///     LoggerFactory.Create(l => l.AddConsole()));
    /// </code>
    /// </example>
    public static IConfigurationBuilder AddTecVaultAzureKeyVault(this IConfigurationBuilder builder, Action<AzureKeyVaultOptions> configure,
        Action<VaultConfigurationOptions>? configureConfiguration = null, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddTecVault(AzureKeyVaultStores.CreateSecretStore(configure, loggerFactory), configureConfiguration,
            loggerFactory: loggerFactory);
    }
}

/// <summary>Criação direta dos stores, sem injeção de dependência (ex.: ferramentas de linha de comando, configuração).</summary>
public static class AzureKeyVaultStores
{
    /// <summary>Cria o cofre de segredos (implementa <see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/>, <see cref="ISecretBackup"/> e <see cref="IVaultHealthProbe"/>).</summary>
    public static AzureKeyVaultSecretStore CreateSecretStore(Action<AzureKeyVaultOptions> configure, ILoggerFactory? loggerFactory = null) =>
        new(CreateClients(configure), loggerFactory?.CreateLogger<AzureKeyVaultSecretStore>());

    /// <summary>Cria o cofre de chaves (implementa <see cref="IKeyStore"/>, <see cref="IKeyCryptography"/>, <see cref="IKeyRecycleBin"/>, <see cref="IKeyBackup"/> e <see cref="IVaultHealthProbe"/>).</summary>
    public static AzureKeyVaultKeyStore CreateKeyStore(Action<AzureKeyVaultOptions> configure, ILoggerFactory? loggerFactory = null) =>
        new(CreateClients(configure), loggerFactory?.CreateLogger<AzureKeyVaultKeyStore>());

    /// <summary>Cria o cofre de certificados (implementa <see cref="ICertificateStore"/>, <see cref="ICertificateRecycleBin"/>, <see cref="ICertificateBackup"/> e <see cref="IVaultHealthProbe"/>).</summary>
    public static AzureKeyVaultCertificateStore CreateCertificateStore(Action<AzureKeyVaultOptions> configure, ILoggerFactory? loggerFactory = null) =>
        new(CreateClients(configure), loggerFactory?.CreateLogger<AzureKeyVaultCertificateStore>());

    private static AzureKeyVaultClients CreateClients(Action<AzureKeyVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var options = new AzureKeyVaultOptions();
        configure(options);
        return new AzureKeyVaultClients(options);
    }
}

/// <summary>Disponibiliza o Azure Key Vault para a escolha por configuração (<c>Vault:Provider = AzureKeyVault</c>).</summary>
public static class AzureKeyVaultCatalogExtensions
{
    /// <summary>Nome do provedor na configuração.</summary>
    public const string ProviderName = "AzureKeyVault";

    /// <summary>
    /// Adiciona o Azure Key Vault aos provedores disponíveis. Opções lidas de <c>Vault:AzureKeyVault</c>: <c>VaultUri</c>
    /// (obrigatório), <c>Authentication</c> (<c>ManagedIdentity</c>, <c>WorkloadIdentity</c>, <c>Developer</c>),
    /// <c>ManagedIdentityClientId</c>, <c>TenantId</c>, <c>MaxRetries</c>, <c>MaxListItems</c>, <c>NetworkTimeout</c>, <c>OperationTimeout</c> e
    /// <c>CryptographyClientLifetime</c>, além da subseção <c>CircuitBreaker</c> (<c>Enabled</c>, <c>FailureRatio</c>,
    /// <c>MinimumThroughput</c>, <c>SamplingDuration</c>, <c>BreakDuration</c>). As famílias vêm da escolha (<c>Vault:Provider</c> e overrides), não de <c>Stores</c>.
    /// </summary>
    /// <remarks>
    /// <paramref name="configure"/> roda depois da leitura da configuração, para o que só existe em código: <c>Credential</c>,
    /// <c>HostEnvironment</c> e <c>AllowDeveloperCredentialsOutsideDevelopment</c> (de propósito fora da configuração: liberar
    /// credencial de desenvolvedor fora de Development tem de ser decisão em código).
    /// </remarks>
    public static VaultProviderCatalog AddAzureKeyVault(this VaultProviderCatalog catalog, Action<AzureKeyVaultOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        return catalog.Add(new VaultProviderRegistration(ProviderName, VaultStores.All,
            (builder, settings, stores) => builder.UseAzureKeyVault(o =>
            {
                Read(settings, o);
                configure?.Invoke(o);
                o.Stores = stores;
            }),
            (settings, loggerFactory) => AzureKeyVaultStores.CreateSecretStore(o =>
            {
                Read(settings, o);
                configure?.Invoke(o);
            }, loggerFactory)));
    }

    private static void Read(VaultSettings settings, AzureKeyVaultOptions options)
    {
        settings.RejectKey("AllowDeveloperCredentialsOutsideDevelopment",
            "só pode ser definido em código (AzureKeyVaultOptions.AllowDeveloperCredentialsOutsideDevelopment).");
        options.VaultUri = settings.GetUri("VaultUri") ?? options.VaultUri;
        options.Authentication = settings.GetEnum<AzureKeyVaultAuthentication>("Authentication") ?? options.Authentication;
        options.ManagedIdentityClientId = settings.GetString("ManagedIdentityClientId") ?? options.ManagedIdentityClientId;
        options.TenantId = settings.GetString("TenantId") ?? options.TenantId;
        options.MaxRetries = settings.GetInt32("MaxRetries", 0, 10) ?? options.MaxRetries;
        options.MaxListItems = settings.GetInt32("MaxListItems", 1, 1_000_000) ?? options.MaxListItems;
        options.NetworkTimeout = settings.GetTimeSpan("NetworkTimeout") ?? options.NetworkTimeout;
        options.OperationTimeout = settings.GetTimeSpan("OperationTimeout") ?? options.OperationTimeout;
        options.CryptographyClientLifetime = settings.GetTimeSpan("CryptographyClientLifetime") ?? options.CryptographyClientLifetime;
        options.CircuitBreaker.Read(settings);
        settings.EnsureNoUnknownKeys();
    }
}
