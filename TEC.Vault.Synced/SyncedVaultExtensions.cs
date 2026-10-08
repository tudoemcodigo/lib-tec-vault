using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;

namespace TEC.Vault.Synced;

/// <summary>Registro dos leitores de segredos sincronizados (em código e por configuração).</summary>
public static class SyncedVaultExtensions
{
    /// <summary>Usa como provedor de segredos os arquivos de uma pasta (um por segredo). Veja <see cref="DirectorySecretStore"/>.</summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseDirectory(o => o.Path = "/mnt/secrets"));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public static VaultBuilder UseDirectory(this VaultBuilder builder, Action<DirectorySecretsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);
        var options = new DirectorySecretsOptions();
        configure(options);
        options.Validate();
        return builder.UseSecretStore(sp => new DirectorySecretStore(options, sp.GetService<ILogger<DirectorySecretStore>>()));
    }

    /// <summary>Usa como provedor de segredos as variáveis de ambiente com prefixo. Veja <see cref="EnvironmentSecretStore"/>.</summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseEnvironmentVariables(o => o.Prefix = "TECVAULT_"));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas (ex.: sem prefixo).</exception>
    public static VaultBuilder UseEnvironmentVariables(this VaultBuilder builder, Action<EnvironmentSecretsOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);
        var options = new EnvironmentSecretsOptions();
        configure(options);
        options.Validate();
        return builder.UseSecretStore(sp => new EnvironmentSecretStore(options, sp.GetService<ILogger<EnvironmentSecretStore>>()));
    }

    /// <summary>Usa como provedor de segredos um arquivo JSON ou .env. Veja <see cref="FileSecretStore"/>.</summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseSecretsFile(o => o.Path = "/vault/secrets/app.json"));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public static VaultBuilder UseSecretsFile(this VaultBuilder builder, Action<SecretsFileOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);
        var options = new SecretsFileOptions();
        configure(options);
        options.Validate();
        return builder.UseSecretStore(sp => new FileSecretStore(options, sp.GetService<ILogger<FileSecretStore>>()));
    }

    /// <summary>
    /// Adiciona os três leitores sincronizados aos provedores disponíveis para a configuração:
    /// <list type="bullet">
    /// <item><description><c>Directory</c>: <c>Vault:Directory</c> com <c>Path</c>, <c>MaxFileBytes</c>, <c>MaxItems</c>, <c>TrimTrailingNewline</c>.</description></item>
    /// <item><description><c>EnvironmentVariables</c>: <c>Vault:EnvironmentVariables</c> com <c>Prefix</c>, <c>MaxItems</c>, <c>MaxValueBytes</c>.</description></item>
    /// <item><description><c>SecretsFile</c>: <c>Vault:SecretsFile</c> com <c>Path</c>, <c>Format</c> (<c>Auto</c>, <c>Json</c>, <c>DotEnv</c>), <c>MaxFileBytes</c>, <c>MaxItems</c>.</description></item>
    /// </list>
    /// Todos atendem só segredos (só leitura) e podem ser fonte de <c>IConfiguration</c>.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), p => p.AddSynced().AddAzureKeyVault());
    /// // "Vault": { "Secrets": { "Provider": "Directory" }, "Keys": { "Provider": "AzureKeyVault" }, "Directory": { "Path": "/mnt/secrets" }, ... }
    /// </code>
    /// </example>
    public static VaultProviderCatalog AddSynced(this VaultProviderCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        return catalog
            .Add(new VaultProviderRegistration(DirectorySecretStore.Provider, VaultStores.Secrets,
                (builder, settings, _) => builder.UseDirectory(o => ReadDirectory(settings, o)),
                (settings, loggerFactory) => new DirectorySecretStore(Configure<DirectorySecretsOptions>(o => ReadDirectory(settings, o)),
                    loggerFactory?.CreateLogger<DirectorySecretStore>())))
            .Add(new VaultProviderRegistration(EnvironmentSecretStore.Provider, VaultStores.Secrets,
                (builder, settings, _) => builder.UseEnvironmentVariables(o => ReadEnvironment(settings, o)),
                (settings, loggerFactory) => new EnvironmentSecretStore(Configure<EnvironmentSecretsOptions>(o => ReadEnvironment(settings, o)),
                    loggerFactory?.CreateLogger<EnvironmentSecretStore>())))
            .Add(new VaultProviderRegistration(FileSecretStore.Provider, VaultStores.Secrets,
                (builder, settings, _) => builder.UseSecretsFile(o => ReadFile(settings, o)),
                (settings, loggerFactory) => new FileSecretStore(Configure<SecretsFileOptions>(o => ReadFile(settings, o)),
                    loggerFactory?.CreateLogger<FileSecretStore>())));
    }

    private static T Configure<T>(Action<T> configure) where T : new()
    {
        var options = new T();
        configure(options);
        return options;
    }

    private static void ReadDirectory(VaultSettings settings, DirectorySecretsOptions options)
    {
        options.Path = settings.GetString("Path");
        options.MaxFileBytes = settings.GetInt32("MaxFileBytes", 1, SyncedSecretStoreBase.MaxValueBytesLimit) ?? options.MaxFileBytes;
        options.MaxItems = settings.GetInt32("MaxItems", 1, 10_000) ?? options.MaxItems;
        options.TrimTrailingNewline = settings.GetBoolean("TrimTrailingNewline") ?? options.TrimTrailingNewline;
        settings.EnsureNoUnknownKeys();
    }

    private static void ReadEnvironment(VaultSettings settings, EnvironmentSecretsOptions options)
    {
        options.Prefix = settings.GetString("Prefix");
        options.MaxItems = settings.GetInt32("MaxItems", 1, 10_000) ?? options.MaxItems;
        options.MaxValueBytes = settings.GetInt32("MaxValueBytes", 1, SyncedSecretStoreBase.MaxValueBytesLimit) ?? options.MaxValueBytes;
        settings.EnsureNoUnknownKeys();
    }

    private static void ReadFile(VaultSettings settings, SecretsFileOptions options)
    {
        options.Path = settings.GetString("Path");
        options.Format = settings.GetEnum<SecretsFileFormat>("Format") ?? options.Format;
        options.MaxFileBytes = settings.GetInt32("MaxFileBytes", 1, 16 * 1024 * 1024) ?? options.MaxFileBytes;
        options.MaxItems = settings.GetInt32("MaxItems", 1, 10_000) ?? options.MaxItems;
        settings.EnsureNoUnknownKeys();
    }
}
