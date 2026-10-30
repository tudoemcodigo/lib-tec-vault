using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Providers;

namespace TEC.Vault.GoogleSecretManager;

/// <summary>Registro do provedor Google Cloud Secret Manager (em código e por configuração).</summary>
public static class GoogleSecretManagerExtensions
{
    /// <summary>Usa o Google Cloud Secret Manager como provedor de segredos. As opções são validadas aqui.</summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseGoogleSecretManager(o => o.ProjectId = "meu-projeto-prod"));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas ou nenhuma credencial.</exception>
    public static VaultBuilder UseGoogleSecretManager(this VaultBuilder builder, Action<GoogleSecretManagerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new GoogleSecretManagerOptions();
        configure(options);
        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);
        options.Validate();

        return builder.UseSecretStore(sp => new GoogleSecretManagerSecretStore(options, sp.GetService<ILogger<GoogleSecretManagerSecretStore>>()));
    }

    /// <summary>
    /// Adiciona o Google Cloud Secret Manager aos provedores disponíveis para a configuração
    /// (<c>Vault:Provider = GoogleSecretManager</c>). Opções lidas de <c>Vault:GoogleSecretManager</c>: <c>ProjectId</c>,
    /// <c>Endpoint</c>, <c>AccessTokenVariable</c>, <c>CredentialsJsonFile</c>, <c>CredentialsJsonVariable</c>,
    /// <c>UseMetadataServer</c>, <c>MaxListItems</c>, <c>MaxRetries</c>, <c>NetworkTimeout</c> e a subseção <c>CircuitBreaker</c>.
    /// </summary>
    /// <remarks>
    /// <c>AccessToken</c> em texto é recusado: o token vem de variável de ambiente (ou de uma fonte sem segredo na configuração,
    /// como Service Account em arquivo montado ou Metadata Server). Chave desconhecida na seção derruba a inicialização.
    /// <paramref name="configure"/> roda depois da configuração (ex.: <c>Http.Handler</c> ou <c>AllowedTokenHosts</c>).
    /// </remarks>
    public static VaultProviderCatalog AddGoogleSecretManager(this VaultProviderCatalog catalog, Action<GoogleSecretManagerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        return catalog.Add(new VaultProviderRegistration(GoogleSecretManagerSecretStore.Provider, VaultStores.Secrets,
            (builder, settings, _) => builder.UseGoogleSecretManager(o =>
            {
                Read(settings, o);
                configure?.Invoke(o);
            }),
            (settings, loggerFactory) =>
            {
                var options = new GoogleSecretManagerOptions();
                Read(settings, options);
                configure?.Invoke(options);
                return new GoogleSecretManagerSecretStore(options, loggerFactory?.CreateLogger<GoogleSecretManagerSecretStore>());
            }));
    }

    private static void Read(VaultSettings settings, GoogleSecretManagerOptions options)
    {
        settings.RejectInlineSecret("AccessToken", "AccessTokenVariable", "CredentialsJsonFile");

        options.ProjectId = settings.GetString("ProjectId") ?? options.ProjectId;
        options.Endpoint = settings.GetUri("Endpoint") ?? options.Endpoint;
        options.AccessTokenVariable = settings.GetString("AccessTokenVariable") ?? options.AccessTokenVariable;
        options.CredentialsJsonFile = settings.GetString("CredentialsJsonFile") ?? options.CredentialsJsonFile;
        options.CredentialsJsonVariable = settings.GetString("CredentialsJsonVariable") ?? options.CredentialsJsonVariable;
        options.UseMetadataServer = settings.GetBoolean("UseMetadataServer") ?? options.UseMetadataServer;
        options.MaxListItems = settings.GetInt32("MaxListItems", 1, 1_000_000) ?? options.MaxListItems;
        options.Http.MaxRetries = settings.GetInt32("MaxRetries", 0, 10) ?? options.Http.MaxRetries;
        options.Http.NetworkTimeout = settings.GetTimeSpan("NetworkTimeout") ?? options.Http.NetworkTimeout;
        options.Http.CircuitBreaker.Read(settings);
        settings.EnsureNoUnknownKeys();
    }
}
