using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;

namespace TEC.Vault.GoogleSecretManager;

/// <summary>Métodos de extensão para registro do provedor Google Cloud Secret Manager.</summary>
public static class GoogleSecretManagerExtensions
{
    /// <summary>
    /// Configura o uso do Google Cloud Secret Manager para a gestão de segredos.
    /// </summary>
    public static VaultBuilder UseGoogleSecretManager(this VaultBuilder builder, Action<GoogleSecretManagerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new GoogleSecretManagerOptions();
        configure(options);

        return builder.UseSecretStore(sp => new GoogleSecretManagerSecretStore(options, sp.GetService<ILogger<GoogleSecretManagerSecretStore>>()));
    }

    /// <summary>
    /// Registra o provedor Google Cloud Secret Manager no catálogo para seleção via appsettings.json (<c>"Vault:Provider": "GoogleSecretManager"</c>).
    /// </summary>
    public static VaultProviderCatalog AddGoogleSecretManager(this VaultProviderCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        return catalog.Add(new VaultProviderRegistration(
            GoogleSecretManagerSecretStore.Provider,
            VaultStores.Secrets,
            (builder, settings, _) => builder.UseGoogleSecretManager(options =>
            {
                if (settings.GetString("ProjectId") is { } projectId)
                    options.ProjectId = projectId;
                if (settings.GetString("Endpoint") is { } endpoint)
                    options.Endpoint = new Uri(endpoint);
                if (settings.GetString("AccessToken") is { } token)
                    options.AccessToken = token;
                if (settings.GetString("CredentialsJsonFile") is { } file)
                    options.CredentialsJsonFile = file;
                if (settings.GetInt32("MaxListItems") is { } maxList)
                    options.MaxListItems = maxList;
            }),
            createSecretReader: (settings, loggerFactory) =>
            {
                var options = new GoogleSecretManagerOptions();
                if (settings.GetString("ProjectId") is { } projectId)
                    options.ProjectId = projectId;
                if (settings.GetString("Endpoint") is { } endpoint)
                    options.Endpoint = new Uri(endpoint);
                if (settings.GetString("AccessToken") is { } token)
                    options.AccessToken = token;
                if (settings.GetString("CredentialsJsonFile") is { } file)
                    options.CredentialsJsonFile = file;

                return new GoogleSecretManagerSecretStore(options, loggerFactory?.CreateLogger<GoogleSecretManagerSecretStore>());
            }
        ));
    }
}
