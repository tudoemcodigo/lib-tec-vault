using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;

namespace TEC.Vault.AwsSecretsManager;

/// <summary>Métodos de extensão para registro do provedor AWS Secrets Manager.</summary>
public static class AwsSecretsManagerExtensions
{
    /// <summary>
    /// Configura o uso do AWS Secrets Manager para a gestão de segredos.
    /// </summary>
    public static VaultBuilder UseAwsSecretsManager(this VaultBuilder builder, Action<AwsSecretsManagerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AwsSecretsManagerOptions();
        configure(options);

        return builder.UseSecretStore(sp => new AwsSecretsManagerSecretStore(options, sp.GetService<ILogger<AwsSecretsManagerSecretStore>>()));
    }

    /// <summary>
    /// Registra o provedor AWS Secrets Manager no catálogo para seleção via appsettings.json (<c>"Vault:Provider": "AwsSecretsManager"</c>).
    /// </summary>
    public static VaultProviderCatalog AddAwsSecretsManager(this VaultProviderCatalog catalog)
    {
        ArgumentNullException.ThrowIfNull(catalog);

        return catalog.Add(new VaultProviderRegistration(
            AwsSecretsManagerSecretStore.Provider,
            VaultStores.Secrets,
            (builder, settings, _) => builder.UseAwsSecretsManager(options =>
            {
                if (settings.GetString("Region") is { } region)
                    options.Region = region;
                if (settings.GetString("Endpoint") is { } endpoint)
                    options.Endpoint = new Uri(endpoint);
                if (settings.GetString("AccessKeyId") is { } accessKeyId)
                    options.AccessKeyId = accessKeyId;
                if (settings.GetString("SecretAccessKey") is { } secretAccessKey)
                    options.SecretAccessKey = secretAccessKey;
                if (settings.GetString("SessionToken") is { } sessionToken)
                    options.SessionToken = sessionToken;
                if (settings.GetInt32("MaxListItems") is { } maxList)
                    options.MaxListItems = maxList;
            }),
            createSecretReader: (settings, loggerFactory) =>
            {
                var options = new AwsSecretsManagerOptions();
                if (settings.GetString("Region") is { } region)
                    options.Region = region;
                if (settings.GetString("Endpoint") is { } endpoint)
                    options.Endpoint = new Uri(endpoint);
                if (settings.GetString("AccessKeyId") is { } accessKeyId)
                    options.AccessKeyId = accessKeyId;
                if (settings.GetString("SecretAccessKey") is { } secretAccessKey)
                    options.SecretAccessKey = secretAccessKey;
                if (settings.GetString("SessionToken") is { } sessionToken)
                    options.SessionToken = sessionToken;

                return new AwsSecretsManagerSecretStore(options, loggerFactory?.CreateLogger<AwsSecretsManagerSecretStore>());
            }
        ));
    }
}
