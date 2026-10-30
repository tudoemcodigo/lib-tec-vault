using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Providers;

namespace TEC.Vault.AwsSecretsManager;

/// <summary>Registro do provedor AWS Secrets Manager (em código e por configuração).</summary>
public static class AwsSecretsManagerExtensions
{
    /// <summary>Usa o AWS Secrets Manager como provedor de segredos. As opções são validadas aqui.</summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseAwsSecretsManager(o => o.Region = "sa-east-1"));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas ou nenhuma fonte de credenciais.</exception>
    public static VaultBuilder UseAwsSecretsManager(this VaultBuilder builder, Action<AwsSecretsManagerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AwsSecretsManagerOptions();
        configure(options);
        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);
        options.Validate();

        return builder.UseSecretStore(sp => new AwsSecretsManagerSecretStore(options, sp.GetService<ILogger<AwsSecretsManagerSecretStore>>()));
    }

    /// <summary>
    /// Adiciona o AWS Secrets Manager aos provedores disponíveis para a configuração (<c>Vault:Provider = AwsSecretsManager</c>).
    /// Opções lidas de <c>Vault:AwsSecretsManager</c>: <c>Region</c>, <c>Endpoint</c>, <c>StsEndpoint</c>, <c>RoleArn</c>,
    /// <c>WebIdentityTokenFile</c>, <c>RoleSessionName</c>, <c>UseContainerCredentials</c>, <c>UseInstanceMetadata</c>,
    /// <c>AccessKeyId</c>, <c>AccessKeyIdVariable</c>, <c>SecretAccessKeyVariable</c>, <c>SessionTokenVariable</c>,
    /// <c>MaxListItems</c>, <c>MaxRetries</c>, <c>NetworkTimeout</c> e a subseção <c>CircuitBreaker</c>.
    /// </summary>
    /// <remarks>
    /// <c>SecretAccessKey</c> e <c>SessionToken</c> em texto são recusados: o segredo vem de variável de ambiente (ou de uma fonte
    /// sem segredo, como web identity, container ou IMDS). Chave desconhecida na seção derruba a inicialização.
    /// <paramref name="configure"/> roda depois da configuração (ex.: <c>Http.Handler</c> com proxy).
    /// </remarks>
    public static VaultProviderCatalog AddAwsSecretsManager(this VaultProviderCatalog catalog, Action<AwsSecretsManagerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        return catalog.Add(new VaultProviderRegistration(AwsSecretsManagerSecretStore.Provider, VaultStores.Secrets,
            (builder, settings, _) => builder.UseAwsSecretsManager(o =>
            {
                Read(settings, o);
                configure?.Invoke(o);
            }),
            (settings, loggerFactory) =>
            {
                var options = new AwsSecretsManagerOptions();
                Read(settings, options);
                configure?.Invoke(options);
                return new AwsSecretsManagerSecretStore(options, loggerFactory?.CreateLogger<AwsSecretsManagerSecretStore>());
            }));
    }

    private static void Read(VaultSettings settings, AwsSecretsManagerOptions options)
    {
        settings.RejectInlineSecret("SecretAccessKey", "SecretAccessKeyVariable");
        settings.RejectInlineSecret("SessionToken", "SessionTokenVariable");

        options.Region = settings.GetString("Region") ?? options.Region;
        options.Endpoint = settings.GetUri("Endpoint") ?? options.Endpoint;
        options.StsEndpoint = settings.GetUri("StsEndpoint") ?? options.StsEndpoint;
        options.RoleArn = settings.GetString("RoleArn") ?? options.RoleArn;
        options.WebIdentityTokenFile = settings.GetString("WebIdentityTokenFile") ?? options.WebIdentityTokenFile;
        options.RoleSessionName = settings.GetString("RoleSessionName") ?? options.RoleSessionName;
        options.UseContainerCredentials = settings.GetBoolean("UseContainerCredentials") ?? options.UseContainerCredentials;
        options.UseInstanceMetadata = settings.GetBoolean("UseInstanceMetadata") ?? options.UseInstanceMetadata;
        options.AccessKeyId = settings.GetString("AccessKeyId") ?? options.AccessKeyId;
        options.AccessKeyIdVariable = settings.GetString("AccessKeyIdVariable") ?? options.AccessKeyIdVariable;
        options.SecretAccessKeyVariable = settings.GetString("SecretAccessKeyVariable") ?? options.SecretAccessKeyVariable;
        options.SessionTokenVariable = settings.GetString("SessionTokenVariable") ?? options.SessionTokenVariable;
        options.MaxListItems = settings.GetInt32("MaxListItems", 1, 1_000_000) ?? options.MaxListItems;
        options.Http.MaxRetries = settings.GetInt32("MaxRetries", 0, 10) ?? options.Http.MaxRetries;
        options.Http.NetworkTimeout = settings.GetTimeSpan("NetworkTimeout") ?? options.Http.NetworkTimeout;
        options.Http.CircuitBreaker.Read(settings);
        settings.EnsureNoUnknownKeys();
    }
}
