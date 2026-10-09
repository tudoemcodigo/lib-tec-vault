using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Providers;

namespace TEC.Vault.Infisical;

/// <summary>Registro do provedor Infisical (em código e por configuração).</summary>
public static class InfisicalExtensions
{
    /// <summary>Usa o Infisical como provedor de segredos. As opções são validadas aqui.</summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseInfisical(o =>
    /// {
    ///     o.ProjectId = "6f1c...";
    ///     o.Environment = "prod";
    ///     o.Authentication = InfisicalAuthentication.Kubernetes;
    ///     o.IdentityId = "b2a4...";
    /// }));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public static VaultBuilder UseInfisical(this VaultBuilder builder, Action<InfisicalOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new InfisicalOptions();
        configure(options);
        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);
        options.Validate();

        return builder.UseSecretStore(sp => new InfisicalSecretStore(options, sp.GetService<ILogger<InfisicalSecretStore>>()));
    }

    /// <summary>
    /// Adiciona o Infisical aos provedores disponíveis para a configuração (<c>Vault:Provider = Infisical</c>). Opções lidas de
    /// <c>Vault:Infisical</c>: <c>SiteUrl</c>, <c>ProjectId</c>, <c>Environment</c>, <c>SecretPath</c>, <c>Authentication</c>
    /// (<c>UniversalAuth</c>, <c>Kubernetes</c>, <c>AccessToken</c>), <c>ClientId</c>, <c>ClientSecretFile</c>,
    /// <c>ClientSecretVariable</c>, <c>IdentityId</c>, <c>ServiceAccountTokenFile</c>, <c>OrganizationSlug</c>,
    /// <c>AccessTokenFile</c>, <c>AccessTokenVariable</c>, <c>ExpandSecretReferences</c>, <c>IncludeImports</c>,
    /// <c>MaxRetries</c>, <c>NetworkTimeout</c> e a subseção <c>CircuitBreaker</c>.
    /// </summary>
    /// <remarks>
    /// <c>ClientSecret</c> e <c>AccessToken</c> em texto são recusados: a credencial vem de arquivo ou variável de ambiente.
    /// <paramref name="configure"/> roda depois da configuração (ex.: <c>Http.Handler</c> com proxy).
    /// </remarks>
    public static VaultProviderCatalog AddInfisical(this VaultProviderCatalog catalog, Action<InfisicalOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        return catalog.Add(new VaultProviderRegistration(InfisicalSecretStore.Provider, VaultStores.Secrets,
            (builder, settings, _) => builder.UseInfisical(o =>
            {
                Read(settings, o);
                configure?.Invoke(o);
            }),
            (settings, loggerFactory) =>
            {
                var options = new InfisicalOptions();
                Read(settings, options);
                configure?.Invoke(options);
                return new InfisicalSecretStore(options, loggerFactory?.CreateLogger<InfisicalSecretStore>());
            }));
    }

    private static void Read(VaultSettings settings, InfisicalOptions options)
    {
        settings.RejectInlineSecret("ClientSecret", "ClientSecretFile", "ClientSecretVariable");
        settings.RejectInlineSecret("AccessToken", "AccessTokenFile", "AccessTokenVariable");

        options.SiteUrl = settings.GetUri("SiteUrl") ?? options.SiteUrl;
        options.ProjectId = settings.GetString("ProjectId") ?? options.ProjectId;
        options.Environment = settings.GetString("Environment") ?? options.Environment;
        options.SecretPath = settings.GetString("SecretPath") ?? options.SecretPath;
        options.Authentication = settings.GetEnum<InfisicalAuthentication>("Authentication") ?? options.Authentication;
        options.ClientId = settings.GetString("ClientId") ?? options.ClientId;
        options.ClientSecretFile = settings.GetString("ClientSecretFile") ?? options.ClientSecretFile;
        options.ClientSecretVariable = settings.GetString("ClientSecretVariable") ?? options.ClientSecretVariable;
        options.IdentityId = settings.GetString("IdentityId") ?? options.IdentityId;
        options.ServiceAccountTokenFile = settings.GetString("ServiceAccountTokenFile") ?? options.ServiceAccountTokenFile;
        options.OrganizationSlug = settings.GetString("OrganizationSlug") ?? options.OrganizationSlug;
        options.AccessTokenFile = settings.GetString("AccessTokenFile") ?? options.AccessTokenFile;
        options.AccessTokenVariable = settings.GetString("AccessTokenVariable") ?? options.AccessTokenVariable;
        options.ExpandSecretReferences = settings.GetBoolean("ExpandSecretReferences") ?? options.ExpandSecretReferences;
        options.IncludeImports = settings.GetBoolean("IncludeImports") ?? options.IncludeImports;
        options.Http.MaxRetries = settings.GetInt32("MaxRetries", 0, 10) ?? options.Http.MaxRetries;
        options.Http.NetworkTimeout = settings.GetTimeSpan("NetworkTimeout") ?? options.Http.NetworkTimeout;
        options.Http.CircuitBreaker.Read(settings);
        settings.EnsureNoUnknownKeys();
    }
}
