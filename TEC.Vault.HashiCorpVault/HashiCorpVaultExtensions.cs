using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HashiCorpVault.Internal;
using TEC.Vault.Providers;

namespace TEC.Vault.HashiCorpVault;

/// <summary>Registro do provedor HashiCorp Vault (em código e por configuração).</summary>
public static class HashiCorpVaultExtensions
{
    /// <summary>Nome do provedor na configuração.</summary>
    public const string ProviderName = HashiCorpVaultStoreBase.Provider;

    /// <summary>
    /// Usa o HashiCorp Vault como provedor de segredos (KV v2), chaves (Transit) e certificados (KV + PKI), conforme
    /// <see cref="HashiCorpVaultOptions.Stores"/>. Os stores compartilham o mesmo login e token. As opções são validadas aqui.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseHashiCorpVault(o =>
    /// {
    ///     o.Address = new Uri("https://vault.interno:8200");
    ///     o.Auth.Method = HashiCorpVaultAuthMethod.Kubernetes;
    ///     o.Auth.Role = "minha-api";
    ///     o.Kv.BasePath = "minha-api";
    /// }));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public static VaultBuilder UseHashiCorpVault(this VaultBuilder builder, Action<HashiCorpVaultOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new HashiCorpVaultOptions();
        configure(options);
        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);
        VaultBuilder.EnsureValidStores(options.Stores, "HashiCorpVaultOptions.Stores");

        var client = new HashiCorpVaultClient(options);   // valida as opções
        builder.Services.AddSingleton(_ => new ClientOwner(client));   // o container descarta a conexão compartilhada

        return builder.UseStores(options.Stores,
            sp => Owned(sp, new HashiCorpVaultSecretStore(client, ownsClient: false, sp.GetService<ILogger<HashiCorpVaultSecretStore>>())),
            sp => Owned(sp, new HashiCorpVaultKeyStore(client, ownsClient: false, sp.GetService<ILogger<HashiCorpVaultKeyStore>>())),
            sp => Owned(sp, new HashiCorpVaultCertificateStore(client, ownsClient: false, sp.GetService<ILogger<HashiCorpVaultCertificateStore>>())));
    }

    /// <summary>
    /// Adiciona o HashiCorp Vault aos provedores disponíveis para a configuração (<c>Vault:Provider = HashiCorpVault</c>).
    /// Opções lidas de <c>Vault:HashiCorpVault</c>:
    /// <list type="bullet">
    /// <item><description><c>Address</c> (obrigatório), <c>Namespace</c>, <c>MaxRetries</c>, <c>NetworkTimeout</c>, <c>MaxListItems</c>.</description></item>
    /// <item><description><c>Auth</c>: <c>Method</c> (<c>Kubernetes</c>, <c>Jwt</c>, <c>AppRole</c>, <c>Token</c>), <c>Mount</c>, <c>Role</c>,
    /// <c>RoleId</c>, <c>ServiceAccountTokenFile</c>, <c>JwtFile</c>, <c>JwtVariable</c>, <c>SecretIdFile</c>, <c>SecretIdVariable</c>,
    /// <c>TokenFile</c>, <c>TokenVariable</c>.</description></item>
    /// <item><description><c>Kv</c>: <c>Mount</c>, <c>BasePath</c>, <c>ValueField</c>, <c>CertificatesPath</c>.</description></item>
    /// <item><description><c>Transit</c>: <c>Mount</c>. <c>Pki</c>: <c>Mount</c>, <c>Role</c>.</description></item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// <c>Auth:Token</c>, <c>Auth:SecretId</c> e <c>Auth:Jwt</c> em texto são recusados: a credencial vem de arquivo ou variável.
    /// <paramref name="configure"/> roda depois da configuração (ex.: <c>Http.Handler</c> com a CA interna).
    /// </remarks>
    public static VaultProviderCatalog AddHashiCorpVault(this VaultProviderCatalog catalog, Action<HashiCorpVaultOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        return catalog.Add(new VaultProviderRegistration(ProviderName, VaultStores.All,
            (builder, settings, stores) => builder.UseHashiCorpVault(o =>
            {
                Read(settings, o);
                configure?.Invoke(o);
                o.Stores = stores;
            }),
            (settings, loggerFactory) =>
            {
                var options = new HashiCorpVaultOptions();
                Read(settings, options);
                configure?.Invoke(options);
                return new HashiCorpVaultSecretStore(options, loggerFactory?.CreateLogger<HashiCorpVaultSecretStore>());
            }));
    }

    private static T Owned<T>(IServiceProvider sp, T store)
    {
        _ = sp.GetRequiredService<ClientOwner>();   // garante o descarte da conexão junto com o container
        return store;
    }

    private static void Read(VaultSettings settings, HashiCorpVaultOptions options)
    {
        options.Address = settings.GetUri("Address") ?? options.Address;
        options.Namespace = settings.GetString("Namespace") ?? options.Namespace;
        options.Http.MaxRetries = settings.GetInt32("MaxRetries", 0, 10) ?? options.Http.MaxRetries;
        options.Http.NetworkTimeout = settings.GetTimeSpan("NetworkTimeout") ?? options.Http.NetworkTimeout;
        options.MaxListItems = settings.GetInt32("MaxListItems", 1, 1_000_000) ?? options.MaxListItems;

        var auth = settings.GetSection("Auth");
        auth.RejectInlineSecret("Token", "TokenFile", "TokenVariable");
        auth.RejectInlineSecret("SecretId", "SecretIdFile", "SecretIdVariable");
        auth.RejectInlineSecret("Jwt", "JwtFile", "JwtVariable");
        options.Auth.Method = auth.GetEnum<HashiCorpVaultAuthMethod>("Method") ?? options.Auth.Method;
        options.Auth.Mount = auth.GetString("Mount") ?? options.Auth.Mount;
        options.Auth.Role = auth.GetString("Role") ?? options.Auth.Role;
        options.Auth.RoleId = auth.GetString("RoleId") ?? options.Auth.RoleId;
        options.Auth.ServiceAccountTokenFile = auth.GetString("ServiceAccountTokenFile") ?? options.Auth.ServiceAccountTokenFile;
        options.Auth.JwtFile = auth.GetString("JwtFile") ?? options.Auth.JwtFile;
        options.Auth.JwtVariable = auth.GetString("JwtVariable") ?? options.Auth.JwtVariable;
        options.Auth.SecretIdFile = auth.GetString("SecretIdFile") ?? options.Auth.SecretIdFile;
        options.Auth.SecretIdVariable = auth.GetString("SecretIdVariable") ?? options.Auth.SecretIdVariable;
        options.Auth.TokenFile = auth.GetString("TokenFile") ?? options.Auth.TokenFile;
        options.Auth.TokenVariable = auth.GetString("TokenVariable") ?? options.Auth.TokenVariable;

        var kv = settings.GetSection("Kv");
        options.Kv.Mount = kv.GetString("Mount") ?? options.Kv.Mount;
        options.Kv.BasePath = kv.GetString("BasePath") ?? options.Kv.BasePath;
        options.Kv.ValueField = kv.GetString("ValueField") ?? options.Kv.ValueField;
        options.Kv.CertificatesPath = kv.GetString("CertificatesPath") ?? options.Kv.CertificatesPath;

        options.Transit.Mount = settings.GetSection("Transit").GetString("Mount") ?? options.Transit.Mount;

        var pki = settings.GetSection("Pki");
        options.Pki.Mount = pki.GetString("Mount") ?? options.Pki.Mount;
        options.Pki.Role = pki.GetString("Role") ?? options.Pki.Role;

        settings.EnsureNoUnknownKeys();
    }

    /// <summary>Dono da conexão compartilhada no container (descartada com ele).</summary>
    private sealed class ClientOwner(HashiCorpVaultClient client) : IDisposable
    {
        public void Dispose() => client.Dispose();
    }
}
