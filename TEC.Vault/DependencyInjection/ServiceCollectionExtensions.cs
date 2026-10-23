using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Caching;
using TEC.Vault.HealthChecks;
using TEC.Core.Common.Results;

namespace TEC.Vault.DependencyInjection;

/// <summary>Registro do cofre no container de injeção de dependência.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registra o cofre com o provedor escolhido. Cada interface que o provedor implementa é registrada apontando para a mesma
    /// instância (singleton, thread-safe):
    /// <list type="bullet">
    /// <item><description>Segredos: <see cref="ISecretReader"/>, <see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/>, <see cref="ISecretBackup"/>.</description></item>
    /// <item><description>Chaves: <see cref="IKeyReader"/>, <see cref="IKeyStore"/>, <see cref="IKeyCryptography"/>, <see cref="IKeyRecycleBin"/>, <see cref="IKeyBackup"/>.</description></item>
    /// <item><description>Certificados: <see cref="ICertificateReader"/>, <see cref="ICertificateStore"/>, <see cref="ICertificateRecycleBin"/>, <see cref="ICertificateBackup"/>.</description></item>
    /// <item><description><see cref="IVaultHealthProbe"/>.</description></item>
    /// </list>
    /// Interfaces que o provedor não implementa não são registradas (ex.: um provedor sem backup não registra <see cref="ISecretBackup"/>).
    /// </summary>
    /// <remarks>
    /// <para>Com <see cref="VaultBuilder.EnableSecretCache"/>, <see cref="ISecretReader"/> é o cache e <see cref="ISecretStore"/>,
    /// <see cref="ISecretRecycleBin"/> e <see cref="ISecretBackup"/> são decorators que limpam o cache após cada escrita.
    /// A classe concreta do provedor também fica registrada e <b>não</b> passa pelo cache: escritas feitas por ela não limpam
    /// o cache (grave sempre pelas interfaces).</para>
    /// <para><see cref="IVaultHealthProbe"/> é registrado em qualquer combinação de stores e verifica <b>cada</b> instância de provedor,
    /// com a permissão que ela exige (ex.: só chaves → lista chaves; não exige permissão de segredos). Provedores que implementam
    /// <see cref="IVaultHealthProbe"/> usam a própria sonda; os demais, a listagem de metadados do leitor. Um <see cref="IVaultHealthProbe"/>
    /// registrado antes pela aplicação é mantido. Sem nenhuma verificação possível (só <see cref="IKeyCryptography"/>, sem sonda
    /// própria) a sonda responde saudável e registra um aviso no log (evento 2010) na primeira verificação.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez, ou nenhum provedor configurado.</exception>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault => vault.UseAzureKeyVault(o =>
    /// {
    ///     o.VaultUri = new Uri("https://kv-minha-app.vault.azure.net/");
    ///     o.Authentication = builder.Environment.IsDevelopment()
    ///         ? AzureKeyVaultAuthentication.Developer
    ///         : AzureKeyVaultAuthentication.ManagedIdentity;
    /// }));
    /// </code>
    /// </example>
    public static IServiceCollection AddTecVault(this IServiceCollection services, Action<VaultBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        if (services.Any(d => d.ServiceType == typeof(VaultBuilder)))
            throw new InvalidOperationException("AddTecVault já foi chamado. Configure o cofre em uma única chamada.");

        var builder = new VaultBuilder(services);
        configure(builder);

        return Register(services, builder);
    }

    /// <summary>
    /// Registra o cofre escolhendo o provedor de cada família pela configuração. A aplicação informa em
    /// <paramref name="providers"/> quais provedores estão disponíveis; a seção <paramref name="configuration"/> escolhe qual usar
    /// (trocar de cofre não exige recompilar). O registro final é o mesmo de <see cref="AddTecVault(IServiceCollection, Action{VaultBuilder})"/>.
    /// </summary>
    /// <remarks>
    /// <para>Chaves da seção:</para>
    /// <list type="bullet">
    /// <item><description><c>Provider</c>: provedor padrão de todas as famílias. Famílias que ele não atende ficam sem provedor.</description></item>
    /// <item><description><c>Secrets:Provider</c>, <c>Keys:Provider</c>, <c>Certificates:Provider</c>: provedor da família (tem
    /// precedência). <c>None</c> desliga a família. Pedir uma família a um provedor que não a atende é erro.</description></item>
    /// <item><description><c>Cache:Duration</c>: ativa o cache de segredos (<see cref="VaultBuilder.EnableSecretCache"/>).</description></item>
    /// <item><description><c>&lt;NomeDoProvedor&gt;</c>: opções do provedor (ex.: <c>AzureKeyVault:VaultUri</c>).</description></item>
    /// <item><description><c>Configuration</c>: opções da fonte de <c>IConfiguration</c> (usadas só por
    /// <c>IConfigurationBuilder.AddTecVault</c>).</description></item>
    /// </list>
    /// <para>Falha fechada na inicialização: provedor desconhecido, valor inválido ou chave desconhecida (provável erro de
    /// digitação) lançam <see cref="InvalidOperationException"/>. A seção de um provedor disponível e não escolhido não é validada.</para>
    /// <para><paramref name="configure"/> roda depois da configuração (ex.: <c>EnableSecretCache</c> em código).</para>
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(builder.Configuration.GetSection("Vault"), providers => providers
    ///     .AddAzureKeyVault()
    ///     .AddSynced()
    ///     .AddInMemory());
    ///
    /// // appsettings.Production.json
    /// // "Vault": { "Provider": "AzureKeyVault", "AzureKeyVault": { "VaultUri": "https://kv-minha-app.vault.azure.net/" } }
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez, configuração inválida ou nenhuma família com provedor.</exception>
    public static IServiceCollection AddTecVault(this IServiceCollection services, IConfiguration configuration,
        Action<VaultProviderCatalog> providers, Action<VaultBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(providers);

        if (services.Any(d => d.ServiceType == typeof(VaultBuilder)))
            throw new InvalidOperationException("AddTecVault já foi chamado. Configure o cofre em uma única chamada.");

        var catalog = VaultProviderCatalog.Create(providers);
        var selection = VaultProviderSelection.Resolve(new VaultSettings(configuration), catalog);

        var builder = new VaultBuilder(services);
        selection.Apply(builder);

        if (selection.Root.GetSection(VaultProviderSelection.CacheKey).GetTimeSpan("Duration") is { } cache)
        {
            try
            {
                builder.EnableSecretCache(cache);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidOperationException($"Configuração inválida em {selection.Root.Path}:Cache:Duration: {exception.Message}".TrimStart(':'), exception);
            }
        }
        selection.Root.Ignore(VaultProviderSelection.ConfigurationKey);
        selection.Root.EnsureNoUnknownKeys();

        configure?.Invoke(builder);

        return Register(services, builder);
    }

    private static IServiceCollection Register(IServiceCollection services, VaultBuilder builder)
    {
        if (builder.Secrets is null && builder.Keys is null && builder.Certificates is null)
        {
            throw new InvalidOperationException(
                "Nenhum provedor de cofre configurado. Ex.: vault.UseAzureKeyVault(...) ou, por configuração, Vault:Provider.");
        }

        services.AddSingleton(builder);

        if (builder.Secrets is { } secrets)
        {
            if (builder.SecretCacheDuration is { } duration)
                AddCachedSecrets(services, secrets, duration);
            else
            {
                AddAs<ISecretReader>(services, secrets);
                AddAs<ISecretStore>(services, secrets);
                AddAs<ISecretRecycleBin>(services, secrets);
                AddAs<ISecretBackup>(services, secrets);
            }
        }

        if (builder.Keys is { } keys)
        {
            AddAs<IKeyReader>(services, keys);
            AddAs<IKeyStore>(services, keys);
            AddAs<IKeyCryptography>(services, keys);
            AddAs<IKeyRecycleBin>(services, keys);
            AddAs<IKeyBackup>(services, keys);
        }

        if (builder.Certificates is { } certificates)
        {
            AddAs<ICertificateReader>(services, certificates);
            AddAs<ICertificateStore>(services, certificates);
            AddAs<ICertificateRecycleBin>(services, certificates);
            AddAs<ICertificateBackup>(services, certificates);
        }

        services.TryAddSingleton<IVaultHealthProbe>(sp => new VaultHealthProbe(CreateHealthChecks(sp, builder),
            sp.GetService<ILoggerFactory>()?.CreateLogger<VaultHealthProbe>()));

        return services;
    }

    private static bool Implements<TService>(VaultBuilder.Registration registration) =>
        typeof(TService).IsAssignableFrom(registration.ImplementationType);

    /// <summary>Registra <typeparamref name="TService"/> apontando para a instância do provedor, se ele implementar a interface.</summary>
    private static void AddAs<TService>(IServiceCollection services, VaultBuilder.Registration registration) where TService : class
    {
        if (Implements<TService>(registration))
            services.AddSingleton(sp => (TService)registration.Resolve(sp));
    }

    private static void AddCachedSecrets(IServiceCollection services, VaultBuilder.Registration secrets, TimeSpan duration)
    {
        services.AddSingleton(sp => new CachingSecretReader((ISecretReader)secrets.Resolve(sp), duration));
        services.AddSingleton<ISecretReader>(sp => sp.GetRequiredService<CachingSecretReader>());

        if (Implements<ISecretStore>(secrets))
        {
            services.AddSingleton<ISecretStore>(sp =>
                new CacheInvalidatingSecretStore((ISecretStore)secrets.Resolve(sp), sp.GetRequiredService<CachingSecretReader>()));
        }

        if (Implements<ISecretRecycleBin>(secrets))
        {
            services.AddSingleton<ISecretRecycleBin>(sp =>
                new CacheInvalidatingSecretRecycleBin((ISecretRecycleBin)secrets.Resolve(sp), sp.GetRequiredService<CachingSecretReader>()));
        }

        if (Implements<ISecretBackup>(secrets))
        {
            services.AddSingleton<ISecretBackup>(sp =>
                new CacheInvalidatingSecretBackup((ISecretBackup)secrets.Resolve(sp), sp.GetRequiredService<CachingSecretReader>()));
        }
    }

    /// <summary>Uma verificação por instância de provedor (a mesma classe pode atender mais de uma família).</summary>
    private static List<Func<CancellationToken, Task<Result>>> CreateHealthChecks(IServiceProvider sp, VaultBuilder builder)
    {
        var checks = new List<Func<CancellationToken, Task<Result>>>();
        var seen = new HashSet<object>(ReferenceEqualityComparer.Instance);

        void Add(VaultBuilder.Registration? registration, Func<object, Func<CancellationToken, Task<Result>>?> fallback)
        {
            if (registration is null)
                return;

            var store = registration.Resolve(sp);
            if (!seen.Add(store))
                return;

            var check = store is IVaultHealthProbe probe ? probe.CheckAccessAsync : fallback(store);
            if (check is not null)
                checks.Add(check);
        }

        Add(builder.Secrets, store => store is ISecretReader reader
            ? async ct => ToResult(await reader.ListSecretsAsync(ct).ConfigureAwait(false))
            : null);
        Add(builder.Keys, store => store is IKeyReader reader
            ? async ct => ToResult(await reader.ListKeysAsync(ct).ConfigureAwait(false))
            : null);   // só IKeyCryptography e sem sonda própria: não há operação barata e sem efeito para verificar
        Add(builder.Certificates, store => store is ICertificateReader reader
            ? async ct => ToResult(await reader.ListCertificatesAsync(ct).ConfigureAwait(false))
            : null);

        return checks;
    }

    private static Result ToResult(Result result) => result.IsSuccess ? Result.Success() : result.ToFailure();
}
