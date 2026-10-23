using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Providers;

namespace TEC.Vault.InMemory;

/// <summary>Registro do provedor em memória.</summary>
public static class InMemoryVaultExtensions
{
    /// <summary>
    /// Usa o provedor em memória (segredos, chaves e certificados, conforme <see cref="InMemoryVaultOptions.Stores"/>).
    /// <b>Somente desenvolvimento local e testes</b>: fora do ambiente Development a inicialização falha, a menos que
    /// <see cref="InMemoryVaultOptions.AllowOutsideDevelopment"/> seja <c>true</c>. O conteúdo some quando o processo termina.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddTecVault(vault =>
    /// {
    ///     if (builder.Environment.IsDevelopment())
    ///         vault.UseInMemory(o => o.InitialSecrets["db-senha"] = "senha-local");
    ///     else
    ///         vault.UseAzureKeyVault(o => o.VaultUri = new Uri(builder.Configuration["Cofre:VaultUri"]!));
    /// });
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Ambiente diferente de Development sem <see cref="InMemoryVaultOptions.AllowOutsideDevelopment"/>.</exception>
    public static VaultBuilder UseInMemory(this VaultBuilder builder, Action<InMemoryVaultOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = new InMemoryVaultOptions();
        configure?.Invoke(options);

        options.HostEnvironment ??= VaultEnvironment.FindHostEnvironment(builder.Services);

        InMemoryEnvironment.EnsureAllowed(options);
        VaultBuilder.EnsureValidStores(options.Stores, "InMemoryVaultOptions.Stores");

        return builder.UseStores(options.Stores,
            sp => new InMemorySecretStore(options, sp.GetService<ILogger<InMemorySecretStore>>()),
            sp => new InMemoryKeyStore(options, sp.GetService<ILogger<InMemoryKeyStore>>()),
            sp => new InMemoryCertificateStore(options, sp.GetService<ILogger<InMemoryCertificateStore>>()));
    }
}

/// <summary>Trava de ambiente: o provedor em memória só roda em Development (ou com liberação explícita).</summary>
internal static class InMemoryEnvironment
{
    internal static void EnsureAllowed(InMemoryVaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.AllowOutsideDevelopment || VaultEnvironment.IsDevelopment(options.HostEnvironment))
            return;

        throw new InvalidOperationException(
            "O provedor de cofre em memória (TEC.Vault.InMemory) só é permitido no ambiente Development (IHostEnvironment ou " +
            "ASPNETCORE_ENVIRONMENT/DOTNET_ENVIRONMENT). Em produção use um cofre real; em testes automatizados, " +
            "InMemoryVaultOptions.AllowOutsideDevelopment = true.");
    }
}

/// <summary>Disponibiliza o provedor em memória para a escolha por configuração (<c>Vault:Provider = InMemory</c>).</summary>
public static class InMemoryVaultCatalogExtensions
{
    /// <summary>Nome do provedor na configuração.</summary>
    public const string ProviderName = "InMemory";

    /// <summary>
    /// Adiciona o provedor em memória aos provedores disponíveis. Opções lidas de <c>Vault:InMemory</c>: <c>MaxBackups</c> e
    /// <c>InitialSecrets</c> (seção nome → valor). Continua bloqueado fora de Development.
    /// </summary>
    /// <remarks>
    /// <c>AllowOutsideDevelopment</c> não é lido da configuração de propósito: liberar o cofre em memória fora de Development
    /// tem de ser decisão em código (<paramref name="configure"/>), nunca efeito de um appsettings trocado.
    /// </remarks>
    public static VaultProviderCatalog AddInMemory(this VaultProviderCatalog catalog, Action<InMemoryVaultOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        return catalog.Add(new VaultProviderRegistration(ProviderName, VaultStores.All,
            (builder, settings, stores) => builder.UseInMemory(o =>
            {
                Read(settings, o);
                configure?.Invoke(o);
                o.Stores = stores;
            }),
            (settings, loggerFactory) =>
            {
                var options = new InMemoryVaultOptions();
                Read(settings, options);
                configure?.Invoke(options);
                InMemoryEnvironment.EnsureAllowed(options);
                return new InMemorySecretStore(options, loggerFactory?.CreateLogger<InMemorySecretStore>());
            }));
    }

    private static void Read(VaultSettings settings, InMemoryVaultOptions options)
    {
        settings.RejectKey("AllowOutsideDevelopment", "só pode ser definido em código (InMemoryVaultOptions.AllowOutsideDevelopment).");
        if (settings.GetInt32("MaxBackups", 1) is { } maxBackups)
            options.MaxBackups = maxBackups;
        foreach (var (name, value) in settings.GetDictionary("InitialSecrets"))
            options.InitialSecrets[name] = value;
        settings.EnsureNoUnknownKeys();
    }
}
