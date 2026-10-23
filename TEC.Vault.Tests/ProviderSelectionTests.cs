using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Abstractions;
using TEC.Vault.Caching;
using TEC.Vault.Configuration;
using TEC.Vault.DependencyInjection;
using TEC.Vault.InMemory;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Escolha do provedor de cada família pela configuração (AddTecVault com IConfiguration).</summary>
public class ProviderSelectionTests
{
    private static IConfiguration Config(params (string Key, string? Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>("Vault:" + v.Key, v.Value)))
            .Build()
            .GetSection("Vault");

    /// <summary>Provedor de teste que atende só segredos e conta os registros.</summary>
    private sealed class SecretsOnly
    {
        public int Uses;
        public VaultStores LastStores;

        public VaultProviderRegistration Registration => new("SecretsOnly", VaultStores.Secrets, (builder, settings, stores) =>
        {
            Uses++;
            LastStores = stores;
            settings.GetString("Path");
            settings.EnsureNoUnknownKeys();
            builder.UseSecretStore(_ => new SecretReaderStub());
        }, (_, _) => new SecretReaderStub());
    }

    private static ServiceProvider Build(IConfiguration config, SecretsOnly? secretsOnly = null, Action<VaultBuilder>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddTecVault(config, p =>
        {
            p.AddInMemory(o => o.AllowOutsideDevelopment = true);
            p.Add((secretsOnly ?? new SecretsOnly()).Registration);
        }, configure);
        return services.BuildServiceProvider();
    }

    [Test]
    public async Task Default_provider_serves_all_families_it_supports()
    {
        using var sp = Build(Config(("Provider", "InMemory")));

        await Assert.That(sp.GetService<ISecretStore>()).IsTypeOf<InMemorySecretStore>();
        await Assert.That(sp.GetService<IKeyCryptography>()).IsTypeOf<InMemoryKeyStore>();
        await Assert.That(sp.GetService<ICertificateStore>()).IsTypeOf<InMemoryCertificateStore>();
    }

    [Test]
    public async Task Provider_name_is_case_insensitive()
    {
        using var sp = Build(Config(("Provider", "inmemory")));

        await Assert.That(sp.GetService<ISecretReader>()).IsTypeOf<InMemorySecretStore>();
    }

    [Test]
    public async Task Family_override_takes_precedence_over_default()
    {
        using var sp = Build(Config(("Provider", "InMemory"), ("Secrets:Provider", "SecretsOnly")));

        await Assert.That(sp.GetService<ISecretReader>()).IsTypeOf<SecretReaderStub>();
        await Assert.That(sp.GetService<IKeyReader>()).IsTypeOf<InMemoryKeyStore>();
    }

    [Test]
    public async Task Family_not_served_by_default_provider_stays_without_provider()
    {
        using var sp = Build(Config(("Provider", "SecretsOnly")));

        await Assert.That(sp.GetService<ISecretReader>()).IsTypeOf<SecretReaderStub>();
        await Assert.That(sp.GetService<IKeyReader>()).IsNull();
        await Assert.That(sp.GetService<ICertificateReader>()).IsNull();
    }

    [Test]
    public async Task Family_explicitly_assigned_to_provider_without_it_is_rejected()
    {
        var exception = await Assert.That(() => Build(Config(("Provider", "InMemory"), ("Keys:Provider", "SecretsOnly"))))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:Keys:Provider");
        await Assert.That(exception.Message).Contains("chaves");
    }

    [Test]
    public async Task None_disables_the_family()
    {
        using var sp = Build(Config(("Provider", "InMemory"), ("Keys:Provider", "None"), ("Certificates:Provider", "none")));

        await Assert.That(sp.GetService<ISecretReader>()).IsNotNull();
        await Assert.That(sp.GetService<IKeyReader>()).IsNull();
        await Assert.That(sp.GetService<ICertificateReader>()).IsNull();
    }

    [Test]
    public async Task Unknown_provider_lists_available_ones()
    {
        var exception = await Assert.That(() => Build(Config(("Provider", "HashiCorp"))))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("InMemory");
        await Assert.That(exception.Message).Contains("SecretsOnly");
        await Assert.That(exception.Message).Contains("Vault:Provider");
    }

    [Test]
    public async Task No_family_with_provider_is_rejected()
    {
        await Assert.That(() => Build(Config(("Provider", "None")))).Throws<InvalidOperationException>();
        await Assert.That(() => Build(Config(("Cache:Duration", "00:01:00")))).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Same_provider_in_several_families_is_registered_once_with_all()
    {
        var secretsOnly = new SecretsOnly();
        using var sp = Build(Config(("Provider", "SecretsOnly")), secretsOnly);

        await Assert.That(secretsOnly.Uses).IsEqualTo(1);
        await Assert.That(secretsOnly.LastStores).IsEqualTo(VaultStores.Secrets);
    }

    [Test]
    public async Task Unknown_key_at_root_or_in_chosen_provider_is_rejected()
    {
        var root = await Assert.That(() => Build(Config(("Provider", "InMemory"), ("Provder", "x"))))
            .Throws<InvalidOperationException>();
        var provider = await Assert.That(() => Build(Config(("Provider", "InMemory"), ("InMemory:MaxBackup", "3"))))
            .Throws<InvalidOperationException>();

        await Assert.That(root!.Message).Contains("Vault:Provder");
        await Assert.That(provider!.Message).Contains("Vault:InMemory:MaxBackup");
    }

    [Test]
    public async Task Section_of_available_unchosen_provider_is_not_validated()
    {
        using var sp = Build(Config(("Provider", "InMemory"), ("SecretsOnly:Qualquer", "valor"), ("Configuration:Prefix", "App--")));

        await Assert.That(sp.GetService<ISecretReader>()).IsTypeOf<InMemorySecretStore>();
    }

    [Test]
    public async Task Invalid_value_reports_key_and_never_value()
    {
        var exception = await Assert.That(() => Build(Config(("Provider", "InMemory"), ("Cache:Duration", "segredo-colado-aqui"))))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:Cache:Duration");
        await Assert.That(exception.Message).DoesNotContain("segredo-colado-aqui");
    }

    [Test]
    public async Task Cache_by_configuration_enables_cached_reader()
    {
        using var sp = Build(Config(("Provider", "InMemory"), ("Cache:Duration", "00:02:00")));

        await Assert.That(sp.GetService<ISecretReader>()).IsTypeOf<CachingSecretReader>();
    }

    [Test]
    public async Task Configure_in_code_runs_after_configuration()
    {
        using var sp = Build(Config(("Provider", "InMemory")), configure: v => v.EnableSecretCache(TimeSpan.FromMinutes(1)));

        await Assert.That(sp.GetService<ISecretReader>()).IsTypeOf<CachingSecretReader>();
    }

    [Test]
    public async Task InMemory_permission_outside_development_is_not_accepted_from_configuration()
    {
        var exception = await Assert.That(() => Build(Config(("Provider", "InMemory"), ("InMemory:AllowOutsideDevelopment", "true"))))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("código");
    }

    [Test]
    public async Task InMemory_initial_secrets_come_from_configuration()
    {
        using var sp = Build(Config(("Provider", "InMemory"), ("InMemory:InitialSecrets:db-senha", "local")));

        var secret = await sp.GetRequiredService<ISecretReader>().GetSecretAsync("db-senha");

        await Assert.That(secret.IsSuccess).IsTrue();
        await Assert.That(secret.Value.Value).IsEqualTo("local");
    }

    [Test]
    public async Task AddTecVault_by_configuration_can_only_be_called_once()
    {
        var services = new ServiceCollection();
        services.AddTecVault(Config(("Provider", "InMemory")), p => p.AddInMemory(o => o.AllowOutsideDevelopment = true));

        await Assert.That(() => services.AddTecVault(Config(("Provider", "InMemory")), p => p.AddInMemory(o => o.AllowOutsideDevelopment = true)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Catalog_rejects_duplicate_name_and_name_None()
    {
        await Assert.That(() => new ServiceCollection().AddTecVault(Config(("Provider", "InMemory")), p => p.AddInMemory().AddInMemory()))
            .Throws<InvalidOperationException>();
        await Assert.That(() => new VaultProviderRegistration("None", VaultStores.Secrets, (_, _, _) => { }))
            .Throws<ArgumentException>();
    }

    // ---------- Fonte de IConfiguration ----------

    [Test]
    public async Task Configuration_source_uses_secret_provider_and_section_options()
    {
        var bootstrap = Config(
            ("Provider", "InMemory"),
            ("Secrets:Provider", "InMemory"),
            ("Keys:Provider", "None"),
            ("InMemory:InitialSecrets:App--ConnectionStrings--Db", "Server=local"),
            ("InMemory:InitialSecrets:Outra--Chave", "x"),
            ("Configuration:Prefix", "App--"));

        var configuration = new ConfigurationBuilder()
            .AddTecVault(bootstrap, p => p.AddInMemory(o => o.AllowOutsideDevelopment = true))
            .Build();

        await Assert.That(configuration["ConnectionStrings:Db"]).IsEqualTo("Server=local");
        await Assert.That(configuration["Outra:Chave"]).IsNull();
    }

    [Test]
    public async Task Configuration_source_without_secret_provider_is_rejected()
    {
        var bootstrap = Config(("Provider", "InMemory"), ("Secrets:Provider", "None"));

        await Assert.That(() => new ConfigurationBuilder().AddTecVault(bootstrap, p => p.AddInMemory(o => o.AllowOutsideDevelopment = true)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Configuration_source_rejects_unknown_option()
    {
        var bootstrap = Config(("Provider", "InMemory"), ("Configuration:Prefx", "App--"));

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecVault(bootstrap, p => p.AddInMemory(o => o.AllowOutsideDevelopment = true)))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:Configuration:Prefx");
    }
}
