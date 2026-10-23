using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HashiCorpVault;
using TEC.Vault.Synced;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Azure Key Vault pelo catálogo e casos de borda da seleção por configuração.</summary>
public class CatalogEdgeCaseTests : TempFolderTest
{
    private static IConfiguration Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>("Vault:" + v.Key, v.Value)))
            .Build()
            .GetSection("Vault");

    [Test]
    public async Task Azure_key_vault_chosen_by_configuration_registers_three_families()
    {
        var services = new ServiceCollection();
        services.AddTecVault(Config(("Provider", "AzureKeyVault"), ("AzureKeyVault:VaultUri", "https://kv-teste.vault.azure.net/"),
            ("AzureKeyVault:Authentication", "WorkloadIdentity"), ("Keys:Provider", "None")), p => p.AddAzureKeyVault());
        using var sp = services.BuildServiceProvider();

        await Assert.That(sp.GetService<ISecretStore>()).IsTypeOf<AzureKeyVaultSecretStore>();
        await Assert.That(sp.GetService<ICertificateStore>()).IsTypeOf<AzureKeyVaultCertificateStore>();
        await Assert.That(sp.GetService<IKeyCryptography>()).IsNull();
    }

    [Test]
    public async Task Azure_key_vault_with_address_outside_domain_fails_at_startup()
    {
        await Assert.That(() => new ServiceCollection().AddTecVault(
                Config(("Provider", "AzureKeyVault"), ("AzureKeyVault:VaultUri", "https://cofre-falso.exemplo.com/")), p => p.AddAzureKeyVault()))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Developer_credential_outside_development_is_not_allowed_by_configuration()
    {
        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(
                Config(("Provider", "AzureKeyVault"), ("AzureKeyVault:VaultUri", "https://kv-teste.vault.azure.net/"),
                    ("AzureKeyVault:AllowDeveloperCredentialsOutsideDevelopment", "true")), p => p.AddAzureKeyVault()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("código");
    }

    [Test]
    public async Task Cache_above_limit_reports_the_key()
    {
        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(
                Config(("Provider", "EnvironmentVariables"), ("EnvironmentVariables:Prefix", "APP_"), ("Cache:Duration", "02:00:00")), p => p.AddSynced()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:Cache:Duration");
    }

    [Test]
    public async Task Plain_text_credential_points_to_correct_keys()
    {
        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(
                Config(("Provider", "HashiCorpVault"), ("HashiCorpVault:Address", "https://vault.teste"), ("HashiCorpVault:Auth:Token", "x")),
                p => p.AddHashiCorpVault()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:HashiCorpVault:Auth:TokenFile");
        await Assert.That(exception.Message).DoesNotContain("Auth:Auth");
    }

    [Test]
    public async Task Auto_renewal_unsupported_by_hashicorp_is_rejected()
    {
        using var store = new HashiCorpVaultCertificateStore(HashiCorpTestOptions.Create(new FakeHashiCorpVault(), Folder));

        var result = await store.CreateCertificateAsync("a",
            new CreateCertificateOptions { Subject = "CN=a", Issuer = "Self", KeySize = 2048, AutoRenewDaysBeforeExpiry = 30 });

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
    }

    [Test]
    public async Task Secrets_folder_that_is_a_symbolic_link_works()
    {
        Write("real/db", "valor");
        var link = Path.Combine(Folder, "montada");
        try
        {
            Directory.CreateSymbolicLink(link, Path.Combine(Folder, "real"));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Skip.Test("Sem permissão para criar links simbólicos nesta máquina.");
        }

        var store = new DirectorySecretStore(new DirectorySecretsOptions { Path = link });

        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("valor");
    }
}
