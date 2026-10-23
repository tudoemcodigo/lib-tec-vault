using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.InMemory;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

public class ChainedProviderTests
{
    private static InMemoryVaultOptions Options(Action<InMemoryVaultOptions>? configure = null)
    {
        var opts = new InMemoryVaultOptions { AllowOutsideDevelopment = true };
        configure?.Invoke(opts);
        return opts;
    }

    [Test]
    public async Task GetSecretAsync_returns_value_from_first_provider_when_present()
    {
        var primary = new InMemorySecretStore(Options(o => o.InitialSecrets["db-conn"] = "primary-value"));
        var secondary = new InMemorySecretStore(Options(o => o.InitialSecrets["db-conn"] = "secondary-value"));

        var chained = new ChainedSecretReader([primary, secondary]);

        var result = await chained.GetSecretAsync("db-conn");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("primary-value");
    }

    [Test]
    public async Task GetSecretAsync_falls_back_to_second_provider_when_missing_in_first()
    {
        var primary = new InMemorySecretStore(Options());
        var secondary = new InMemorySecretStore(Options(o => o.InitialSecrets["api-key"] = "fallback-key"));

        var chained = new ChainedSecretReader([primary, secondary]);

        var result = await chained.GetSecretAsync("api-key");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("fallback-key");
    }

    [Test]
    public async Task GetSecretAsync_returns_not_found_when_missing_in_all_providers()
    {
        var primary = new InMemorySecretStore(Options());
        var secondary = new InMemorySecretStore(Options());

        var chained = new ChainedSecretReader([primary, secondary]);

        var result = await chained.GetSecretAsync("non-existent");

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task ListSecretsAsync_aggregates_properties_from_all_providers_without_duplicates()
    {
        var primary = new InMemorySecretStore(Options(o =>
        {
            o.InitialSecrets["secret-a"] = "1";
            o.InitialSecrets["shared-key"] = "p1";
        }));

        var secondary = new InMemorySecretStore(Options(o =>
        {
            o.InitialSecrets["secret-b"] = "2";
            o.InitialSecrets["shared-key"] = "p2";
        }));

        var chained = new ChainedSecretReader([primary, secondary]);

        var result = await chained.ListSecretsAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        var names = result.Value.Select(p => p.Name).ToList();
        await Assert.That(names).Contains("secret-a");
        await Assert.That(names).Contains("secret-b");
        await Assert.That(names).Contains("shared-key");
        await Assert.That(result.Value.Count).IsEqualTo(3);
    }

    [Test]
    public async Task ExistsAsync_returns_true_if_present_in_any()
    {
        var primary = new InMemorySecretStore(Options());
        var secondary = new InMemorySecretStore(Options(o => o.InitialSecrets["api-key"] = "fallback-key"));

        var chained = new ChainedSecretReader([primary, secondary]);

        var exists = await chained.ExistsAsync("api-key");

        await Assert.That(exists.IsSuccess).IsTrue();
        await Assert.That(exists.Value).IsTrue();
    }

    [Test]
    public async Task CheckAccessAsync_reports_ok_when_all_healthy()
    {
        var primary = new InMemorySecretStore(Options());
        var secondary = new InMemorySecretStore(Options());

        var chained = new ChainedSecretReader([primary, secondary]);

        var status = await chained.CheckAccessAsync();

        await Assert.That(status.IsSuccess).IsTrue();
    }
}
