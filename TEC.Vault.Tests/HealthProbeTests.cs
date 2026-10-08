using System.Net;
using Azure.Core.Pipeline;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HealthChecks;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>Sonda do health check: registrada em qualquer combinação de stores e verificando só os stores registrados.</summary>
public class HealthProbeTests
{
    [Test]
    public async Task Only_UseKeyStore_registers_probe_and_stays_healthy()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecVault(c => c.UseKeyStore<KeyReaderStub>());
        services.AddHealthChecks().AddTecVault();
        using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();

        await Assert.That(report.Entries["vault"].Status).IsEqualTo(HealthStatus.Healthy);
        await Assert.That(provider.GetRequiredService<KeyReaderStub>().ListKeysCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Health_check_joins_readiness_by_default_and_given_tags_replace()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecVault(c => c.UseKeyStore<KeyReaderStub>());
        services.AddHealthChecks()
            .AddTecVault()
            .AddTecVault(name: "cofre-proprio", tags: ["critico"]);
        using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();

        // "ready" é a tag do readiness do TEC.Observability (/health/ready); nunca "live"
        await Assert.That(report.Entries["vault"].Tags).IsEquivalentTo(new[] { "ready", "vault" });
        await Assert.That(report.Entries["cofre-proprio"].Tags).IsEquivalentTo(new[] { "critico" });
    }

    [Test]
    public async Task Own_probe_registered_before_is_kept()
    {
        var own = new ProbeStub(Result.Success());
        var services = new ServiceCollection();
        services.AddSingleton<IVaultHealthProbe>(own);
        services.AddTecVault(c => c.UseSecretStore<SecretReaderStub>());
        using var provider = services.BuildServiceProvider();

        await Assert.That(provider.GetRequiredService<IVaultHealthProbe>()).IsSameReferenceAs(own);
    }

    [Test]
    public async Task Failure_of_one_store_fails_the_probe()
    {
        var probe = new VaultHealthProbe([_ => Task.FromResult(Result.Success()), _ => Task.FromResult(Result.Failure(VaultErrors.AccessDenied()))]);

        var result = await probe.CheckAccessAsync();

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);
    }

    [Test]
    public async Task Azure_keys_only_registers_only_IKeyStore_and_probe_lists_only_keys()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, """{"value":[]}"""));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecVault(c => c.UseAzureKeyVault(o =>
        {
            Fake(o, vault);
            o.Stores = VaultStores.Keys;
        }));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true });

        var result = await provider.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(provider.GetService<ISecretStore>()).IsNull();
        await Assert.That(provider.GetService<ICertificateStore>()).IsNull();
        await Assert.That(provider.GetService<IKeyStore>()).IsNotNull();
        await Assert.That(vault.Requests.All(r => r.Uri.AbsolutePath.TrimEnd('/') == "/keys")).IsTrue();
    }

    [Test]
    public async Task Azure_keys_only_does_not_need_secret_permission()
    {
        // Identidade com papel só de chaves: listar segredos daria 403
        var vault = new FakeKeyVault((request, _) => request.RequestUri!.AbsolutePath.StartsWith("/keys", StringComparison.Ordinal)
            ? (HttpStatusCode.OK, """{"value":[]}""")
            : (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "Caller is not authorized.", "ForbiddenByRbac")));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecVault(c => c.UseAzureKeyVault(o =>
        {
            Fake(o, vault);
            o.Stores = VaultStores.Keys;
        }));
        services.AddHealthChecks().AddTecVault();
        using var provider = services.BuildServiceProvider();

        var report = await provider.GetRequiredService<HealthCheckService>().CheckHealthAsync();

        await Assert.That(report.Entries["vault"].Status).IsEqualTo(HealthStatus.Healthy);
    }

    [Test]
    public async Task Azure_with_all_stores_checks_secrets_keys_and_certificates()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, """{"value":[]}"""));
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecVault(c => c.UseAzureKeyVault(o => Fake(o, vault)));
        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync();
        var paths = vault.Requests.Where(r => r.Authorized).Select(r => r.Uri.AbsolutePath.TrimEnd('/')).Distinct().Order().ToList();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(paths).IsEquivalentTo(new[] { "/certificates", "/keys", "/secrets" });
    }

    [Test]
    public async Task Azure_empty_stores_is_rejected_at_startup()
    {
        var services = new ServiceCollection();

        await Assert.That(() => services.AddTecVault(c => c.UseAzureKeyVault(o =>
        {
            o.VaultUri = new Uri(FakeKeyVault.VaultUri);
            o.Credential = new FakeCredential();
            o.Stores = VaultStores.None;
        }))).Throws<InvalidOperationException>();
    }

    private static void Fake(AzureKeyVaultOptions options, FakeKeyVault vault)
    {
        options.VaultUri = new Uri(FakeKeyVault.VaultUri);
        options.Credential = new FakeCredential();
        options.MaxRetries = 0;
        options.Transport = new HttpClientTransport(new HttpClient(vault));
    }

    private sealed class ProbeStub(Result result) : IVaultHealthProbe
    {
        public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) => Task.FromResult(result);
    }
}
