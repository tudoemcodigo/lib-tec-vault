using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Caching;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HealthChecks;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>Registro no container: provedores que seriam ignorados em silêncio, sonda sem verificações e descarte do cache.</summary>
public class DependencyInjectionTests
{
    // ---------- VaultBuilder: registro que o container descartaria ----------

    [Test]
    public async Task Provider_class_already_registered_in_container_is_rejected()
    {
        var byType = new ServiceCollection();
        byType.AddSingleton<SecretReaderStub>();
        var byFactory = new ServiceCollection();
        byFactory.AddSingleton(new SecretReaderStub());

        var typed = await Assert.That(() => byType.AddTecVault(c => c.UseSecretStore<SecretReaderStub>())).Throws<InvalidOperationException>();
        await Assert.That(() => byFactory.AddTecVault(c => c.UseSecretStore(_ => new SecretReaderStub()))).Throws<InvalidOperationException>();
        await Assert.That(typed!.Message).Contains(nameof(SecretReaderStub));
    }

    [Test]
    public async Task Second_factory_for_same_class_is_rejected()
    {
        var first = new SecretReaderStub();
        var services = new ServiceCollection();

        var exception = await Assert.That(() => services.AddTecVault(c => c
                .UseSecretStore(_ => first)
                .UseSecretStore(_ => new SecretReaderStub())))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("fábrica");
    }

    [Test]
    public async Task Same_class_with_and_without_factory_in_different_families_is_rejected()
    {
        var services = new ServiceCollection();

        await Assert.That(() => services.AddTecVault(c => c
                .UseSecretStore<SecretAndKeyStub>()
                .UseKeyStore(_ => new SecretAndKeyStub())))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Repeat_without_factory_or_with_same_factory_is_accepted_and_registers_once()
    {
        Func<IServiceProvider, SecretReaderStub> factory = _ => new SecretReaderStub();
        var withFactory = new ServiceCollection();
        withFactory.AddTecVault(c => c.UseSecretStore(factory).UseSecretStore(factory));
        var byType = new ServiceCollection();
        byType.AddTecVault(c => c.UseSecretStore<SecretAndKeyStub>().UseKeyStore<SecretAndKeyStub>());
        using var provider = byType.BuildServiceProvider();

        await Assert.That(withFactory.Count(d => d.ServiceType == typeof(SecretReaderStub))).IsEqualTo(1);
        await Assert.That(byType.Count(d => d.ServiceType == typeof(SecretAndKeyStub))).IsEqualTo(1);
        await Assert.That(provider.GetRequiredService<IKeyReader>()).IsSameReferenceAs(provider.GetRequiredService<ISecretReader>());
    }

    // ---------- Sonda sem verificações ----------

    [Test]
    public async Task Probe_without_checks_stays_healthy_and_warns_once()
    {
        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddTecVault(c => c.UseKeyStore<CryptographyOnlyStub>());   // só IKeyCryptography, sem sonda própria
        services.AddHealthChecks().AddTecVault();
        using var provider = services.BuildServiceProvider();
        var health = provider.GetRequiredService<HealthCheckService>();

        var first = await health.CheckHealthAsync();
        var second = await health.CheckHealthAsync();

        await Assert.That(((VaultHealthProbe)provider.GetRequiredService<IVaultHealthProbe>()).Count).IsEqualTo(0);
        await Assert.That(first.Entries["vault"].Status).IsEqualTo(HealthStatus.Healthy);
        await Assert.That(second.Entries["vault"].Status).IsEqualTo(HealthStatus.Healthy);
        await Assert.That(logs.Entries.Count(e => e.Level == LogLevel.Warning && e.Text.Contains("sem nenhuma verificação"))).IsEqualTo(1);
    }

    [Test]
    public async Task Probe_with_checks_does_not_log_warning()
    {
        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddTecVault(c => c.UseSecretStore<SecretReaderStub>());
        using var provider = services.BuildServiceProvider();

        var result = await provider.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(logs.Entries.Any(e => e.Text.Contains("sem nenhuma verificação"))).IsFalse();
    }

    // ---------- Cache descartado pelo container ----------

    [Test]
    public async Task Container_disposes_cache_and_following_reads_go_to_provider()
    {
        var inner = new ScriptedSecretStore(Memory.Secrets());
        await inner.SetSecretAsync("A", "1");
        var services = new ServiceCollection();
        services.AddTecVault(c => c.UseSecretStore(_ => inner).EnableSecretCache(TimeSpan.FromMinutes(1)));
        var provider = services.BuildServiceProvider();
        var cache = provider.GetRequiredService<CachingSecretReader>();
        var reader = provider.GetRequiredService<ISecretReader>();

        await reader.GetSecretAsync("A");
        await reader.GetSecretAsync("A");
        await Assert.That(inner.GetCalls).IsEqualTo(1);
        await Assert.That(cache.Count).IsEqualTo(1);

        await provider.DisposeAsync();

        await Assert.That(cache.IsDisposed).IsTrue();
        var afterDispose = await cache.GetSecretAsync("A");
        await Assert.That(afterDispose.Value.Value).IsEqualTo("1");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    /// <summary>Provedor só de criptografia, sem sonda própria e sem leitura de chaves: nada a verificar.</summary>
    internal sealed class CryptographyOnlyStub : IKeyCryptography
    {
        public string ProviderName => "Stub";

        public Task<Result<VaultEncryptResult>> EncryptAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
            string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<byte[]>> DecryptAsync(string name, string version, byte[] ciphertext,
            VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<VaultEncryptResult>> WrapKeyAsync(string name, byte[] key, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
            string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<byte[]>> UnwrapKeyAsync(string name, string version, byte[] wrappedKey,
            VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<VaultSignResult>> SignDataAsync(string name, byte[] data, VaultSignatureAlgorithm algorithm,
            string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<bool>> VerifyDataAsync(string name, string version, byte[] data, byte[] signature, VaultSignatureAlgorithm algorithm,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    /// <summary>Uma classe para duas famílias (segredos e chaves), com construtor público.</summary>
    internal sealed class SecretAndKeyStub : ISecretReader, IKeyReader
    {
        private readonly SecretReaderStub _secrets = new();
        private readonly KeyReaderStub _keys = new();

        public string ProviderName => "Stub";

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            _secrets.GetSecretAsync(name, version, cancellationToken);

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => _secrets.ExistsAsync(name, cancellationToken);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            _secrets.ListSecretsAsync(cancellationToken);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            _secrets.ListSecretVersionsAsync(name, cancellationToken);

        public Task<Result<VaultKey>> GetKeyAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            _keys.GetKeyAsync(name, version, cancellationToken);

        public Task<Result<IReadOnlyList<KeyProperties>>> ListKeysAsync(CancellationToken cancellationToken = default) => _keys.ListKeysAsync(cancellationToken);

        public Task<Result<IReadOnlyList<KeyProperties>>> ListKeyVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            _keys.ListKeyVersionsAsync(name, cancellationToken);
    }
}
