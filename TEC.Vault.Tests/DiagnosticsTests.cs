using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TEC.Vault.Abstractions;
using TEC.Vault.Caching;
using TEC.Vault.Common;
using TEC.Vault.Diagnostics;
using TEC.Vault.Providers;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>Métricas (Meter "TEC.Vault") e compatibilidade .NET 8 × .NET 9+ da carga de certificados.</summary>
public class DiagnosticsTests
{
    /// <summary>Medições capturadas do Meter do cofre (os testes rodam em paralelo: filtre pelo que o teste gerou).</summary>
    private sealed class MeterCapture : IDisposable
    {
        private readonly MeterListener _listener = new();

        public ConcurrentQueue<(string Instrument, double Value, Dictionary<string, object?> Tags)> Measurements { get; } = new();

        public MeterCapture()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == VaultDiagnostics.MeterName)
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Add(instrument, value, tags));
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Add(instrument, value, tags));
            _listener.Start();
        }

        private void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var copy = new Dictionary<string, object?>();
            foreach (var tag in tags)
                copy[tag.Key] = tag.Value;
            Measurements.Enqueue((instrument.Name, value, copy));
        }

        public void Dispose() => _listener.Dispose();
    }

    [Test]
    public async Task Operations_record_duration_with_provider_operation_and_error_without_item_name()
    {
        using var capture = new MeterCapture();
        var store = Memory.Secrets();
        string name = "metrica-" + Guid.NewGuid().ToString("N");

        await store.SetSecretAsync(name, "valor");
        await store.GetSecretAsync(name + "-inexistente");
        await store.GetSecretAsync("nome invalido");

        var durations = capture.Measurements.Where(m => m.Instrument == VaultDiagnostics.OperationDurationName
            && Equals(m.Tags.GetValueOrDefault("vault.provider"), "InMemory")).ToList();
        await Assert.That(durations.Any(m => Equals(m.Tags["vault.operation"], "secret.set") && !m.Tags.ContainsKey("error.type"))).IsTrue();
        await Assert.That(durations.Any(m => Equals(m.Tags["vault.operation"], "secret.get")
            && Equals(m.Tags.GetValueOrDefault("error.type"), VaultErrors.NotFoundCode))).IsTrue();
        await Assert.That(durations.Any(m => Equals(m.Tags.GetValueOrDefault("error.type"), VaultErrors.InvalidInputCode))).IsTrue();

        // Segurança: só dimensões de baixa cardinalidade; o nome do item nunca vai para a métrica
        var allowed = new[] { "vault.provider", "vault.operation", "error.type", "vault.cache.result" };
        await Assert.That(capture.Measurements.All(m => m.Tags.Keys.All(allowed.Contains))).IsTrue();
        await Assert.That(capture.Measurements.Any(m => m.Tags.Values.Any(v => v is string s && s.Contains(name, StringComparison.Ordinal)))).IsFalse();
    }

    [Test]
    public async Task Cache_records_hit_miss_and_coalesced()
    {
        using var capture = new MeterCapture();
        string provider = "Metricas-" + Guid.NewGuid().ToString("N");
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "1");
        var inner = new ScriptedSecretStore(new NamedSecretStore(memory, provider)) { AfterGet = (_, _) => gate.Task };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var first = cache.GetSecretAsync("a");    // miss
        var second = cache.GetSecretAsync("a");   // coalesced
        gate.SetResult();
        await Task.WhenAll(first, second);
        await cache.GetSecretAsync("a");          // hit

        var results = capture.Measurements
            .Where(m => m.Instrument == VaultDiagnostics.CacheRequestsName && Equals(m.Tags["vault.provider"], provider))
            .Select(m => (string)m.Tags["vault.cache.result"]!).Order().ToList();
        await Assert.That(results).IsEquivalentTo(new[] { "coalesced", "hit", "miss" });
    }

    [Test]
    public async Task Meter_name_is_exposed() =>
        await Assert.That(VaultDiagnostics.MeterName).IsEqualTo("TEC.Vault");

    [Test]
    public async Task Sources_use_prefix_exported_by_TEC_Observability()
    {
        // O AddTecObservability registra "TEC.*" como ActivitySource e Meter: renomear quebraria a exportação em silêncio
        await Assert.That(VaultDiagnostics.ActivitySourceName).StartsWith("TEC.");
        await Assert.That(VaultDiagnostics.MeterName).StartsWith("TEC.");
    }

    [Test]
    public async Task Activity_has_error_type_like_the_metric_and_no_item_name()
    {
        using var testSource = new ActivitySource("TEC.Vault.Tests.Diagnostics");
        List<Activity> stopped = [];
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == VaultDiagnostics.ActivitySourceName || source == testSource,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                lock (stopped)
                    stopped.Add(activity);
            }
        };
        ActivitySource.AddActivityListener(listener);
        var store = Memory.Secrets();
        string name = "trace-" + Guid.NewGuid().ToString("N");

        // Trace próprio: os testes rodam em paralelo (e o TUnit executa cada teste dentro de uma Activity)
        Activity.Current = null;
        ActivityTraceId traceId;
        using (var root = testSource.StartActivity("teste")!)
        {
            traceId = root.TraceId;
            await store.SetSecretAsync(name, "valor");
            await store.GetSecretAsync(name + "-inexistente");
        }

        Activity[] mine;
        lock (stopped)
            mine = [.. stopped.Where(a => a.TraceId == traceId && a.Source.Name == VaultDiagnostics.ActivitySourceName)];
        var set = mine.Single(a => Equals(a.GetTagItem("vault.operation"), "secret.set"));
        var get = mine.Single(a => Equals(a.GetTagItem("vault.operation"), "secret.get"));

        await Assert.That(set.GetTagItem("error.type")).IsNull();
        await Assert.That(get.GetTagItem("error.type")).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That(get.Status).IsEqualTo(ActivityStatusCode.Error);
        await Assert.That(mine.Any(a => a.TagObjects.Any(t => t.Value is string s && s.Contains(name, StringComparison.Ordinal)))).IsFalse();
        await Assert.That(mine.Any(a => a.DisplayName.Contains(name, StringComparison.Ordinal))).IsFalse();
    }

    // ---------- Carga de certificados: X509CertificateLoader (.NET 9+) × construtor (.NET 8) ----------

    [Test]
    public async Task Certificate_loader_implementation_matches_runtime()
    {
#if NET9_0_OR_GREATER
        await Assert.That(VaultCertificateLoader.UsesCertificateLoader).IsTrue();
#else
        await Assert.That(VaultCertificateLoader.UsesCertificateLoader).IsFalse();
#endif
    }

    [Test]
    public async Task LoadCertificate_loads_der_and_rejects_pfx()
    {
        using var rsa = RSA.Create(2048);
        using var cert = new CertificateRequest("CN=carga", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        using var loaded = VaultCertificateLoader.LoadCertificate(cert.RawData);

        await Assert.That(loaded.Thumbprint).IsEqualTo(cert.Thumbprint);
        await Assert.That(loaded.HasPrivateKey).IsFalse();
        await Assert.That(() => VaultCertificateLoader.LoadCertificate(cert.Export(X509ContentType.Pkcs12, "s"))).Throws<CryptographicException>();
    }

    [Test]
    public async Task LoadPkcs12_loads_key_and_rejects_wrong_password_and_certificate_without_key()
    {
        using var rsa = RSA.Create(2048);
        using var cert = new CertificateRequest("CN=carga", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        byte[] pfx = cert.Export(X509ContentType.Pkcs12, "senha");

        using var loaded = VaultCertificateLoader.LoadPkcs12(pfx, "senha");

        await Assert.That(loaded.HasPrivateKey).IsTrue();
        await Assert.That(() => VaultCertificateLoader.LoadPkcs12(pfx, "errada")).Throws<CryptographicException>();
        await Assert.That(() => VaultCertificateLoader.LoadPkcs12(cert.RawData, null)).Throws<CryptographicException>();
    }

    [Test]
    public async Task Safe_flags_do_not_write_key_to_disk_outside_macOS() =>
        await Assert.That(VaultCertificateLoader.SafeKeyStorageFlags).IsEqualTo(OperatingSystem.IsMacOS()
            ? X509KeyStorageFlags.DefaultKeySet
            : X509KeyStorageFlags.EphemeralKeySet);

    /// <summary>Repassa tudo ao cofre interno, trocando só o nome do provedor (isola as métricas deste teste).</summary>
    private sealed class NamedSecretStore(ISecretStore inner, string providerName) : ISecretStore
    {
        public string ProviderName => providerName;

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            inner.GetSecretAsync(name, version, cancellationToken);

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => inner.ExistsAsync(name, cancellationToken);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            inner.ListSecretsAsync(cancellationToken);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            inner.ListSecretVersionsAsync(name, cancellationToken);

        public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
            CancellationToken cancellationToken = default) => inner.SetSecretAsync(name, value, options, cancellationToken);

        public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
            CancellationToken cancellationToken = default) => inner.UpdateSecretPropertiesAsync(name, update, version, cancellationToken);

        public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
            inner.DeleteSecretAsync(name, cancellationToken);
    }
}
