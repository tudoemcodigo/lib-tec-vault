using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Reflection;
using Microsoft.Extensions.Logging;
using TEC.Vault.Caching;
using TEC.Vault.Diagnostics;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>
/// Convenção de telemetria da Doutrina TEC (CMP-OBS-06/07): instrumentos <c>tec.vault.*</c> e EventId na faixa 7000-7999.
/// Os nomes antigos <c>vault.*</c> coexistem por uma MINOR e emitem a mesma medição.
/// </summary>
public class TelemetryConventionTests
{
    private const int RangeStart = 7000;
    private const int RangeEnd = 7999;

    private static readonly string[] ProviderAssemblies =
    [
        "TEC.Vault", "TEC.Vault.AzureKeyVault", "TEC.Vault.AwsSecretsManager", "TEC.Vault.GoogleSecretManager",
        "TEC.Vault.HashiCorpVault", "TEC.Vault.Infisical", "TEC.Vault.Synced", "TEC.Vault.InMemory"
    ];

    private static readonly string[] LegacyNames =
    [
        "vault.operation.duration", "vault.cache.requests", "vault.circuit.state_changes"
    ];

    private static List<(string Instrument, string Name, double Value, Dictionary<string, object?> Tags)> Capture(
        Action action, string? provider = null)
    {
        var measurements = new ConcurrentQueue<(string, string, double, Dictionary<string, object?>)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == VaultDiagnostics.MeterName)
                l.EnableMeasurementEvents(instrument);
        };
        void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var copy = tags.ToArray().ToDictionary(t => t.Key, t => t.Value);
            measurements.Enqueue((instrument.Name, instrument.Name, value, copy));
        }
        listener.SetMeasurementEventCallback<double>((i, v, t, _) => Add(i, v, t));
        listener.SetMeasurementEventCallback<long>((i, v, t, _) => Add(i, v, t));
        listener.Start();
        action();
        return measurements
            .Where(m => provider is null || Equals(m.Item4.GetValueOrDefault("vault.provider"), provider))
            .ToList();
    }

    [Test]
    public async Task Every_instrument_starts_with_tec_vault_except_the_deprecated_names()
    {
        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(VaultDiagnostics).TypeHandle);   // cria os instrumentos
        var names = new ConcurrentBag<string>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, _) =>
        {
            if (instrument.Meter.Name == VaultDiagnostics.MeterName)
                names.Add(instrument.Name);
        };
        listener.Start();

        var all = names.Distinct().ToList();
        await Assert.That(all.Count).IsGreaterThanOrEqualTo(6);
        foreach (var name in all)
        {
            await Assert.That(name.StartsWith("tec.vault.", StringComparison.Ordinal) || LegacyNames.Contains(name)).IsTrue();
        }
        // Cada nome antigo tem o novo correspondente
        foreach (var legacy in LegacyNames)
            await Assert.That(all.Contains("tec." + legacy)).IsTrue();
    }

    [Test]
    public async Task Public_name_constants_follow_the_convention_and_legacy_constants_are_obsolete()
    {
        await Assert.That(VaultDiagnostics.OperationDurationName).IsEqualTo("tec.vault.operation.duration");
        await Assert.That(VaultDiagnostics.CacheRequestsName).IsEqualTo("tec.vault.cache.requests");
        await Assert.That(VaultDiagnostics.CircuitStateChangesName).IsEqualTo("tec.vault.circuit.state_changes");

        var legacy = typeof(VaultDiagnostics).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.Name.StartsWith("Legacy", StringComparison.Ordinal)).ToList();
        await Assert.That(legacy.Count).IsEqualTo(3);
        foreach (var field in legacy)
        {
            await Assert.That(field.GetCustomAttribute<ObsoleteAttribute>()).IsNotNull();
            await Assert.That(LegacyNames.Contains((string)field.GetRawConstantValue()!)).IsTrue();
        }
    }

    [Test]
    public async Task Old_and_new_duration_instruments_receive_the_same_measurement_and_tags()
    {
        var store = Memory.Secrets();
        string name = "coex-" + Guid.NewGuid().ToString("N");

        var measured = Capture(() =>
        {
            store.SetSecretAsync(name, "v").GetAwaiter().GetResult();
            store.GetSecretAsync(name + "-nao-existe").GetAwaiter().GetResult();   // falha: error.type presente
            store.GetSecretAsync("nome invalido").GetAwaiter().GetResult();        // entrada recusada
        }, provider: "InMemory");

        var newer = measured.Where(m => m.Instrument == "tec.vault.operation.duration").ToList();
        var older = measured.Where(m => m.Instrument == "vault.operation.duration").ToList();
        await Assert.That(newer.Count).IsGreaterThanOrEqualTo(3);
        await Assert.That(older.Count).IsEqualTo(newer.Count);
        // Testes em paralelo intercalam as medições: compara como conjuntos (valor + tags), não por posição
        static string Key((string Instrument, string Name, double Value, Dictionary<string, object?> Tags) m) =>
            $"{m.Value:R}|{string.Join(",", m.Tags.OrderBy(t => t.Key).Select(t => $"{t.Key}={t.Value}"))}";
        await Assert.That(older.Select(Key).Order()).IsEquivalentTo(newer.Select(Key).Order());
        // Tags inalteradas e sem o nome do item
        var allowed = new[] { "vault.provider", "vault.operation", "error.type" };
        await Assert.That(measured.All(m => m.Tags.Keys.All(allowed.Contains))).IsTrue();
        await Assert.That(measured.Any(m => m.Tags.Values.Any(v => v is string s && s.Contains(name, StringComparison.Ordinal)))).IsFalse();
    }

    [Test]
    public async Task Old_and_new_cache_instruments_receive_the_same_measurement_and_tags()
    {
        string provider = "Coex-" + Guid.NewGuid().ToString("N");
        var memory = Memory.Secrets();
        memory.SetSecretAsync("a", "1").GetAwaiter().GetResult();
        using var cache = new CachingSecretReader(new DiagnosticsTests.NamedSecretStore(memory, provider), TimeSpan.FromMinutes(5));

        var measured = Capture(() =>
        {
            cache.GetSecretAsync("a").GetAwaiter().GetResult();   // miss
            cache.GetSecretAsync("a").GetAwaiter().GetResult();   // hit
        }, provider);

        string Key((string Instrument, string Name, double Value, Dictionary<string, object?> Tags) m) =>
            $"{m.Value}|{string.Join(",", m.Tags.OrderBy(t => t.Key).Select(t => $"{t.Key}={t.Value}"))}";
        var newer = measured.Where(m => m.Instrument == "tec.vault.cache.requests").Select(Key).Order().ToList();
        var older = measured.Where(m => m.Instrument == "vault.cache.requests").Select(Key).Order().ToList();
        await Assert.That(newer.Count).IsEqualTo(2);
        await Assert.That(older).IsEquivalentTo(newer);
        await Assert.That(newer.Any(k => k.Contains("vault.cache.result=hit", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    public async Task Old_and_new_circuit_instruments_receive_the_same_measurement_and_tags()
    {
        string provider = "Circ-" + Guid.NewGuid().ToString("N");
        var measured = Capture(() => VaultDiagnostics.RecordCircuitState(provider, VaultDiagnostics.CircuitOpen), provider);

        var newer = measured.Single(m => m.Instrument == "tec.vault.circuit.state_changes");
        var older = measured.Single(m => m.Instrument == "vault.circuit.state_changes");
        await Assert.That(older.Value).IsEqualTo(newer.Value);
        await Assert.That(older.Tags["vault.circuit.state"]).IsEqualTo("open");
        await Assert.That(newer.Tags["vault.circuit.state"]).IsEqualTo("open");
        await Assert.That(older.Tags["vault.provider"]).IsEqualTo(provider);
        await Assert.That(newer.Tags.Count).IsEqualTo(older.Tags.Count);
    }

    [Test]
    public async Task Every_EventId_of_every_package_is_in_the_7000_to_7999_range_and_unique()
    {
        // Os ids ficam no [LoggerMessage] (os campos gerados guardam o id dentro de delegates, fora do alcance da reflexão)
        var ids = new List<(string Where, int Id)>();
        foreach (var assemblyName in ProviderAssemblies)
        {
            var assembly = System.Reflection.Assembly.Load(assemblyName);
            foreach (var type in assembly.GetTypes())
            {
                foreach (var method in type.GetMethods(BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
                {
                    var attribute = method.GetCustomAttribute<LoggerMessageAttribute>();
                    if (attribute is not null)
                        ids.Add(($"{type.FullName}.{method.Name}", attribute.EventId));
                }
            }
        }

        // Sanidade: o varredor encontrou os eventos do núcleo, do Synced e da AWS
        await Assert.That(ids.Count).IsGreaterThanOrEqualTo(25);
        foreach (var (where, id) in ids)
        {
            await Assert.That(id is >= RangeStart and <= RangeEnd).IsTrue().Because($"{where} = {id} fora de {RangeStart}-{RangeEnd}");
        }
        var duplicates = ids.GroupBy(i => i.Id).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        await Assert.That(duplicates).IsEmpty();
    }
}
