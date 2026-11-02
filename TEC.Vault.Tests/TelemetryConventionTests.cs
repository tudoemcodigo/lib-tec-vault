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
/// Os nomes antigos <c>vault.*</c> foram removidos sem coexistência (ADR 0009 da Doutrina).
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

    private static List<string> InstrumentNames()
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
        return names.Distinct().ToList();
    }

    [Test]
    public async Task Every_instrument_starts_with_tec_vault_without_exception()
    {
        var all = InstrumentNames();
        await Assert.That(all.Count).IsEqualTo(3);
        foreach (var name in all)
            await Assert.That(name.StartsWith("tec.vault.", StringComparison.Ordinal)).IsTrue().Because(name);
    }

    [Test]
    public async Task Old_vault_instrument_names_no_longer_exist()
    {
        var all = InstrumentNames();
        foreach (var legacy in LegacyNames)
            await Assert.That(all.Contains(legacy)).IsFalse().Because(legacy);

        // Nenhuma constante pública de nome sobrou com o nome antigo (nem "Legacy*")
        var constants = typeof(VaultDiagnostics).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.FieldType == typeof(string)).ToList();
        await Assert.That(constants.Any(f => f.Name.StartsWith("Legacy", StringComparison.Ordinal))).IsFalse();
        await Assert.That(constants.Any(f => LegacyNames.Contains((string)f.GetRawConstantValue()!))).IsFalse();
    }

    [Test]
    public async Task Public_name_constants_follow_the_convention()
    {
        await Assert.That(VaultDiagnostics.OperationDurationName).IsEqualTo("tec.vault.operation.duration");
        await Assert.That(VaultDiagnostics.CacheRequestsName).IsEqualTo("tec.vault.cache.requests");
        await Assert.That(VaultDiagnostics.CircuitStateChangesName).IsEqualTo("tec.vault.circuit.state_changes");
    }

    [Test]
    public async Task Duration_instrument_records_value_and_tags_without_the_item_name()
    {
        var store = Memory.Secrets();
        string name = "tel-" + Guid.NewGuid().ToString("N");

        var measured = Capture(() =>
        {
            store.SetSecretAsync(name, "v").GetAwaiter().GetResult();
            store.GetSecretAsync(name + "-nao-existe").GetAwaiter().GetResult();   // falha: error.type presente
            store.GetSecretAsync("nome invalido").GetAwaiter().GetResult();        // entrada recusada
        }, provider: "InMemory");

        await Assert.That(measured.All(m => m.Instrument == "tec.vault.operation.duration")).IsTrue();
        await Assert.That(measured.Count).IsGreaterThanOrEqualTo(3);
        await Assert.That(measured.All(m => m.Value >= 0)).IsTrue();
        await Assert.That(measured.Any(m => m.Tags.ContainsKey("error.type"))).IsTrue();
        var allowed = new[] { "vault.provider", "vault.operation", "error.type" };
        await Assert.That(measured.All(m => m.Tags.Keys.All(allowed.Contains))).IsTrue();
        await Assert.That(measured.Any(m => m.Tags.Values.Any(v => v is string s && s.Contains(name, StringComparison.Ordinal)))).IsFalse();
    }

    [Test]
    public async Task Cache_instrument_records_hit_and_miss_once_each()
    {
        string provider = "Tel-" + Guid.NewGuid().ToString("N");
        var memory = Memory.Secrets();
        memory.SetSecretAsync("a", "1").GetAwaiter().GetResult();
        using var cache = new CachingSecretReader(new DiagnosticsTests.NamedSecretStore(memory, provider), TimeSpan.FromMinutes(5));

        var measured = Capture(() =>
        {
            cache.GetSecretAsync("a").GetAwaiter().GetResult();   // miss
            cache.GetSecretAsync("a").GetAwaiter().GetResult();   // hit
        }, provider);

        await Assert.That(measured.Count).IsEqualTo(2);
        await Assert.That(measured.All(m => m.Instrument == "tec.vault.cache.requests" && m.Value == 1)).IsTrue();
        var results = measured.Select(m => (string)m.Tags["vault.cache.result"]!).Order().ToList();
        await Assert.That(results).IsEquivalentTo(new[] { "hit", "miss" });
    }

    [Test]
    public async Task Circuit_instrument_records_state_and_provider()
    {
        string provider = "Circ-" + Guid.NewGuid().ToString("N");
        var measured = Capture(() => VaultDiagnostics.RecordCircuitState(provider, VaultDiagnostics.CircuitOpen), provider);

        var m = measured.Single();
        await Assert.That(m.Instrument).IsEqualTo("tec.vault.circuit.state_changes");
        await Assert.That(m.Value).IsEqualTo(1);
        await Assert.That(m.Tags["vault.circuit.state"]).IsEqualTo("open");
        await Assert.That(m.Tags["vault.provider"]).IsEqualTo(provider);
        await Assert.That(m.Tags.Count).IsEqualTo(2);
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
