using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Diagnostics.Tracing;
using System.Net;
using System.Text;
using Azure.Core.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Caching;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.Diagnostics;
using TEC.Vault.Keys;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>
/// Vazamento de valores sob concorrência e com falhas injetadas (throttling, 5xx, 403 com mensagem ecoando o valor, rede
/// caindo, cancelamentos): o valor de um segredo e o texto puro de uma criptografia nunca aparecem em logs do componente,
/// eventos do SDK do Azure, traces, métricas, mensagens de erro ou exceções.
/// </summary>
[NotInParallel("eventos-do-sdk")]
public class LeakUnderLoadTests
{
    private const string Canary = "CANARIO-CARGA-a71f3c";

    [Test]
    public async Task Values_do_not_leak_in_any_channel_under_load_with_failures()
    {
        var sinks = new Sinks();
        using var _ = sinks.Listen();
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));

        int calls = 0;
        var vault = new FakeKeyVault((request, body) =>
        {
            int n = Interlocked.Increment(ref calls);
            return (n % 10) switch
            {
                // Falhas cujo corpo ecoa o valor: o texto da resposta nunca pode ir para log/erro
                0 => (HttpStatusCode.TooManyRequests, FakeKeyVault.ErrorJson("Throttled", $"Rate limit; payload={Canary}")),
                1 => (HttpStatusCode.InternalServerError, FakeKeyVault.ErrorJson("InternalError", $"Falha ao gravar {Canary}")),
                2 => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", $"Valor {Canary} recusado", "ForbiddenByPolicy")),
                // Falhas de transporte (o HttpClient real nunca põe o corpo da requisição na mensagem da exceção)
                3 => throw new HttpRequestException("Conexão encerrada pelo servidor."),
                4 => throw new IOException("Fluxo cortado."),
                _ => request.Method == HttpMethod.Put
                    ? (HttpStatusCode.OK, FakeKeyVault.SecretJson("s", Canary + "-gravado"))
                    : (HttpStatusCode.OK, FakeKeyVault.SecretJson("s", Canary + "-lido"))
            };
        });
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());
        using var cache = new CachingSecretReader(store, TimeSpan.FromMilliseconds(50));

        var outcomes = new ConcurrentBag<string>();
        await Task.WhenAll(Enumerable.Range(0, 16).Select(worker => Task.Run(async () =>
        {
            var random = new Random(worker);
            for (int i = 0; i < 150; i++)
            {
                using var cancellation = new CancellationTokenSource();
                if (random.Next(10) == 0)
                    cancellation.CancelAfter(TimeSpan.FromTicks(random.Next(1, 5_000)));
                try
                {
                    Result result = random.Next(3) switch
                    {
                        0 => await store.SetSecretAsync($"s{random.Next(4)}", $"{Canary}-{worker}-{i}", cancellationToken: cancellation.Token),
                        1 => await cache.GetSecretAsync($"s{random.Next(4)}", cancellationToken: cancellation.Token),
                        _ => await store.GetSecretAsync($"s{random.Next(4)}", cancellationToken: cancellation.Token)
                    };
                    outcomes.Add(Describe(result));
                }
                catch (OperationCanceledException ex)
                {
                    outcomes.Add(ex.ToString());
                }
            }
        })));

        // Também o IConfiguration (carga com falhas e recarga) e a criptografia
        var configuration = new ConfigurationBuilder().AddTecVault(cache, o => o.Optional = true, loggerFactory: factory).Build();
        outcomes.Add(string.Join('\n', configuration.AsEnumerable().Select(e => e.Key)));
        (configuration as IDisposable)?.Dispose();

        var keys = await Memory.KeysWithKekAsync();
        byte[] plaintext = Encoding.UTF8.GetBytes(Canary);
        var envelope = await keys.EncryptEnvelopeAsync("kek", plaintext, "ctx"u8.ToArray());
        var wrongContext = await keys.DecryptEnvelopeAsync(envelope.Value, "outro"u8.ToArray());
        outcomes.Add(envelope.Value.ToString() + Describe(wrongContext));

        await Assert.That(outcomes.Count).IsGreaterThan(16 * 150);
        await Assert.That(logs.Entries).IsNotEmpty();
        await Assert.That(sinks.Activities).IsNotEmpty();
        await Assert.That(sinks.Measurements).IsNotEmpty();
        await Assert.That(logs.AllText).DoesNotContain(Canary);
        await Assert.That(sinks.SdkEvents.ToArray().Any(e => e.Contains(Canary, StringComparison.Ordinal))).IsFalse();
        await Assert.That(sinks.Activities.ToArray().Any(e => e.Contains(Canary, StringComparison.Ordinal))).IsFalse();
        await Assert.That(sinks.Measurements.ToArray().Any(e => e.Contains(Canary, StringComparison.Ordinal))).IsFalse();
        await Assert.That(outcomes.ToArray().Any(e => e.Contains(Canary, StringComparison.Ordinal))).IsFalse();
    }

    private static string Describe(Result result) =>
        result.IsSuccess
            ? result.ToString() ?? string.Empty
            : $"{result.Error!.Code} {result.Error.Message} {result.Error.Field} {result.Error}";

    /// <summary>Coleta tudo o que sai do processo além do log: eventos do SDK do Azure, activities e medições.</summary>
    private sealed class Sinks
    {
        public ConcurrentQueue<string> SdkEvents { get; } = new();
        public ConcurrentQueue<string> Activities { get; } = new();
        public ConcurrentQueue<string> Measurements { get; } = new();

        public IDisposable Listen()
        {
            // Eventos do Azure.Core (requisição, resposta, retentativas), no nível mais detalhado
            var sdk = new AzureEventSourceListener((e, message) => SdkEvents.Enqueue(message + " " + string.Join(" ", e.Payload ?? (IEnumerable<object?>)Array.Empty<object?>())),
                EventLevel.Verbose);

            var activities = new ActivityListener
            {
                ShouldListenTo = source => source.Name.StartsWith("TEC.", StringComparison.Ordinal) || source.Name.StartsWith("Azure", StringComparison.Ordinal),
                Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
                ActivityStopped = a => Activities.Enqueue($"{a.DisplayName} {a.StatusDescription} " +
                    string.Join(' ', a.TagObjects.Select(t => $"{t.Key}={t.Value}")) + " " +
                    string.Join(' ', a.Events.Select(e => e.Name + string.Join(' ', e.Tags.Select(t => $"{t.Key}={t.Value}")))))
            };
            ActivitySource.AddActivityListener(activities);

            var meters = new MeterListener
            {
                InstrumentPublished = (instrument, listener) =>
                {
                    if (instrument.Meter.Name == VaultDiagnostics.MeterName)
                        listener.EnableMeasurementEvents(instrument);
                }
            };
            meters.SetMeasurementEventCallback<double>((i, v, tags, _) => Measurements.Enqueue(Format(i, tags)));
            meters.SetMeasurementEventCallback<long>((i, v, tags, _) => Measurements.Enqueue(Format(i, tags)));
            meters.Start();

            return new Composite(sdk, activities, meters);
        }

        private static string Format(Instrument instrument, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var text = new StringBuilder(instrument.Name);
            foreach (var tag in tags)
                text.Append(' ').Append(tag.Key).Append('=').Append(tag.Value);
            return text.ToString();
        }

        private sealed class Composite(params IDisposable[] items) : IDisposable
        {
            public void Dispose()
            {
                foreach (var item in items)
                    item.Dispose();
            }
        }
    }
}
