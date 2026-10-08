using System.Diagnostics;
using System.Globalization;
using Microsoft.Extensions.Configuration;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.LoadGenerator;

namespace TEC.Vault.LoadTests;

/// <summary>
/// Performance dos caminhos quentes, medida em execução única e sequencial: custo e alocação da leitura em cache, recusa de
/// entrada inválida (sem tocar no cofre), leituras da chave pública por operação de criptografia e carga paralela do
/// <c>IConfiguration</c>. Os limites são ordens de grandeza acima do medido: pegam regressões (ex.: cache que deixou de
/// acertar, cliente de criptografia recriado a cada chamada, carga que voltou a ser sequencial), não variações do runner.
/// </summary>
[NotInParallel("load")]
public class PerformanceTests
{
    private static readonly CultureInfo Ci = CultureInfo.InvariantCulture;

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public async Task Cached_read_is_synchronous_fast_and_allocates_little()
    {
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated, secrets: 1);
        target.EnableCache(TimeSpan.FromMinutes(10));
        string name = target.SecretNames[0];
        await target.Reader.GetSecretAsync(name);   // aquece: a primeira leitura vai ao cofre

        const int iterations = 100_000;
        int synchronous = 0;
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < iterations; i++)
        {
            var task = target.Reader.GetSecretAsync(name);
            if (task.IsCompletedSuccessfully)
                synchronous++;
            if (task.GetAwaiter().GetResult().IsFailure)
                throw new InvalidOperationException("Leitura em cache falhou.");
        }

        double microseconds = Stopwatch.GetElapsedTime(start).TotalMicroseconds / iterations;
        double bytes = (double)(GC.GetAllocatedBytesForCurrentThread() - allocatedBefore) / iterations;
        LoadTestSettings.Publish("Performance · leitura em cache",
            string.Create(Ci, $"{iterations} leituras · {microseconds:F2} µs/leitura · {bytes:F0} bytes alocados/leitura · síncronas: {synchronous}"));

        await Assert.That(synchronous).IsEqualTo(iterations);           // acerto no cache não passa por I/O nem troca de thread
        await Assert.That(microseconds).IsLessThan(50);
        await Assert.That(bytes).IsLessThan(1_024);
        await Assert.That(target.Simulated!.Requests.GetValueOrDefault("GET secret")).IsEqualTo(1);
    }

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public async Task Invalid_input_is_rejected_in_linear_time_without_calling_vault()
    {
        // Nomes hostis de até 1 MB: a validação (regex ancorada, sem retrocesso) recusa em tempo proporcional ao tamanho,
        // sem chegar ao SDK nem ao cofre
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated, secrets: 1);
        target.Simulated!.ResetCounters();
        string[] hostile =
        [
            new string('a', 1_000_000),
            string.Concat(Enumerable.Repeat("a-", 500_000)) + "!",
            "../" + new string('-', 100_000),
            new string('a', 127) + "\n"
        ];

        long start = Stopwatch.GetTimestamp();
        const int rounds = 50;
        for (int i = 0; i < rounds; i++)
        {
            foreach (string name in hostile)
            {
                var result = await target.Secrets.GetSecretAsync(name);
                if (result.Error?.Code != VaultErrors.InvalidInputCode)
                    throw new InvalidOperationException("Entrada hostil não foi recusada na validação.");
            }
        }

        double milliseconds = Stopwatch.GetElapsedTime(start).TotalMilliseconds / (rounds * hostile.Length);
        LoadTestSettings.Publish("Performance · recusa de entrada hostil (até 1 MB)",
            string.Create(Ci, $"{rounds * hostile.Length} recusas · {milliseconds:F3} ms/recusa"));

        await Assert.That(milliseconds).IsLessThan(20);
        await Assert.That(target.Simulated.TotalRequests).IsEqualTo(0);
    }

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public async Task Encryption_with_version_reads_public_key_once()
    {
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated, secrets: 1);
        var envelope = VaultScenarios.Envelope(target);
        var random = new Random(2026);

        const int operations = 500;
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < operations; i++)
        {
            if (await envelope.Execute(random, CancellationToken.None) is { } error)
                throw new InvalidOperationException($"Envelope falhou: {error}.");
        }

        double milliseconds = Stopwatch.GetElapsedTime(start).TotalMilliseconds / operations;
        long keyReads = target.Simulated!.Requests.GetValueOrDefault("GET key");
        long unwraps = target.Simulated.Requests.GetValueOrDefault("POST unwrapkey");
        LoadTestSettings.Publish("Performance · envelope sequencial com versão",
            string.Create(Ci, $"{operations} envelopes · {milliseconds:F2} ms/envelope · leituras da chave: {keyReads} · unwraps remotos: {unwraps}"));

        await Assert.That(keyReads).IsEqualTo(1);        // wrap local com a chave pública em cache no cliente
        await Assert.That(unwraps).IsEqualTo(operations);  // unwrap sempre no cofre (a chave privada não sai)
    }

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public async Task IConfiguration_load_reads_in_parallel()
    {
        // 100 segredos com o cofre levando 20 ms cada: sequencial seriam >= 2 s; com MaxConcurrentReads = 8, bem menos
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated, secrets: 100);
        target.Simulated!.Latency = TimeSpan.FromMilliseconds(20);
        target.Simulated.ResetCounters();

        long start = Stopwatch.GetTimestamp();
        var configuration = new ConfigurationBuilder()
            .AddTecVault(target.Secrets, o =>
            {
                o.Prefix = target.Prefix;
                o.MaxConcurrentReads = 8;
            })
            .Build();
        var elapsed = Stopwatch.GetElapsedTime(start);
        int loaded = configuration.AsEnumerable().Count(e => e.Value is not null);
        LoadTestSettings.Publish("Performance · carga do IConfiguration (100 segredos, cofre com 20 ms, 8 leituras simultâneas)",
            string.Create(Ci, $"{loaded} chaves em {elapsed.TotalMilliseconds:F0} ms · requisições: {target.Simulated.TotalRequests}"));

        await Assert.That(loaded).IsEqualTo(100);
        await Assert.That(elapsed).IsLessThan(TimeSpan.FromMilliseconds(100 * 20 / 2));
        (configuration as IDisposable)?.Dispose();
    }

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public async Task Memory_is_stable_under_continuous_cached_reads()
    {
        // Leituras contínuas em cache não podem acumular memória (ex.: entradas em andamento nunca removidas)
        // Sem o LoadRunner (que guarda amostras de latência): só o cache e o provedor ocupam memória entre as medições
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated, secrets: 200);
        target.EnableCache(TimeSpan.FromSeconds(1));   // expira durante a execução: força releituras e substituições

        async Task<long> ReadAsync(TimeSpan duration)
        {
            long reads = 0;
            var stopAt = Stopwatch.GetTimestamp() + (long)(duration.TotalSeconds * Stopwatch.Frequency);
            await Task.WhenAll(Enumerable.Range(0, 32).Select(worker => Task.Run(async () =>
            {
                var random = new Random(worker);
                for (long i = 1; Stopwatch.GetTimestamp() < stopAt; i++)
                {
                    if (i % 64 == 0)
                        await Task.Yield();
                    var result = await target.Reader.GetSecretAsync(target.SecretNames[random.Next(target.SecretNames.Count)]);
                    if (result.IsFailure)
                        throw new InvalidOperationException(result.Error!.Code);
                    Interlocked.Increment(ref reads);
                }
            })));
            return reads;
        }

        await ReadAsync(TimeSpan.FromSeconds(2));       // aquece: cache cheio, JIT, pools
        long baseline = HeapAfterFullCollection();
        long total = await ReadAsync(LoadTestSettings.Duration(5));
        long after = HeapAfterFullCollection();
        double growthMb = (after - baseline) / (1024.0 * 1024.0);
        LoadTestSettings.Publish("Performance · memória após leituras contínuas com cache (expiração de 1 s)",
            string.Create(Ci, $"{total} leituras · heap: {baseline / 1024.0 / 1024.0:F1} MB → {after / 1024.0 / 1024.0:F1} MB ({growthMb:+0.0;-0.0} MB) · entradas no cache: {target.Cache!.Count}"));

        await Assert.That(growthMb).IsLessThan(16);
        await Assert.That(target.Cache.Count).IsLessThanOrEqualTo(target.SecretNames.Count);
    }

    private static long HeapAfterFullCollection()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        return GC.GetTotalMemory(forceFullCollection: false);
    }
}
