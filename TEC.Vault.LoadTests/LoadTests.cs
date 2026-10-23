using System.Globalization;
using System.Net;
using TEC.Vault.Common;
using TEC.Vault.LoadGenerator;

namespace TEC.Vault.LoadTests;

/// <summary>
/// Carga em malha fechada sobre os provedores: correção sob concorrência (zero erros, nenhum conteúdo divergente), proteção do
/// cofre (coalescência do cache contra stampede), escalabilidade (sem serialização escondida) e classificação de falhas sob
/// throttling. Limites folgados: o objetivo é pegar regressões grosseiras, não medir o hardware do runner.
/// </summary>
/// <remarks>
/// Cada cenário roda em duas categorias: <see cref="TestCategories.LoadCi"/> (segundos, só as asserções de correção, em todo
/// pull request) e <see cref="TestCategories.LoadHeavy"/> (cerca de 3 minutos por cenário com <c>TEC_CARGA_FATOR=1</c>,
/// também com os limites de vazão e latência).
/// </remarks>
[NotInParallel("load")]
public class LoadTests
{
    private static readonly CultureInfo Ci = CultureInfo.InvariantCulture;

    // ---------------------------------------------------------------- Carga-CI

    [Test]
    [Category(TestCategories.LoadCi)]
    public Task InMemory_full_mix_has_no_errors() => InMemoryMixAsync(seconds: 3, measure: false);

    [Test]
    [Category(TestCategories.LoadCi)]
    public Task Simulated_azure_full_mix_has_no_errors() => SimulatedMixAsync(seconds: 3, measure: false);

    [Test]
    [Category(TestCategories.LoadCi)]
    public Task Cache_absorbs_read_burst_with_one_call_per_secret() => CacheBurstAsync(seconds: 3);

    [Test]
    [Category(TestCategories.LoadCi)]
    public Task Throughput_scales_with_concurrency_when_vault_is_slow() => ScalingAsync(seconds: 2);

    [Test]
    [Category(TestCategories.LoadCi)]
    public Task Concurrent_cryptography_does_not_corrupt_and_reuses_key_client() => CryptographyAsync(seconds: 3);

    [Test]
    [Category(TestCategories.LoadCi)]
    [Arguments(HttpStatusCode.TooManyRequests, VaultErrors.ThrottledCode)]
    [Arguments(HttpStatusCode.ServiceUnavailable, VaultErrors.UnavailableCode)]
    public Task Vault_failures_under_load_become_known_codes_without_exceptions(HttpStatusCode status, string expectedCode) =>
        FaultsAsync(status, expectedCode, seconds: 3);

    // ---------------------------------------------------------------- Carga-Pesada

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public Task InMemory_full_mix_sustained() => InMemoryMixAsync(seconds: 180, measure: true);

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public Task Simulated_azure_full_mix_sustained() => SimulatedMixAsync(seconds: 180, measure: true);

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public Task Cache_absorbs_sustained_read_burst() => CacheBurstAsync(seconds: 60);

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public Task Throughput_scaling_sustained() => ScalingAsync(seconds: 30);

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public Task Concurrent_cryptography_sustained() => CryptographyAsync(seconds: 120);

    [Test]
    [Category(TestCategories.LoadHeavy)]
    [Arguments(HttpStatusCode.TooManyRequests, VaultErrors.ThrottledCode)]
    [Arguments(HttpStatusCode.ServiceUnavailable, VaultErrors.UnavailableCode)]
    public Task Vault_failures_under_sustained_load(HttpStatusCode status, string expectedCode) =>
        FaultsAsync(status, expectedCode, seconds: 60);

    [Test]
    [Category(TestCategories.LoadHeavy)]
    public async Task Real_test_vault_with_rate_limit()
    {
        // Só com o cofre de testes configurado (TEC_TESTES_VAULT_URI); sem ele o teste se pula com o motivo. Taxa limitada a
        // 20 ops/s: longe do limite de throttling do Key Vault, mede latência ponta a ponta e confirma zero erros com o serviço real
        var vaultUri = LoadTestSettings.RequireVault();
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Azure, secrets: 10, vaultUri, LoadTestSettings.TenantId);

        var report = await LoadRunner.RunAsync(new LoadOptions
        {
            Concurrency = 4,
            Duration = LoadTestSettings.Duration(60),
            WarmUp = TimeSpan.FromSeconds(3),
            MaxOperationsPerSecond = 20,
            Scenarios = [VaultScenarios.ReadSecret(target, 8), VaultScenarios.Envelope(target, 1), VaultScenarios.SignVerify(target, 1)]
        });
        LoadTestSettings.Publish("Key Vault de testes real · 4 workers · até 20 ops/s", report);

        // Throttling eventual do serviço é tolerado (e classificado); qualquer outro erro, não
        await Assert.That(report.ErrorsByKind.Keys.All(k => k == VaultErrors.ThrottledCode)).IsTrue();
        await Assert.That(report.ErrorRate).IsLessThan(0.01);
        await Assert.That(report.Scenario("ler segredo").Latency.P95).IsLessThan(2_000);
    }

    // ---------------------------------------------------------------- Cenários

    private static async Task InMemoryMixAsync(double seconds, bool measure)
    {
        await using var target = await VaultTarget.CreateAsync(VaultBackend.InMemory);

        var report = await LoadRunner.RunAsync(new LoadOptions
        {
            Concurrency = 32,
            Duration = LoadTestSettings.Duration(seconds),
            WarmUp = TimeSpan.FromSeconds(measure ? 2 : 0.5),
            Scenarios = VaultScenarios.Mix("misto", target)
        });
        LoadTestSettings.Publish("Em memória · mistura completa · 32 workers", report);

        await Assert.That(report.Errors).IsEqualTo(0);
        if (measure)
        {
            await Assert.That(report.OperationsPerSecond).IsGreaterThan(1_000);
            await Assert.That(report.Scenario("ler segredo").Latency.P99).IsLessThan(50);
        }
    }

    private static async Task SimulatedMixAsync(double seconds, bool measure)
    {
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated);

        var report = await LoadRunner.RunAsync(new LoadOptions
        {
            Concurrency = 32,
            Duration = LoadTestSettings.Duration(seconds),
            WarmUp = TimeSpan.FromSeconds(measure ? 2 : 0.5),
            Scenarios = VaultScenarios.Mix("misto", target)
        });
        LoadTestSettings.Publish("Azure (SDK real, cofre simulado) · mistura completa · 32 workers", report,
            $"Requisições ao cofre: {target.Simulated!.TotalRequests}");

        await Assert.That(report.Errors).IsEqualTo(0);
        if (measure)
        {
            await Assert.That(report.OperationsPerSecond).IsGreaterThan(500);
            await Assert.That(report.Scenario("ler segredo").Latency.P99).IsLessThan(100);
        }
    }

    private static async Task CacheBurstAsync(double seconds)
    {
        // Stampede: 128 workers lendo 20 segredos com o cofre lento (10 ms). Com cache e coalescência, cada segredo é lido
        // do cofre uma única vez durante toda a execução, por maior que seja a concorrência
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated, secrets: 20);
        target.EnableCache(TimeSpan.FromMinutes(10));
        target.Simulated!.Latency = TimeSpan.FromMilliseconds(10);

        var report = await LoadRunner.RunAsync(new LoadOptions
        {
            Concurrency = 128,
            Duration = LoadTestSettings.Duration(seconds),
            WarmUp = TimeSpan.Zero,
            Scenarios = VaultScenarios.Mix("leitura", target)
        });
        long reads = target.Simulated.Requests.GetValueOrDefault("GET secret");
        LoadTestSettings.Publish("Cache · rajada de 128 workers sobre 20 segredos (cofre com 10 ms)", report,
            $"Leituras que chegaram ao cofre: {reads}");

        await Assert.That(report.Errors).IsEqualTo(0);
        await Assert.That(reads).IsLessThanOrEqualTo(20);
        await Assert.That(report.Operations).IsGreaterThan(reads * 100);
    }

    private static async Task ScalingAsync(double seconds)
    {
        // Com o cofre levando ~20 ms por requisição, 64 workers têm de render bem mais que 1: uma trava ou um recurso
        // compartilhado serializando as chamadas (pool de conexões, lock no provedor) apareceria aqui
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated);
        target.Simulated!.Latency = TimeSpan.FromMilliseconds(20);

        async Task<LoadReport> RunAsync(int concurrency) => await LoadRunner.RunAsync(new LoadOptions
        {
            Concurrency = concurrency,
            Duration = LoadTestSettings.Duration(seconds),
            WarmUp = TimeSpan.FromSeconds(1),
            Scenarios = VaultScenarios.Mix("leitura", target)
        });

        var single = await RunAsync(1);
        var parallel = await RunAsync(64);
        double speedup = parallel.OperationsPerSecond / Math.Max(single.OperationsPerSecond, 1);
        LoadTestSettings.Publish("Escalabilidade · cofre com 20 ms · 1 × 64 workers", parallel,
            string.Create(Ci, $"1 worker: {single.OperationsPerSecond:F0} ops/s · 64 workers: {parallel.OperationsPerSecond:F0} ops/s · ganho: {speedup:F1}×"));

        await Assert.That(single.Errors + parallel.Errors).IsEqualTo(0);
        await Assert.That(speedup).IsGreaterThan(16);
    }

    private static async Task CryptographyAsync(double seconds)
    {
        // Envelope e assinatura em paralelo com versão informada: todo conteúdo decifrado/verificado confere, e a chave pública
        // é lida do cofre só na criação dos clientes de criptografia (reaproveitados por nome + versão), não a cada operação
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated);

        var report = await LoadRunner.RunAsync(new LoadOptions
        {
            Concurrency = 32,
            Duration = LoadTestSettings.Duration(seconds),
            WarmUp = TimeSpan.FromSeconds(1),
            Scenarios = VaultScenarios.Mix("cripto", target)
        });
        long keyReads = target.Simulated!.Requests.GetValueOrDefault("GET key");
        LoadTestSettings.Publish("Criptografia · envelope + assinatura · 32 workers", report, $"Leituras da chave pública: {keyReads}");

        await Assert.That(report.Errors).IsEqualTo(0);
        await Assert.That(report.ErrorsByKind.ContainsKey(VaultScenarios.MismatchError)).IsFalse();
        await Assert.That(keyReads).IsLessThanOrEqualTo(32);
    }

    private static async Task FaultsAsync(HttpStatusCode status, string expectedCode, double seconds)
    {
        // 10% das requisições falham: cada falha vira o código padronizado (nada de exceção escapando nem VAULT_FALHA genérico)
        // e as demais operações seguem normalmente
        await using var target = await VaultTarget.CreateAsync(VaultBackend.Simulated);
        target.Simulated!.FaultRate = 0.10;
        target.Simulated.FaultStatus = status;

        var report = await LoadRunner.RunAsync(new LoadOptions
        {
            Concurrency = 32,
            Duration = LoadTestSettings.Duration(seconds),
            WarmUp = TimeSpan.FromSeconds(1),
            Scenarios = VaultScenarios.Mix("leitura", target)
        });
        LoadTestSettings.Publish($"Falhas injetadas · 10% de HTTP {(int)status}", report);

        await Assert.That(report.ErrorsByKind.Keys.ToArray()).IsEquivalentTo(new[] { expectedCode });
        await Assert.That(report.ErrorRate).IsBetween(0.05, 0.15);
    }
}
