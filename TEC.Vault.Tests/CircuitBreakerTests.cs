using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HashiCorpVault;
using TEC.Vault.Providers;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

public class CircuitBreakerTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static void Sensitive(VaultCircuitBreakerOptions options)
    {
        options.MinimumThroughput = 2;
        options.FailureRatio = 0.5;
        options.BreakDuration = TimeSpan.FromSeconds(30);
    }

    [Test]
    public async Task Repeated_unavailability_opens_circuit_and_rejects_without_calling_vault()
    {
        var time = new FixedTimeProvider(Start);
        var status = HttpStatusCode.ServiceUnavailable;
        var vault = new FakeKeyVault((_, _) => status == HttpStatusCode.OK
            ? (HttpStatusCode.OK, FakeKeyVault.SecretJson("db", "valor"))
            : (status, FakeKeyVault.ErrorJson("ServiceUnavailable", "x")));
        var clients = vault.CreateClients(configure: o =>
        {
            o.TimeProvider = time;
            Sensitive(o.CircuitBreaker);
        });
        var logs = new CapturingLoggerProvider();
        var secrets = new AzureKeyVaultSecretStore(clients, new Logger<AzureKeyVaultSecretStore>(new LoggerFactory([logs])));
        var keys = new AzureKeyVaultKeyStore(clients);

        await Assert.That((await secrets.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That((await secrets.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(clients.CircuitBreaker!.IsOpen).IsTrue();

        int requests = vault.Requests.Count;
        await Assert.That((await secrets.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.CircuitOpenCode);
        // O circuito é do cofre, não do store: chaves do mesmo cofre também param
        await Assert.That((await keys.GetKeyAsync("k")).Error!.Code).IsEqualTo(VaultErrors.CircuitOpenCode);
        await Assert.That(vault.Requests.Count).IsEqualTo(requests);
        await Assert.That(logs.AllText).Contains("circuito aberto");

        // Fim da pausa: chamada de teste com o cofre de volta fecha o circuito
        status = HttpStatusCode.OK;
        time.Now = Start.AddSeconds(31);
        await Assert.That((await secrets.GetSecretAsync("db")).Value.Value).IsEqualTo("valor");
        await Assert.That(clients.CircuitBreaker.IsOpen).IsFalse();
        await Assert.That((await secrets.GetSecretAsync("db")).IsSuccess).IsTrue();
        await Assert.That(logs.AllText).Contains("circuito fechado");
    }

    /// <summary>Provedor mínimo: a chamada é o delegate do teste.</summary>
    private sealed class ScriptedProvider(VaultCircuitBreaker circuit) : VaultProviderBase("Scripted", Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, circuit)
    {
        public Task<TEC.Core.Common.Results.Result<int>> CallAsync(Func<CancellationToken, Task<TEC.Core.Common.Results.Result<int>>> call,
            CancellationToken cancellationToken = default) =>
            ExecuteAsync("teste.get", "x", null, isWrite: false, call, cancellationToken);

        protected override VaultFailure? MapException(Exception exception) => null;
    }

    private static (ScriptedProvider Provider, VaultCircuitBreaker Circuit, FixedTimeProvider Time) OpenScripted()
    {
        var time = new FixedTimeProvider(Start);
        var options = new VaultCircuitBreakerOptions();
        Sensitive(options);
        var circuit = new VaultCircuitBreaker("Scripted", options, time);
        return (new ScriptedProvider(circuit), circuit, time);
    }

    [Test]
    [Arguments("cancelada")]
    [Arguments("inesperada")]
    public async Task Probe_without_vault_answer_keeps_circuit_open(string kind)
    {
        var (provider, circuit, time) = OpenScripted();
        for (int i = 0; i < 2; i++)
            await provider.CallAsync(_ => Task.FromResult(TEC.Core.Common.Results.Result<int>.Failure(VaultErrors.Unavailable())));
        await Assert.That(circuit.IsOpen).IsTrue();

        time.Now = Start.AddSeconds(31);
        if (kind == "cancelada")
        {
            using var cts = new CancellationTokenSource();
            await Assert.That(async () => await provider.CallAsync(ct =>
            {
                cts.Cancel();
                ct.ThrowIfCancellationRequested();
                return Task.FromResult(TEC.Core.Common.Results.Result<int>.Success(1));
            }, cts.Token)).Throws<OperationCanceledException>();
        }
        else
        {
            var result = await provider.CallAsync(_ => throw new InvalidOperationException("bug"));
            await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
        }

        // A chamada de teste não teve resposta do cofre: o circuito volta a abrir
        await Assert.That(circuit.IsOpen).IsTrue();
        var next = await provider.CallAsync(_ => Task.FromResult(TEC.Core.Common.Results.Result<int>.Success(1)));
        await Assert.That(next.Error!.Code).IsEqualTo(VaultErrors.CircuitOpenCode);
    }

    [Test]
    public async Task Probe_answered_by_vault_closes_circuit_even_with_item_error()
    {
        var (provider, circuit, time) = OpenScripted();
        for (int i = 0; i < 2; i++)
            await provider.CallAsync(_ => Task.FromResult(TEC.Core.Common.Results.Result<int>.Failure(VaultErrors.Unavailable())));

        time.Now = Start.AddSeconds(31);
        var probe = await provider.CallAsync(_ => Task.FromResult(TEC.Core.Common.Results.Result<int>.Failure(VaultErrors.NotFound())));

        await Assert.That(probe.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That(circuit.IsOpen).IsFalse();
    }

    [Test]
    public async Task Failed_probe_after_break_reopens_circuit()
    {
        var time = new FixedTimeProvider(Start);
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.ServiceUnavailable, FakeKeyVault.ErrorJson("ServiceUnavailable", "x")));
        var clients = vault.CreateClients(configure: o =>
        {
            o.TimeProvider = time;
            Sensitive(o.CircuitBreaker);
        });
        var secrets = new AzureKeyVaultSecretStore(clients);
        await secrets.GetSecretAsync("db");
        await secrets.GetSecretAsync("db");

        time.Now = Start.AddSeconds(31);
        await Assert.That((await secrets.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That((await secrets.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.CircuitOpenCode);
    }

    [Test]
    [Arguments(HttpStatusCode.NotFound, "SecretNotFound", VaultErrors.NotFoundCode)]
    [Arguments(HttpStatusCode.Forbidden, "ForbiddenByRbac", VaultErrors.AccessDeniedCode)]
    public async Task Item_and_permission_errors_never_open_circuit(HttpStatusCode status, string code, string expected)
    {
        var vault = new FakeKeyVault((_, _) => (status, FakeKeyVault.ErrorJson(code, "x")));
        var clients = vault.CreateClients(configure: o => Sensitive(o.CircuitBreaker));
        var secrets = new AzureKeyVaultSecretStore(clients);

        for (int i = 0; i < 20; i++)
            await Assert.That((await secrets.GetSecretAsync("db")).Error!.Code).IsEqualTo(expected);
        await Assert.That(clients.CircuitBreaker!.IsOpen).IsFalse();
    }

    [Test]
    public async Task Invalid_input_is_not_counted_and_does_not_reach_circuit()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.ServiceUnavailable, FakeKeyVault.ErrorJson("ServiceUnavailable", "x")));
        var clients = vault.CreateClients(configure: o => Sensitive(o.CircuitBreaker));
        var secrets = new AzureKeyVaultSecretStore(clients);

        for (int i = 0; i < 10; i++)
            await Assert.That((await secrets.GetSecretAsync("nome inválido")).Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(clients.CircuitBreaker!.IsOpen).IsFalse();
    }

    [Test]
    public async Task Disabled_circuit_keeps_calling_vault()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.ServiceUnavailable, FakeKeyVault.ErrorJson("ServiceUnavailable", "x")));
        var clients = vault.CreateClients(configure: o => o.CircuitBreaker.Enabled = false);
        var secrets = new AzureKeyVaultSecretStore(clients);

        for (int i = 0; i < 20; i++)
            await Assert.That((await secrets.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(clients.CircuitBreaker).IsNull();
    }

    [Test]
    public async Task Http_provider_opens_circuit_after_retries_are_exhausted()
    {
        var folder = Directory.CreateTempSubdirectory("tec-vault-cb").FullName;
        try
        {
            var fake = new FakeHashiCorpVault();
            var options = HashiCorpTestOptions.Create(fake, folder, o =>
            {
                o.Http.MaxRetries = 0;
                Sensitive(o.Http.CircuitBreaker);
            });
            using var store = new HashiCorpVaultSecretStore(options);
            await store.SetSecretAsync("db", "x");
            fake.Failures.Enqueue(HttpStatusCode.ServiceUnavailable);

            // Janela com 1 sucesso (a gravação) e 1 falha: 50% abre o circuito
            await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
            int requests = fake.Requests.Count;
            await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.CircuitOpenCode);
            await Assert.That(fake.Requests.Count).IsEqualTo(requests);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Test]
    public async Task Options_are_read_from_configuration()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["P:CircuitBreaker:Enabled"] = "true",
            ["P:CircuitBreaker:FailureRatio"] = "0.25",
            ["P:CircuitBreaker:MinimumThroughput"] = "4",
            ["P:CircuitBreaker:SamplingDuration"] = "00:01:00",
            ["P:CircuitBreaker:BreakDuration"] = "00:00:10"
        }).Build();
        var settings = new VaultSettings(configuration.GetSection("P"));
        var options = new VaultCircuitBreakerOptions();

        options.Read(settings);
        settings.EnsureNoUnknownKeys();

        await Assert.That(options.FailureRatio).IsEqualTo(0.25);
        await Assert.That(options.MinimumThroughput).IsEqualTo(4);
        await Assert.That(options.SamplingDuration).IsEqualTo(TimeSpan.FromMinutes(1));
        await Assert.That(options.BreakDuration).IsEqualTo(TimeSpan.FromSeconds(10));
    }

    [Test]
    [Arguments("FailureRatio", "1.5")]
    [Arguments("FailureRatio", "abc")]
    [Arguments("MinimumThroughput", "1")]
    [Arguments("Thresold", "3")]
    public async Task Invalid_configuration_fails_at_startup(string key, string value)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["P:CircuitBreaker:" + key] = value
        }).Build();
        var settings = new VaultSettings(configuration.GetSection("P"));

        await Assert.That(() =>
        {
            new VaultCircuitBreakerOptions().Read(settings);
            settings.EnsureNoUnknownKeys();
        }).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(0.0, 10, 30, 30)]
    [Arguments(0.5, 1, 30, 30)]
    [Arguments(0.5, 10, 0.1, 30)]
    [Arguments(0.5, 10, 30, 7200)]
    public async Task Out_of_range_options_are_rejected(double ratio, int throughput, double samplingSeconds, double breakSeconds)
    {
        var options = new VaultCircuitBreakerOptions
        {
            FailureRatio = ratio,
            MinimumThroughput = throughput,
            SamplingDuration = TimeSpan.FromSeconds(samplingSeconds),
            BreakDuration = TimeSpan.FromSeconds(breakSeconds)
        };

        await Assert.That(() => options.Validate("X")).Throws<InvalidOperationException>();
        options.Enabled = false;
        options.Validate("X");
        await Assert.That(VaultCircuitBreaker.Create("P", options, null, "X")).IsNull();
    }
}
