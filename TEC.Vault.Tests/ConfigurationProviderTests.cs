using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Provedor de <c>IConfiguration</c>: log de falhas, tempo limite, recarga incremental e leituras com paralelismo limitado.</summary>
public class ConfigurationProviderTests
{
    [Test]
    public async Task Initial_load_failure_is_logged_as_Error_with_code()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var store = new ScriptedSecretStore(Memory.Secrets()) { ListFailure = VaultErrors.AccessDenied() };

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecVault(store, loggerFactory: factory).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains(VaultErrors.AccessDeniedCode);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains(VaultErrors.AccessDeniedCode))).IsTrue();
    }

    [Test]
    public async Task MaxSecrets_overflow_is_logged_as_Error()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var store = Memory.Secrets();
        for (int i = 0; i < 3; i++)
            await store.SetSecretAsync($"s{i}", "v");

        await Assert.That(() => new ConfigurationBuilder().AddTecVault(store, o => o.MaxSecrets = 2, loggerFactory: factory).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains("MaxSecrets") && e.Text.Contains('3'))).IsTrue();
    }

    [Test]
    public async Task Initial_load_respects_timeout()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var store = new ScriptedSecretStore(Memory.Secrets()) { BeforeList = ct => Task.Delay(Timeout.Infinite, ct) };

        var started = TimeProvider.System.GetTimestamp();
        await Assert.That(() => new ConfigurationBuilder()
                .AddTecVault(store, o => o.LoadTimeout = TimeSpan.FromMilliseconds(200), loggerFactory: factory).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains("tempo limite"))).IsTrue();
    }

    [Test]
    public async Task Initial_load_timeout_holds_when_reader_ignores_cancellation()
    {
        // Leitor que não respeita o CancellationToken: só a espera limitada do Load() impede a subida de travar
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var never = new TaskCompletionSource();
        var store = new ScriptedSecretStore(Memory.Secrets()) { BeforeList = _ => never.Task };

        var started = TimeProvider.System.GetTimestamp();
        await Assert.That(() => new ConfigurationBuilder()
                .AddTecVault(store, o => o.LoadTimeout = TimeSpan.FromMilliseconds(200), loggerFactory: factory).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That(logs.Entries.Count(e => e.Level == LogLevel.Error && e.Text.Contains("tempo limite"))).IsEqualTo(1);
        never.SetResult();
    }

    [Test]
    public async Task Timeout_with_Optional_starts_with_empty_configuration()
    {
        var store = new ScriptedSecretStore(Memory.Secrets()) { BeforeList = ct => Task.Delay(Timeout.Infinite, ct) };

        var configuration = new ConfigurationBuilder()
            .AddTecVault(store, o => { o.LoadTimeout = TimeSpan.FromMilliseconds(100); o.Optional = true; }).Build();

        await Assert.That(configuration.AsEnumerable()).IsEmpty();
    }

    [Test]
    public async Task Incremental_reload_rereads_only_changed_secrets()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        await memory.SetSecretAsync("B", "1");
        await memory.SetSecretAsync("C", "1");
        var configuration = new ConfigurationBuilder().AddTecVault(memory).Build();
        var provider = (VaultConfigurationProvider)configuration.Providers.Single();
        await Assert.That(memory.GetCalls).IsEqualTo(3);

        await memory.SetSecretAsync("B", "2");
        await provider.ReloadAsync();

        await Assert.That(memory.GetCalls).IsEqualTo(4);
        await Assert.That(configuration["A"]).IsEqualTo("1");
        await Assert.That(configuration["B"]).IsEqualTo("2");

        await provider.ReloadAsync();
        await Assert.That(memory.GetCalls).IsEqualTo(4);
    }

    [Test]
    public async Task Periodic_full_reload_rereads_all()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var configuration = new ConfigurationBuilder().AddTecVault(memory).Build();
        var provider = (VaultConfigurationProvider)configuration.Providers.Single();

        for (int i = 0; i < VaultConfigurationOptions.FullReloadEvery; i++)
            await provider.ReloadAsync();

        // 1 (carga inicial) + 1 (recarga completa); as incrementais não releem o segredo inalterado
        await Assert.That(memory.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Removed_secret_disappears_from_configuration_on_reload()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        await memory.SetSecretAsync("B", "1");
        var configuration = new ConfigurationBuilder().AddTecVault(memory).Build();
        var provider = (VaultConfigurationProvider)configuration.Providers.Single();

        await memory.DeleteSecretAsync("B");
        await provider.ReloadAsync();

        await Assert.That(configuration["A"]).IsEqualTo("1");
        await Assert.That(configuration["B"]).IsNull();
    }

    [Test]
    public async Task Reload_failure_keeps_values_and_is_logged()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var store = new ScriptedSecretStore(memory);
        var configuration = new ConfigurationBuilder().AddTecVault(store, loggerFactory: factory).Build();
        var provider = (VaultConfigurationProvider)configuration.Providers.Single();

        store.ListFailure = VaultErrors.Unavailable();
        await provider.ReloadAsync();

        await Assert.That(configuration["A"]).IsEqualTo("1");
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Warning && e.Text.Contains(VaultErrors.UnavailableCode))).IsTrue();
    }

    [Test]
    public async Task Reload_with_Optional_and_vault_down_keeps_loaded_secrets()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var store = new ScriptedSecretStore(memory);
        var configuration = new ConfigurationBuilder().AddTecVault(store, o => o.Optional = true, loggerFactory: factory).Build();
        await Assert.That(configuration["A"]).IsEqualTo("1");

        store.ListFailure = VaultErrors.Unavailable();
        configuration.Reload();                       // a falha mantém os valores carregados (não troca por vazio)

        await Assert.That(configuration["A"]).IsEqualTo("1");
        // Recarga manual que falha: aviso de recarga (evento 2101, valores mantidos), não erro de carga inicial (2100)
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Warning && e.Text.Contains("falha na recarga") && e.Text.Contains(VaultErrors.UnavailableCode))).IsTrue();

        store.ListFailure = null;
        await memory.SetSecretAsync("A", "2");
        configuration.Reload();                       // cofre de volta: a carga volta a valer

        await Assert.That(configuration["A"]).IsEqualTo("2");
    }

    [Test]
    public async Task Reload_without_Optional_and_vault_down_throws_and_keeps_values()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        await memory.SetSecretAsync("A", "1");
        var store = new ScriptedSecretStore(memory);
        var configuration = new ConfigurationBuilder().AddTecVault(store).Build();

        store.ListFailure = VaultErrors.Unavailable();

        await Assert.That(() => configuration.Reload()).Throws<InvalidOperationException>();
        await Assert.That(configuration["A"]).IsEqualTo("1");
    }

    [Test]
    public async Task Reads_respect_concurrency_limit()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        for (int i = 0; i < 12; i++)
            await memory.SetSecretAsync($"S{i}", "v");
        int current = 0, max = 0;
        var store = new ScriptedSecretStore(memory)
        {
            AfterGet = async (_, ct) =>
            {
                int now = Interlocked.Increment(ref current);
                int seen;
                while (now > (seen = Volatile.Read(ref max)) && Interlocked.CompareExchange(ref max, now, seen) != seen)
                {
                }

                await Task.Delay(20, ct);
                Interlocked.Decrement(ref current);
            }
        };

        var configuration = new ConfigurationBuilder().AddTecVault(store, o => o.MaxConcurrentReads = 2).Build();

        await Assert.That(configuration.AsEnumerable().Count()).IsEqualTo(12);
        await Assert.That(max).IsLessThanOrEqualTo(2);
        await Assert.That(max).IsGreaterThanOrEqualTo(1);
    }

    [Test]
    public async Task Failure_in_one_read_fails_the_load()
    {
        var memory = new ScriptedSecretStore(Memory.Secrets());
        for (int i = 0; i < 6; i++)
            await memory.SetSecretAsync($"S{i}", "v");
        var store = new ScriptedSecretStore(memory) { GetFailure = name => name == "S3" ? VaultErrors.Throttled() : null };

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecVault(store).Build()).Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains(VaultErrors.ThrottledCode);
    }

    [Test]
    [Arguments(0)]
    [Arguments(17)]
    public async Task MaxConcurrentReads_out_of_range_is_rejected(int value) =>
        await Assert.That(() => new VaultConfigurationOptions { MaxConcurrentReads = value }).Throws<ArgumentOutOfRangeException>();

    [Test]
    public async Task Invalid_LoadTimeout_is_rejected() =>
        await Assert.That(() => new VaultConfigurationOptions { LoadTimeout = TimeSpan.Zero }).Throws<ArgumentOutOfRangeException>();

    // ---------- Cargas simultâneas: uma carga antiga não sobrescreve uma mais nova ----------

    [Test]
    public async Task Stale_reload_finishing_after_Reload_does_not_overwrite_new_values()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("A", "1");
        int hold = 0;
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = new ScriptedSecretStore(memory)
        {
            // Segura somente a leitura armada (a da recarga do timer), depois de ela ter lido o valor
            AfterGet = async (_, _) =>
            {
                if (Interlocked.CompareExchange(ref hold, 0, 1) == 1)
                {
                    reached.TrySetResult();
                    await release.Task;
                }
            }
        };
        var configuration = new ConfigurationBuilder().AddTecVault(store).Build();
        var provider = (VaultConfigurationProvider)configuration.Providers.Single();
        int changes = 0;
        using var subscription = Microsoft.Extensions.Primitives.ChangeToken.OnChange(configuration.GetReloadToken, () => Interlocked.Increment(ref changes));

        await memory.SetSecretAsync("A", "2");
        Volatile.Write(ref hold, 1);
        var timerReload = provider.ReloadAsync();          // começa antes: lê "2" e fica parada
        await reached.Task;

        await memory.SetSecretAsync("A", "3");
        configuration.Reload();                             // começa depois e termina antes: aplica "3"
        await Assert.That(configuration["A"]).IsEqualTo("3");
        int changesAfterReload = Volatile.Read(ref changes);

        release.TrySetResult();
        await timerReload;                                  // termina por último com o valor antigo: descartada

        await Assert.That(configuration["A"]).IsEqualTo("3");
        await Assert.That(Volatile.Read(ref changes)).IsEqualTo(changesAfterReload);   // sem aviso de mudança para valores antigos

        // A recarga seguinte parte da carga aplicada (incremental) e continua vendo o valor atual
        await provider.ReloadAsync();
        await Assert.That(configuration["A"]).IsEqualTo("3");
    }

    [Test]
    public async Task Stale_Reload_finishing_after_timer_reload_does_not_overwrite_new_values()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("A", "1");
        int hold = 0;
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var store = new ScriptedSecretStore(memory)
        {
            AfterGet = async (_, _) =>
            {
                if (Interlocked.CompareExchange(ref hold, 0, 1) == 1)
                {
                    reached.TrySetResult();
                    await release.Task;
                }
            }
        };
        var configuration = new ConfigurationBuilder().AddTecVault(store).Build();
        var provider = (VaultConfigurationProvider)configuration.Providers.Single();

        await memory.SetSecretAsync("A", "2");
        Volatile.Write(ref hold, 1);
        var manualReload = Task.Run(configuration.Reload);  // Load() manual começa antes: lê "2" e fica parado
        await reached.Task;

        await memory.SetSecretAsync("A", "3");
        await provider.ReloadAsync();                       // recarga do timer começa depois e aplica "3"
        await Assert.That(configuration["A"]).IsEqualTo("3");

        release.TrySetResult();
        await manualReload;

        await Assert.That(configuration["A"]).IsEqualTo("3");
    }

    // ---------- Optional: exceção do leitor na carga inicial ----------

    [Test]
    public async Task Read_exception_with_Optional_starts_empty_logs_and_reload_recovers()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("A", "1");
        var store = new ScriptedSecretStore(memory) { ThrowOnGet = new InvalidOperationException("provedor quebrado") };

        var configuration = new ConfigurationBuilder()
            .AddTecVault(store, o => { o.Optional = true; o.ReloadInterval = TimeSpan.FromMinutes(1); }, loggerFactory: factory).Build();
        var provider = (VaultConfigurationProvider)configuration.Providers.Single();

        await Assert.That(configuration.AsEnumerable()).IsEmpty();
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains(nameof(InvalidOperationException)))).IsTrue();
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains(VaultConfigurationProvider.ExceptionCode))).IsTrue();
        await Assert.That(provider.Timer).IsNotNull();       // a recarga periódica continua agendada

        store.ThrowOnGet = null;
        await provider.ReloadAsync();
        await Assert.That(configuration["A"]).IsEqualTo("1");
        ((IDisposable)configuration).Dispose();
    }

    [Test]
    public async Task Listing_exception_with_Optional_starts_with_empty_configuration()
    {
        var store = new ScriptedSecretStore(Memory.Secrets()) { BeforeList = _ => Task.FromException(new HttpRequestException("rede")) };

        var configuration = new ConfigurationBuilder().AddTecVault(store, o => o.Optional = true).Build();

        await Assert.That(configuration.AsEnumerable()).IsEmpty();
    }

    [Test]
    public async Task Listing_exception_without_Optional_propagates_original_exception_and_logs()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var store = new ScriptedSecretStore(Memory.Secrets()) { BeforeList = _ => Task.FromException(new HttpRequestException("rede")) };

        await Assert.That(() => new ConfigurationBuilder().AddTecVault(store, loggerFactory: factory).Build()).Throws<HttpRequestException>();
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains(nameof(HttpRequestException)))).IsTrue();
    }

    // ---------- Dispose ----------

    [Test]
    public async Task Configuration_dispose_stops_reload_timer()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("A", "1");
        var time = new TimerCaptureTimeProvider();
        var configuration = new ConfigurationBuilder()
            .AddTecVault(memory, o => o.ReloadInterval = TimeSpan.FromMinutes(5), timeProvider: time).Build();

        // O tempo limite da carga (CancellationTokenSource com o TimeProvider) também cria um timer, sem período
        var reload = time.Timers.Single(t => t.Period != Timeout.InfiniteTimeSpan);
        await Assert.That(reload.Period).IsEqualTo(TimeSpan.FromMinutes(5));
        await Assert.That(reload.Disposed).IsFalse();

        ((IDisposable)configuration).Dispose();

        await Assert.That(reload.Disposed).IsTrue();
    }

    [Test]
    public async Task Without_ReloadInterval_no_timer_is_created()
    {
        var time = new TimerCaptureTimeProvider();
        using var _ = (IDisposable)new ConfigurationBuilder().AddTecVault(Memory.Secrets(), timeProvider: time).Build();

        await Assert.That(time.Timers.Where(t => t.Period != Timeout.InfiniteTimeSpan)).IsEmpty();
    }

    /// <summary>Relógio do sistema que registra os timers criados (sem dispará-los).</summary>
    private sealed class TimerCaptureTimeProvider : TimeProvider
    {
        public List<CapturedTimer> Timers { get; } = [];

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new CapturedTimer(period);
            lock (Timers)
                Timers.Add(timer);
            return timer;
        }
    }

    private sealed class CapturedTimer(TimeSpan period) : ITimer
    {
        public TimeSpan Period { get; private set; } = period;

        public bool Disposed { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            Period = period;
            return !Disposed;
        }

        public void Dispose() => Disposed = true;

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
