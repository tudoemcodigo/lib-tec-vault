using TEC.Vault.Abstractions;
using TEC.Vault.Caching;
using TEC.Vault.Common;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>
/// Concorrência do cache de segredos. Determinísticos: a leitura "lenta" é segurada por um portão (TaskCompletionSource)
/// depois de já ter lido o valor do cofre, sem depender de atrasos ou do agendador.
/// </summary>
public class CacheConcurrencyTests
{
    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    [Test]
    public async Task Read_finished_after_write_does_not_cache_stale_value()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "antigo");
        var entered = NewSignal();
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = async (_, _) => { entered.TrySetResult(); await gate.Task; } };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var slowRead = cache.GetSecretAsync("a");
        await entered.Task;                        // a leitura já tem o valor "antigo" em mãos
        inner.AfterGet = null;
        await new CacheInvalidatingSecretStore(inner, cache).SetSecretAsync("a", "novo");   // a escrita termina e limpa o cache
        gate.SetResult();                          // só agora a leitura antiga termina

        var stale = await slowRead;
        var fresh = await cache.GetSecretAsync("a");

        await Assert.That(stale.Value.Value).IsEqualTo("antigo");
        await Assert.That(fresh.Value.Value).IsEqualTo("novo");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Read_started_after_write_does_not_join_previous_read()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "antigo");
        var entered = NewSignal();
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = async (_, _) => { entered.TrySetResult(); await gate.Task; } };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var before = cache.GetSecretAsync("a");
        await entered.Task;
        await new CacheInvalidatingSecretStore(inner, cache).SetSecretAsync("a", "novo");
        var after = cache.GetSecretAsync("a");     // não pode reaproveitar a leitura anterior à escrita
        gate.SetResult();

        await Assert.That((await before).Value.Value).IsEqualTo("antigo");
        await Assert.That((await after).Value.Value).IsEqualTo("novo");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Concurrent_reads_of_same_key_make_a_single_vault_call()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = (_, _) => gate.Task };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var reads = Enumerable.Range(0, 20).Select(_ => cache.GetSecretAsync("a")).ToList();
        gate.SetResult();
        var results = await Task.WhenAll(reads);

        await Assert.That(inner.GetCalls).IsEqualTo(1);
        await Assert.That(results.All(r => r.Value.Value == "valor")).IsTrue();
    }

    [Test]
    public async Task Cancellation_of_one_caller_does_not_cancel_the_others()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = (_, _) => gate.Task };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));
        using var cts = new CancellationTokenSource();

        var cancelled = cache.GetSecretAsync("a", cancellationToken: cts.Token);
        var other = cache.GetSecretAsync("a");
        await cts.CancelAsync();

        await Assert.That(async () => { await cancelled; }).Throws<OperationCanceledException>();
        gate.SetResult();
        await Assert.That((await other).Value.Value).IsEqualTo("valor");
        await Assert.That(inner.GetCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Shared_exception_is_not_kept()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = (_, _) => gate.Task, ThrowOnGet = new InvalidOperationException("falha") };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var first = cache.GetSecretAsync("a");
        var second = cache.GetSecretAsync("a");
        gate.SetResult();
        await Assert.That(async () => { await first; }).Throws<InvalidOperationException>();
        await Assert.That(async () => { await second; }).Throws<InvalidOperationException>();

        inner.ThrowOnGet = null;
        inner.AfterGet = null;
        var recovered = await cache.GetSecretAsync("a");

        await Assert.That(recovered.Value.Value).IsEqualTo("valor");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    [Test]
    public async Task In_flight_read_completes_when_cache_is_disposed()
    {
        // Encerramento da aplicação: o container descarta o cache com uma leitura no meio. A tarefa compartilhada precisa
        // terminar mesmo que guardar o resultado lance ObjectDisposedException (quem aguarda não pode ficar preso)
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "valor");
        var entered = NewSignal();
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(memory) { AfterGet = async (_, _) => { entered.TrySetResult(); await gate.Task; } };
        var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var owner = cache.GetSecretAsync("a");
        var waiter = cache.GetSecretAsync("a");
        await entered.Task;
        cache.Dispose();
        gate.SetResult();

        var results = await Task.WhenAll(owner, waiter).WaitAsync(TimeSpan.FromSeconds(30));
        await Assert.That(results.All(r => r.Value.Value == "valor")).IsTrue();
        await Assert.That(inner.GetCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Write_after_cache_dispose_returns_its_own_result()
    {
        var memory = Memory.Secrets();
        var cache = new CachingSecretReader(memory, TimeSpan.FromMinutes(5));
        var store = new CacheInvalidatingSecretStore(memory, cache);
        await store.SetSecretAsync("a", "1");
        await cache.GetSecretAsync("a");
        cache.Dispose();

        var written = await store.SetSecretAsync("a", "2");       // a limpeza do cache descartado não mascara o resultado
        var failed = await store.SetSecretAsync("nome inválido", "x");
        var read = await cache.GetSecretAsync("a");                // sem cache: vai direto ao provedor

        await Assert.That(written.IsSuccess).IsTrue();
        await Assert.That(failed.IsFailure).IsTrue();
        await Assert.That(read.Value.Value).IsEqualTo("2");
        await Assert.That(() => cache.Invalidate()).ThrowsNothing();
        await Assert.That(() => cache.Dispose()).ThrowsNothing();
    }

    [Test]
    [Arguments(0.001, 1)]      // mínimo de 1 segundo
    [Arguments(10, 10)]        // acompanha durações curtas
    [Arguments(300, 60)]       // no máximo o padrão do MemoryCache (1 minuto)
    public async Task Expiration_scan_follows_cache_duration(double durationSeconds, int expectedSeconds) =>
        await Assert.That(CachingSecretReader.ScanFrequency(TimeSpan.FromSeconds(durationSeconds))).IsEqualTo(TimeSpan.FromSeconds(expectedSeconds));

    [Test]
    public async Task Shared_failure_is_not_kept()
    {
        var gate = NewSignal();
        var inner = new ScriptedSecretStore(Memory.Secrets()) { AfterGet = (_, _) => gate.Task };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var first = cache.GetSecretAsync("nao-existe");
        var second = cache.GetSecretAsync("nao-existe");
        gate.SetResult();

        await Assert.That((await first).IsFailure).IsTrue();
        await Assert.That((await second).IsFailure).IsTrue();
        await Assert.That(inner.GetCalls).IsEqualTo(1);

        await cache.GetSecretAsync("nao-existe");
        await Assert.That(inner.GetCalls).IsEqualTo(2);
    }

    // ---------- Limites, versões e expiração ----------

    [Test]
    public async Task Cache_is_bounded_to_MaxEntries()
    {
        var inner = new AnySecretReader();
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));
        int limit = CachingSecretReader.MaxEntries;
        await Assert.That(limit).IsEqualTo(1024);

        for (int i = 0; i < CachingSecretReader.MaxEntries + 100; i++)
            await cache.GetSecretAsync($"s{i}");

        await Assert.That(cache.Count).IsLessThanOrEqualTo(CachingSecretReader.MaxEntries);
        await Assert.That(cache.Count).IsGreaterThan(0);
        await Assert.That(inner.Calls).IsEqualTo(CachingSecretReader.MaxEntries + 100);
    }

    [Test]
    public async Task Read_with_explicit_version_has_own_entry()
    {
        var memory = Memory.Secrets();
        var v1 = (await memory.SetSecretAsync("a", "1")).Value;
        var inner = new ScriptedSecretStore(memory);
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));
        var store = new CacheInvalidatingSecretStore(inner, cache);

        await store.SetSecretAsync("a", "2");
        var current = await cache.GetSecretAsync("a");
        var old = await cache.GetSecretAsync("a", v1.Version);
        await cache.GetSecretAsync("a");
        await cache.GetSecretAsync("a", v1.Version);

        await Assert.That(current.Value.Value).IsEqualTo("2");
        await Assert.That(old.Value.Value).IsEqualTo("1");
        await Assert.That(inner.GetCalls).IsEqualTo(2);    // uma por chave (nome + versão)
        await Assert.That(cache.Count).IsEqualTo(2);
    }

    [Test]
    public async Task Secret_expiring_now_is_not_cached()
    {
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var inner = new AnySecretReader { ExpiresOn = _ => time.Now };
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5), time);

        await cache.GetSecretAsync("a");
        await cache.GetSecretAsync("a");
        await Assert.That(inner.Calls).IsEqualTo(2);
        await Assert.That(cache.Count).IsEqualTo(0);

        inner.ExpiresOn = _ => time.Now.AddSeconds(1);     // um instante depois de agora: guardado até a expiração
        await cache.GetSecretAsync("b");
        await cache.GetSecretAsync("b");
        await Assert.That(inner.Calls).IsEqualTo(3);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task Exception_on_write_also_clears_cache(bool synchronous)
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("a", "1");
        using var cache = new CachingSecretReader(memory, TimeSpan.FromMinutes(5));
        var store = new CacheInvalidatingSecretStore(new ThrowingWriteStore(memory, synchronous), cache);
        await cache.GetSecretAsync("a");
        long generation = cache.Generation;
        await Assert.That(cache.Count).IsEqualTo(1);

        await Assert.That(async () => { await store.SetSecretAsync("a", "2"); }).Throws<InvalidOperationException>();
        await Assert.That(async () => { await store.UpdateSecretPropertiesAsync("a", new() { Enabled = false }); }).Throws<InvalidOperationException>();
        await Assert.That(async () => { await store.DeleteSecretAsync("a"); }).Throws<InvalidOperationException>();

        // A escrita pode ter chegado ao cofre antes da exceção: o cache não pode continuar servindo o valor anterior
        await Assert.That(cache.Count).IsEqualTo(0);
        await Assert.That(cache.Generation).IsEqualTo(generation + 3);
    }

    /// <summary>Leitor que responde qualquer nome (valor = nome), contando as chamadas.</summary>
    private sealed class AnySecretReader : ISecretReader
    {
        public int Calls;

        public Func<string, DateTimeOffset?> ExpiresOn { get; set; } = _ => null;

        public string ProviderName => "Stub";

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null,
            CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Calls);
            var properties = new SecretProperties { Name = name, Version = version, Enabled = true, ExpiresOn = ExpiresOn(name) };
            return Task.FromResult<Result<VaultSecret>>(new VaultSecret(properties, name));
        }

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<bool>>(true);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(Array.Empty<SecretProperties>());

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(Array.Empty<SecretProperties>());
    }

    /// <summary>Store cujas escritas lançam (de forma síncrona ou na Task), como um provedor que viola o contrato.</summary>
    private sealed class ThrowingWriteStore(ISecretStore inner, bool synchronous) : ISecretStore
    {
        public string ProviderName => inner.ProviderName;

        private Task<T> Fail<T>() => synchronous
            ? throw new InvalidOperationException("falha síncrona")
            : Task.FromException<T>(new InvalidOperationException("falha assíncrona"));

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null,
            CancellationToken cancellationToken = default) => inner.GetSecretAsync(name, version, cancellationToken);

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
            inner.ExistsAsync(name, cancellationToken);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            inner.ListSecretsAsync(cancellationToken);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name,
            CancellationToken cancellationToken = default) => inner.ListSecretVersionsAsync(name, cancellationToken);

        public Task<Result<SecretProperties>> SetSecretAsync(string name, string value,
            SecretWriteOptions? options = null, CancellationToken cancellationToken = default) =>
            Fail<Result<SecretProperties>>();

        public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name,
            SecretPropertiesUpdate update, string? version = null, CancellationToken cancellationToken = default) =>
            Fail<Result<SecretProperties>>();

        public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name,
            CancellationToken cancellationToken = default) => Fail<Result<DeletedVaultItem>>();
    }
}
