using Microsoft.Extensions.Caching.Memory;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Diagnostics;
using TEC.Vault.Secrets;
using TEC.Core.Common.Guards;
using TEC.Core.Common.Results;

namespace TEC.Vault.Caching;

/// <summary>
/// Cache em memória de <see cref="ISecretReader.GetSecretAsync"/> (decorator do leitor, funciona com qualquer provedor). Desligado por padrão.
/// </summary>
/// <remarks>
/// <para>Segurança: usa uma instância de <see cref="MemoryCache"/> própria e privada (outros componentes não enumeram nem leem
/// as entradas), guarda só leituras bem-sucedidas, nunca além da expiração do segredo, e é limitado em quantidade de entradas.</para>
/// <para>Escritas feitas pelos decorators desta instância (<see cref="CacheInvalidatingSecretStore"/>,
/// <see cref="CacheInvalidatingSecretRecycleBin"/>, <see cref="CacheInvalidatingSecretBackup"/>) limpam todo o cache (a comparação
/// de nomes varia entre provedores). Escritas feitas por outras instâncias da aplicação só são vistas após a expiração do cache:
/// escolha uma duração curta.</para>
/// <para>Consistência: um contador de geração muda a cada escrita; uma leitura só é guardada se nenhuma escrita terminou
/// enquanto ela estava em andamento (senão um valor antigo, lido antes da escrita, voltaria ao cache depois da limpeza).</para>
/// <para>Stampede: leituras simultâneas da mesma chave compartilham uma única chamada ao cofre. A chamada compartilhada não
/// usa o <see cref="CancellationToken"/> de nenhum chamador (o cancelamento de um não cancela os demais): cada chamador
/// deixa de esperar quando o seu token é cancelado, e a chamada termina sozinha, limitada pelos timeouts do provedor.
/// Falhas não são guardadas: a próxima leitura depois de uma falha consulta o cofre de novo.</para>
/// </remarks>
internal sealed class CachingSecretReader : ISecretReader, IDisposable
{
    internal const int MaxEntries = 1024;
    internal static readonly TimeSpan MaxDuration = TimeSpan.FromHours(1);

    private readonly ISecretReader _inner;
    private readonly TimeSpan _duration;
    private readonly TimeProvider _time;
    private readonly MemoryCache _cache;
    private volatile bool _disposed;

    // Protege _generation, _inFlight e a sequência "conferir geração + gravar no cache" contra a limpeza
    private readonly Lock _sync = new();
    private readonly Dictionary<CacheKey, TaskCompletionSource<Result<VaultSecret>>> _inFlight = [];
    private long _generation;

    /// <summary>
    /// Chave do cache e das leituras em andamento: nome e versão como campos separados (uma chave textual concatenada faria
    /// <c>("a\n", "b")</c> e <c>("a", "\nb")</c> colidirem, e uma leitura receberia o segredo da outra).
    /// </summary>
    private readonly record struct CacheKey(string Name, string? Version);

    public CachingSecretReader(ISecretReader inner, TimeSpan duration, TimeProvider? time = null)
    {
        _inner = Guard.NotNull(inner);
        ValidateDuration(duration);
        _duration = duration;
        _time = time ?? TimeProvider.System;

        // A varredura de expirados do MemoryCache só roda quando há acesso ao cache e, no máximo, a cada ExpirationScanFrequency
        // (padrão: 1 minuto). Com duração menor que isso, a varredura acompanha a duração (mínimo 1 segundo).
        _cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = MaxEntries, ExpirationScanFrequency = ScanFrequency(duration) });
    }

    internal static TimeSpan ScanFrequency(TimeSpan duration) =>
        duration >= TimeSpan.FromMinutes(1) ? TimeSpan.FromMinutes(1)
        : duration <= TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1)
        : duration;

    public string ProviderName => _inner.ProviderName;

    internal static void ValidateDuration(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero || duration > MaxDuration)
            throw new ArgumentOutOfRangeException(nameof(duration), "A duração do cache deve ser maior que zero e no máximo 1 hora.");
    }

    public async Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var key = new CacheKey(name, version);
        if (TryGetCached(key, out var cached))
        {
            VaultDiagnostics.RecordCache(ProviderName, "hit");
            return cached;
        }

        TaskCompletionSource<Result<VaultSecret>>? owner = null;
        Task<Result<VaultSecret>> shared;
        long generation = 0;
        lock (_sync)
        {
            // Segunda consulta, sob o lock: a leitura em andamento pode ter terminado (saído de _inFlight e gravado no cache,
            // as duas coisas sob este lock) entre a consulta acima e aqui; sem ela, uma nova chamada ao cofre seria disparada
            if (TryGetCached(key, out cached))
            {
                VaultDiagnostics.RecordCache(ProviderName, "hit");
                return cached;
            }

            if (_inFlight.TryGetValue(key, out var running))
            {
                shared = running.Task;
            }
            else
            {
                owner = new TaskCompletionSource<Result<VaultSecret>>(TaskCreationOptions.RunContinuationsAsynchronously);
                _inFlight[key] = owner;
                shared = owner.Task;
                generation = _generation;
            }
        }

        VaultDiagnostics.RecordCache(ProviderName, owner is null ? "coalesced" : "miss");

        // Quem criou a entrada dispara a leitura fora do lock; os demais só aguardam a mesma Task
        if (owner is not null)
            _ = FetchAsync(owner, key, name, version, generation);

        return await shared.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task FetchAsync(TaskCompletionSource<Result<VaultSecret>> owner, CacheKey key, string name, string? version, long generation)
    {
        Result<VaultSecret>? result = null;
        Exception? failure = null;
        try
        {
            result = await _inner.GetSecretAsync(name, version, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            failure = ex;
        }

        // A tarefa compartilhada termina SEMPRE (finally): se guardar no cache lançasse (ex.: cache descartado no
        // encerramento da aplicação), quem aguarda a leitura ficaria esperando para sempre
        try
        {
            Complete(owner, key, generation, result is { IsSuccess: true } ? result.Value : null);
        }
        finally
        {
            if (failure is not null)
                owner.TrySetException(failure);
            else
                owner.TrySetResult(result!);
        }
    }

    /// <summary>Grava o valor (se a geração não mudou) e encerra a leitura compartilhada, de forma atômica em relação à limpeza.</summary>
    private void Complete(TaskCompletionSource<Result<VaultSecret>> owner, CacheKey key, long generation, VaultSecret? secret)
    {
        lock (_sync)
        {
            if (_inFlight.TryGetValue(key, out var current) && current == owner)
                _inFlight.Remove(key);

            if (secret is null || generation != _generation || _disposed)
                return;

            var now = _time.GetUtcNow();
            var expiration = now.Add(_duration);
            if (secret.Properties.ExpiresOn is { } expiresOn && expiresOn < expiration)
                expiration = expiresOn;

            if (expiration <= now)
                return;

            try
            {
                _cache.Set(key, secret, new MemoryCacheEntryOptions { AbsoluteExpiration = expiration, Size = 1 });
            }
            catch (ObjectDisposedException)
            {
                // Descartado entre a conferência e a gravação: a leitura é devolvida sem ser guardada
            }
        }
    }

    /// <summary>Consulta o cache. Depois de <see cref="Dispose"/> nada é servido do cache: a leitura vai direto ao provedor.</summary>
    private bool TryGetCached(CacheKey key, out VaultSecret secret)
    {
        secret = null!;
        if (_disposed)
            return false;

        try
        {
            if (_cache.TryGetValue(key, out VaultSecret? cached) && cached is not null)
            {
                secret = cached;
                return true;
            }
        }
        catch (ObjectDisposedException)
        {
            // Descartado durante a consulta
        }

        return false;
    }

    /// <summary>Entradas no cache (testes).</summary>
    internal int Count => _disposed ? 0 : _cache.Count;

    /// <summary>Descartado (testes).</summary>
    internal bool IsDisposed => _disposed;

    /// <summary>Geração atual (testes).</summary>
    internal long Generation
    {
        get
        {
            lock (_sync)
                return _generation;
        }
    }

    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        _inner.ExistsAsync(name, cancellationToken);

    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        _inner.ListSecretsAsync(cancellationToken);

    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        _inner.ListSecretVersionsAsync(name, cancellationToken);

    /// <summary>
    /// Descarta o cache (os valores guardados deixam de ser referenciados). Leituras em andamento terminam normalmente, sem
    /// guardar o resultado; leituras e escritas posteriores continuam funcionando, sem cache.
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
        _cache.Dispose();
    }

    /// <summary>
    /// Executa uma escrita e limpa o cache depois, também em falha/exceção (o estado no cofre pode ter mudado sem confirmação).
    /// Recebe a operação ainda não iniciada: um provedor que lança antes de devolver a <see cref="Task"/> (exceção síncrona)
    /// também passa pela limpeza.
    /// </summary>
    internal async Task<T> InvalidateAfter<T>(Func<Task<T>> operation)
    {
        try
        {
            return await operation().ConfigureAwait(false);
        }
        finally
        {
            Invalidate();
        }
    }

    /// <summary>
    /// Nova geração: leituras em andamento não gravam mais no cache e novas leituras não se juntam às antigas
    /// (que podem ter lido o valor anterior à escrita).
    /// </summary>
    internal void Invalidate()
    {
        lock (_sync)
        {
            _generation++;
            _inFlight.Clear();
            if (_disposed)
                return;

            try
            {
                _cache.Clear();
            }
            catch (ObjectDisposedException)
            {
                // Cache já descartado: não há o que limpar, e a exceção não pode mascarar o resultado da escrita
            }
        }
    }
}

/// <summary>Gestão de segredos com cache: leituras pelo <see cref="CachingSecretReader"/>, escritas no provedor seguidas de limpeza do cache.</summary>
internal sealed class CacheInvalidatingSecretStore(ISecretStore inner, CachingSecretReader cache) : ISecretStore
{
    public string ProviderName => cache.ProviderName;

    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        cache.GetSecretAsync(name, version, cancellationToken);

    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => cache.ExistsAsync(name, cancellationToken);

    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        cache.ListSecretsAsync(cancellationToken);

    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        cache.ListSecretVersionsAsync(name, cancellationToken);

    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default) =>
        cache.InvalidateAfter(() => inner.SetSecretAsync(name, value, options, cancellationToken));

    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default) =>
        cache.InvalidateAfter(() => inner.UpdateSecretPropertiesAsync(name, update, version, cancellationToken));

    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        cache.InvalidateAfter(() => inner.DeleteSecretAsync(name, cancellationToken));
}

/// <summary>Lixeira de segredos com cache: recuperação e remoção definitiva limpam o cache.</summary>
internal sealed class CacheInvalidatingSecretRecycleBin(ISecretRecycleBin inner, CachingSecretReader cache) : ISecretRecycleBin
{
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedSecretsAsync(CancellationToken cancellationToken = default) =>
        inner.ListDeletedSecretsAsync(cancellationToken);

    public Task<Result<SecretProperties>> RecoverDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        cache.InvalidateAfter(() => inner.RecoverDeletedSecretAsync(name, cancellationToken));

    public Task<Result> PurgeDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        cache.InvalidateAfter(() => inner.PurgeDeletedSecretAsync(name, cancellationToken));
}

/// <summary>Backup de segredos com cache: a restauração limpa o cache.</summary>
internal sealed class CacheInvalidatingSecretBackup(ISecretBackup inner, CachingSecretReader cache) : ISecretBackup
{
    public Task<Result<byte[]>> BackupSecretAsync(string name, CancellationToken cancellationToken = default) =>
        inner.BackupSecretAsync(name, cancellationToken);

    public Task<Result<SecretProperties>> RestoreSecretBackupAsync(byte[] backup, CancellationToken cancellationToken = default) =>
        cache.InvalidateAfter(() => inner.RestoreSecretBackupAsync(backup, cancellationToken));
}
