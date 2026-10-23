using System.Diagnostics;
using System.Runtime.ExceptionServices;

namespace TEC.Vault.Providers.Http;

/// <summary>Token de acesso obtido no login do cofre. <see cref="ToString"/> não mostra o valor.</summary>
/// <param name="Value">Token.</param>
/// <param name="ExpiresOn">Expiração. <c>null</c>: sem expiração conhecida (renovado só quando o cofre recusa o token).</param>
public sealed record VaultToken(string Value, DateTimeOffset? ExpiresOn)
{
    /// <inheritdoc />
    public override string ToString() => $"VaultToken {{ Value = ***, ExpiresOn = {ExpiresOn:O} }}";
}

/// <summary>
/// Token de acesso com renovação antecipada e login único em concorrência (uso pelos provedores HTTP). Thread-safe.
/// </summary>
/// <remarks>
/// <para>O token é renovado antes de expirar: faltando 10% da vida dele (entre 10 segundos e 5 minutos, e nunca mais que metade
/// da vida, para que um token de vida curta não nasça vencido).</para>
/// <para>Várias requisições simultâneas com o token vencido aguardam um único login, e o desfecho dele (sucesso <b>ou</b> falha)
/// vale para todas. Uma falha de login fica guardada por <see cref="FailureCooldown"/>: nesse intervalo as chamadas falham na hora
/// com a mesma exceção, sem novo login (evita uma fila de logins em série com o endpoint de login fora do ar). O login não é
/// cancelado pelo cancelamento de quem o disparou (as demais chamadas aguardam o mesmo login); só pelo <see cref="Dispose"/>.</para>
/// </remarks>
public sealed class VaultTokenSource : IDisposable
{
    /// <summary>Por quanto tempo uma falha de login é devolvida às chamadas seguintes sem novo login: 2 segundos.</summary>
    public static readonly TimeSpan FailureCooldown = TimeSpan.FromSeconds(2);

    private static readonly TimeSpan MinSkew = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MaxSkew = TimeSpan.FromMinutes(5);

    private readonly Func<CancellationToken, Task<VaultToken>> _login;
    private readonly TimeProvider _time;
    private readonly Lock _sync = new();
    private readonly CancellationTokenSource _disposed = new();
    private volatile Entry? _current;
    private Task<Entry>? _pending;          // login em andamento, compartilhado (sob _sync)
    private Failure? _lastFailure;          // última falha de login, guardada por FailureCooldown (sob _sync)

    /// <summary>Token guardado. <see cref="ToString"/> e o depurador não mostram o valor (o gerado pelo <c>record</c> o imprimiria).</summary>
    [DebuggerDisplay("{ToString(),nq}")]
    private sealed record Entry(string Value, DateTimeOffset? RenewAt)
    {
        public override string ToString() => $"Entry {{ Value = ***, RenewAt = {RenewAt:O} }}";
    }

    private sealed record Failure(ExceptionDispatchInfo Error, DateTimeOffset Until);

    /// <summary>Cria a fonte.</summary>
    /// <param name="login">Faz o login no cofre (relê credenciais de arquivo a cada chamada, acompanhando rotação).</param>
    /// <param name="timeProvider">Relógio. Padrão: <see cref="TimeProvider.System"/>.</param>
    public VaultTokenSource(Func<CancellationToken, Task<VaultToken>> login, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(login);
        _login = login;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Token válido (do cache ou de um novo login).</summary>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> cancelado (o login continua para as demais chamadas).</exception>
    public async ValueTask<string> GetAsync(CancellationToken cancellationToken)
    {
        if (Valid(_current) is { } cached)
            return cached;

        Task<Entry> pending;
        lock (_sync)
        {
            if (Valid(_current) is { } other)
                return other;   // outra chamada já renovou
            if (_lastFailure is { } failure && _time.GetUtcNow() < failure.Until)
                failure.Error.Throw();   // falha recente: a mesma exceção, sem novo login
            pending = _pending ??= LoginAsync();
        }

        var entry = await pending.WaitAsync(cancellationToken).ConfigureAwait(false);
        return entry.Value;
    }

    /// <summary>
    /// Descarta <paramref name="token"/> (ex.: o cofre respondeu 401/403 com ele). Se outra chamada já trocou o token, não faz nada.
    /// </summary>
    public void Invalidate(string token)
    {
        var current = _current;
        if (current is not null && string.Equals(current.Value, token, StringComparison.Ordinal))
            Interlocked.CompareExchange(ref _current, null, current);
    }

    /// <inheritdoc />
    public void Dispose() => _disposed.Cancel();   // sem timer: o CancellationTokenSource não precisa de Dispose

    private async Task<Entry> LoginAsync()
    {
        await Task.Yield();   // sai da trava de quem iniciou o login antes de chamar o cofre
        try
        {
            var now = _time.GetUtcNow();
            var token = await _login(_disposed.Token).ConfigureAwait(false);
            if (string.IsNullOrEmpty(token.Value))
                throw new VaultLoginException("o login no cofre não devolveu token");

            DateTimeOffset? renewAt = null;
            if (token.ExpiresOn is { } expires)
            {
                var life = expires - now;
                var skew = TimeSpan.FromTicks(Math.Clamp(life.Ticks / 10, MinSkew.Ticks, MaxSkew.Ticks));
                if (skew > life / 2)
                    skew = life / 2;   // vida curta (abaixo de ~20 s): renova na metade, em vez de nascer vencido
                renewAt = expires - (skew < TimeSpan.Zero ? TimeSpan.Zero : skew);
            }

            var entry = new Entry(token.Value, renewAt);
            lock (_sync)
            {
                _current = entry;
                _lastFailure = null;
                _pending = null;
            }

            return entry;
        }
        catch (Exception exception)
        {
            lock (_sync)
            {
                _pending = null;
                // Cancelamento (só pelo Dispose) não é guardado: não é um desfecho do cofre
                if (exception is not OperationCanceledException)
                    _lastFailure = new Failure(ExceptionDispatchInfo.Capture(exception), _time.GetUtcNow() + FailureCooldown);
            }

            throw;
        }
    }

    private string? Valid(Entry? entry) =>
        entry is not null && (entry.RenewAt is null || _time.GetUtcNow() < entry.RenewAt) ? entry.Value : null;
}
