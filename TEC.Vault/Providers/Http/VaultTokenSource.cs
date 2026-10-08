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
/// O token é renovado antes de expirar: faltando 10% da vida dele (entre 10 segundos e 5 minutos). Várias requisições
/// simultâneas com o token vencido fazem um único login. Um login que falha não é guardado: a próxima chamada tenta de novo.
/// </remarks>
public sealed class VaultTokenSource : IDisposable
{
    private static readonly TimeSpan MinSkew = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MaxSkew = TimeSpan.FromMinutes(5);

    private readonly Func<CancellationToken, Task<VaultToken>> _login;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile Entry? _current;

    private sealed record Entry(string Value, DateTimeOffset? RenewAt);

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
    public async ValueTask<string> GetAsync(CancellationToken cancellationToken)
    {
        if (Valid(_current) is { } cached)
            return cached;

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Valid(_current) is { } other)
                return other;   // outra chamada já renovou enquanto esta esperava

            var now = _time.GetUtcNow();
            var token = await _login(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(token.Value))
                throw new VaultLoginException("o login no cofre não devolveu token");

            DateTimeOffset? renewAt = null;
            if (token.ExpiresOn is { } expires)
            {
                var life = expires - now;
                var skew = TimeSpan.FromTicks(Math.Clamp(life.Ticks / 10, MinSkew.Ticks, MaxSkew.Ticks));
                renewAt = expires - skew;
            }

            _current = new Entry(token.Value, renewAt);
            return token.Value;
        }
        finally
        {
            _gate.Release();
        }
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
    public void Dispose() => _gate.Dispose();

    private string? Valid(Entry? entry) =>
        entry is not null && (entry.RenewAt is null || _time.GetUtcNow() < entry.RenewAt) ? entry.Value : null;
}
