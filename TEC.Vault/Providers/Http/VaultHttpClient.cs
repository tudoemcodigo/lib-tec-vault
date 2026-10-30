using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace TEC.Vault.Providers.Http;

/// <summary>Opções de transporte comuns aos provedores HTTP (uso pelos provedores).</summary>
public sealed class VaultHttpSettings
{
    /// <summary>Tentativas extras em falhas transitórias (0 a 10). Padrão: 3.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Tempo limite de cada tentativa (maior que zero, até 5 minutos). Padrão: 30 segundos.</summary>
    public TimeSpan NetworkTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Maior espera aceita de um <c>Retry-After</c> antes de desistir da retentativa. Padrão: 30 segundos.</summary>
    public TimeSpan MaxRetryDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Tamanho máximo de uma resposta lida (proteção de memória). Padrão: 4 MB.</summary>
    public int MaxResponseBytes { get; set; } = 4 * 1024 * 1024;

    /// <summary>
    /// Handler HTTP próprio (ex.: proxy, CA interna, testes). <c>null</c>: <see cref="SocketsHttpHandler"/> sem redirecionamento
    /// automático e com conexões renovadas a cada 5 minutos (acompanha mudança de DNS). Com handler próprio, desligue
    /// <c>AllowAutoRedirect</c>: um redirecionamento levaria o token de acesso para outro endereço.
    /// </summary>
    public HttpMessageHandler? Handler { get; set; }

    /// <summary>Relógio (esperas entre tentativas). Padrão: <see cref="TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; set; }

    /// <summary>
    /// Circuit breaker do cofre (ligado por padrão): com o cofre fora do ar, as chamadas falham na hora com
    /// <c>VAULT_CIRCUITO_ABERTO</c> em vez de esperar timeout e retentativas. Configuração: subseção <c>CircuitBreaker</c> do provedor.
    /// </summary>
    public VaultCircuitBreakerOptions CircuitBreaker { get; } = new();

    /// <summary>Confere os limites.</summary>
    /// <param name="optionPrefix">Prefixo do nome da opção nas mensagens (ex.: "HashiCorpVaultOptions").</param>
    /// <exception cref="InvalidOperationException">Valor fora do limite.</exception>
    public void Validate(string optionPrefix)
    {
        if (MaxRetries is < 0 or > 10)
            throw new InvalidOperationException($"{optionPrefix}.MaxRetries deve estar entre 0 e 10.");
        if (NetworkTimeout <= TimeSpan.Zero || NetworkTimeout > TimeSpan.FromMinutes(5))
            throw new InvalidOperationException($"{optionPrefix}.NetworkTimeout deve ser maior que zero e no máximo 5 minutos.");
        if (MaxRetryDelay < TimeSpan.Zero || MaxRetryDelay > TimeSpan.FromMinutes(5))
            throw new InvalidOperationException($"{optionPrefix}.MaxRetryDelay deve estar entre zero e 5 minutos.");
        if (MaxResponseBytes is < 1024 or > 64 * 1024 * 1024)
            throw new InvalidOperationException($"{optionPrefix}.MaxResponseBytes deve estar entre 1 KB e 64 MB.");
        CircuitBreaker.Validate($"{optionPrefix}.CircuitBreaker");
    }
}

/// <summary>
/// Resposta do cofre maior que <see cref="VaultHttpSettings.MaxResponseBytes"/>: a leitura é interrompida no limite (o corpo não é
/// mantido). Convertida por <see cref="VaultHttpProviderBase"/> em <c>VaultErrors.ProviderFailure</c>, com o limite no log.
/// </summary>
/// <param name="maxBytes">Limite configurado.</param>
public sealed class VaultResponseTooLargeException(int maxBytes)
    : Exception($"A resposta do cofre passou do limite de {maxBytes} bytes (MaxResponseBytes).")
{
    /// <summary>Limite configurado (<see cref="VaultHttpSettings.MaxResponseBytes"/>).</summary>
    public int MaxBytes { get; } = maxBytes;
}

/// <summary>Resposta HTTP de erro do cofre. A mensagem nunca contém o corpo da resposta.</summary>
public sealed class VaultHttpException : Exception
{
    /// <summary>Cria a exceção.</summary>
    /// <param name="statusCode">Status HTTP.</param>
    /// <param name="detail">Detalhe técnico seguro para log (ex.: código de erro do cofre). Nunca valores ou tokens.</param>
    public VaultHttpException(HttpStatusCode statusCode, string? detail = null)
        : base($"O cofre respondeu {(int)statusCode}{(detail is null ? "" : " " + detail)}.")
    {
        StatusCode = statusCode;
        Detail = detail;
    }

    /// <summary>Status HTTP.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Detalhe técnico seguro para log.</summary>
    public string? Detail { get; }
}

/// <summary>
/// Cliente HTTP dos provedores sem SDK (uso pelos provedores): retentativa com backoff exponencial e <c>Retry-After</c>,
/// tempo limite por tentativa (também na leitura do corpo), autenticação por token renovada uma vez em 401 (e em 403, se pedido),
/// limite de tamanho de resposta e redirecionamento desligado. Thread-safe; uma instância por provedor.
/// </summary>
/// <remarks>
/// <para>Só operações idempotentes são repetidas após falha de rede, tempo limite ou 5xx; as demais só após 429 (a requisição foi
/// recusada antes de ser processada). Assim uma criação nunca é aplicada duas vezes por retentativa.</para>
/// <para><see cref="VaultHttpSettings.NetworkTimeout"/> vale para a espera dos cabeçalhos de cada tentativa e, de novo, para a
/// leitura do corpo (<see cref="ReadBytesAsync"/>): um cofre que manda os cabeçalhos e para de enviar o corpo não prende a chamada.</para>
/// </remarks>
public sealed class VaultHttpClient : IDisposable
{
    private readonly HttpClient _client;
    private readonly VaultHttpSettings _settings;
    private readonly TimeProvider _time;
    private readonly VaultTokenSource? _tokens;
    private readonly Action<HttpRequestMessage, string>? _applyToken;
    private readonly bool _reauthenticateOnForbidden;
    private readonly Func<string, CancellationToken, Task<bool>>? _isTokenRejected;
    private volatile ConfirmedToken? _confirmed;

    /// <summary>Por quanto tempo um token confirmado como válido após um 403 dispensa nova confirmação: 5 segundos.</summary>
    public static readonly TimeSpan ForbiddenConfirmationCacheDuration = TimeSpan.FromSeconds(5);

    /// <summary>Token confirmado como válido após um 403 (o 403 era de política). Sem <c>ToString</c> com o valor.</summary>
    private sealed class ConfirmedToken(string token, DateTimeOffset until)
    {
        public string Token { get; } = token;

        public DateTimeOffset Until { get; } = until;

        public override string ToString() => $"ConfirmedToken {{ Token = ***, Until = {Until:O} }}";
    }

    /// <summary>Cria o cliente.</summary>
    /// <param name="baseAddress">Endereço do cofre, já validado (<see cref="VaultEndpoint.Validate"/>).</param>
    /// <param name="settings">Opções de transporte, já validadas.</param>
    /// <param name="tokens">Fonte do token de acesso. <c>null</c>: requisições sem autenticação (ex.: o próprio login).</param>
    /// <param name="applyToken">Como colocar o token na requisição. Padrão: <c>Authorization: Bearer</c>.</param>
    /// <param name="reauthenticateOnForbidden">
    /// Também refaz o login em 403 (além de 401). Use quando o cofre responde 403 a token vencido ou revogado (HashiCorp Vault);
    /// nos demais, 403 é falta de permissão e um novo login a cada chamada negada seria desperdício.
    /// </param>
    public VaultHttpClient(Uri baseAddress, VaultHttpSettings settings, VaultTokenSource? tokens = null,
        Action<HttpRequestMessage, string>? applyToken = null, bool reauthenticateOnForbidden = false)
        : this(baseAddress, settings, tokens, applyToken, reauthenticateOnForbidden, isTokenRejected: null)
    {
    }

    /// <summary>Cria o cliente, confirmando com o cofre se um 403 é de token inválido antes de refazer o login.</summary>
    /// <param name="baseAddress">Endereço do cofre, já validado (<see cref="VaultEndpoint.Validate"/>).</param>
    /// <param name="settings">Opções de transporte, já validadas.</param>
    /// <param name="tokens">Fonte do token de acesso. <c>null</c>: requisições sem autenticação (ex.: o próprio login).</param>
    /// <param name="applyToken">Como colocar o token na requisição. Padrão: <c>Authorization: Bearer</c>.</param>
    /// <param name="reauthenticateOnForbidden">Também refaz o login em 403 (além de 401), se <paramref name="isTokenRejected"/> confirmar.</param>
    /// <param name="isTokenRejected">
    /// Chamado em 403 com o token usado: <c>true</c> = o cofre recusa o token (descarta e refaz o login, como em 401);
    /// <c>false</c> = o token é válido e o 403 é falta de permissão na política (devolvido como está, sem novo login e sem descartar
    /// o token das demais chamadas). Um <c>false</c> vale por <see cref="ForbiddenConfirmationCacheDuration"/> para o mesmo token.
    /// <c>null</c>: todo 403 refaz o login (comportamento do outro construtor). Ex.: no HashiCorp Vault, <c>auth/token/lookup-self</c>.
    /// </param>
    public VaultHttpClient(Uri baseAddress, VaultHttpSettings settings, VaultTokenSource? tokens, Action<HttpRequestMessage, string>? applyToken,
        bool reauthenticateOnForbidden, Func<string, CancellationToken, Task<bool>>? isTokenRejected)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentNullException.ThrowIfNull(settings);

        _settings = settings;
        _time = settings.TimeProvider ?? TimeProvider.System;
        _tokens = tokens;
        _reauthenticateOnForbidden = reauthenticateOnForbidden;
        _isTokenRejected = isTokenRejected;
        _applyToken = tokens is null ? null : applyToken ?? ((request, token) => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token));

        var handler = settings.Handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AutomaticDecompression = DecompressionMethods.None
        };
        _client = new HttpClient(handler, disposeHandler: settings.Handler is null)
        {
            BaseAddress = baseAddress,
            Timeout = Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = settings.MaxResponseBytes
        };
    }

    /// <summary>Endereço do cofre.</summary>
    public Uri BaseAddress => _client.BaseAddress!;

    /// <summary>
    /// Para cofres que informam o tipo do erro no corpo, e não no status (ex.: AWS, que responde HTTP 400 com <c>__type</c> =
    /// <c>ThrottlingException</c> ou <c>ExpiredTokenException</c>): recebe o status e o corpo de cada resposta 4xx (lido com o teto
    /// de <see cref="VaultHttpSettings.MaxResponseBytes"/> e o tempo limite de rede) e devolve o status equivalente (ex.: 429 ou
    /// 401). O status devolvido vale para a retentativa, para o novo login e para a conversão do erro, e o corpo continua legível
    /// na resposta devolvida. <c>null</c> (padrão): o status é usado como veio.
    /// </summary>
    public Func<HttpStatusCode, ReadOnlyMemory<byte>, HttpStatusCode>? ErrorStatusMapper { get; init; }

    /// <summary>
    /// Envia a requisição criada por <paramref name="createRequest"/> (chamada de novo a cada tentativa) e devolve a resposta,
    /// qualquer que seja o status. O chamador descarta a resposta.
    /// </summary>
    /// <param name="createRequest">Cria a requisição (com conteúdo novo a cada chamada).</param>
    /// <param name="idempotent">Pode ser repetida após falha de rede, tempo limite ou 5xx.</param>
    /// <param name="cancellationToken">Cancelamento do chamador (lança <see cref="OperationCanceledException"/>).</param>
    /// <exception cref="HttpRequestException">Falha de rede após as tentativas.</exception>
    /// <exception cref="TimeoutException">Tempo limite da última tentativa.</exception>
    public async Task<HttpResponseMessage> SendAsync(Func<HttpRequestMessage> createRequest, bool idempotent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(createRequest);
        var reauthenticated = false;

        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var canRetry = attempt < _settings.MaxRetries;

            using var request = createRequest();
            string? token = null;
            if (_tokens is not null)
            {
                token = await _tokens.GetAsync(cancellationToken).ConfigureAwait(false);
                _applyToken!(request, token);
            }

            HttpResponseMessage response;
            using (var attemptTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                attemptTimeout.CancelAfter(_settings.NetworkTimeout);
                try
                {
                    response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, attemptTimeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    if (idempotent && canRetry)
                    {
                        await DelayAsync(attempt, null, cancellationToken).ConfigureAwait(false);
                        continue;
                    }

                    throw new TimeoutException($"O cofre não respondeu em {_settings.NetworkTimeout.TotalSeconds:0} segundos.");
                }
                catch (HttpRequestException) when (idempotent && canRetry && !cancellationToken.IsCancellationRequested)
                {
                    await DelayAsync(attempt, null, cancellationToken).ConfigureAwait(false);
                    continue;
                }
            }

            if (ErrorStatusMapper is { } mapStatus && (int)response.StatusCode is >= 400 and < 500)
                await MapErrorStatusAsync(response, mapStatus, cancellationToken).ConfigureAwait(false);

            // Token expirado ou revogado no cofre: um novo login, uma vez por chamada (não conta como tentativa). Em 403, só se
            // o token for o problema: um 403 de política com token válido não descarta o token compartilhado nem refaz o login
            if (token is not null && !reauthenticated &&
                (response.StatusCode == HttpStatusCode.Unauthorized ||
                 (_reauthenticateOnForbidden && response.StatusCode == HttpStatusCode.Forbidden &&
                  await IsTokenRejectedAsync(token, cancellationToken).ConfigureAwait(false))))
            {
                response.Dispose();
                _tokens!.Invalidate(token);
                reauthenticated = true;
                attempt--;
                continue;
            }

            if (canRetry && IsTransient(response.StatusCode, idempotent))
            {
                var status = response.StatusCode;
                var retryAfter = RetryAfter(response);
                response.Dispose();
                if (retryAfter is null || retryAfter <= _settings.MaxRetryDelay)
                {
                    await DelayAsync(attempt, retryAfter, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                // O status real (429 ou 503 com Retry-After longo): um 503 é indisponibilidade, não limite de requisições
                throw new VaultHttpException(status, "Retry-After acima do limite");
            }

            return response;
        }
    }

    /// <summary>Lança <see cref="VaultHttpException"/> (e descarta a resposta) se o status não for de sucesso.</summary>
    /// <param name="response">Resposta.</param>
    /// <param name="detail">Detalhe seguro para log (ex.: código de erro já extraído do corpo).</param>
    public static void EnsureSuccess(HttpResponseMessage response, string? detail = null)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.IsSuccessStatusCode)
            return;

        var status = response.StatusCode;
        response.Dispose();
        throw new VaultHttpException(status, detail);
    }

    /// <summary>
    /// Confere a resposta de um <b>login</b>: 4xx (exceto 408 e 429) é login recusado (<see cref="VaultLoginException"/>, que vira
    /// <c>VAULT_AUTENTICACAO_FALHOU</c>); 408, 429 e 5xx mantêm o status real (<see cref="VaultHttpException"/>, que vira
    /// <c>VAULT_INDISPONIVEL</c> ou <c>VAULT_LIMITE_EXCEDIDO</c> e conta no circuit breaker). Descarta a resposta se lançar.
    /// </summary>
    /// <param name="response">Resposta do login.</param>
    /// <param name="vaultName">Nome do cofre na mensagem (ex.: "o Vault").</param>
    /// <exception cref="VaultLoginException">Credencial ou papel recusado.</exception>
    /// <exception cref="VaultHttpException">Cofre indisponível ou limite de requisições.</exception>
    public static void EnsureLoginSuccess(HttpResponseMessage response, string vaultName)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.IsSuccessStatusCode)
            return;

        var status = response.StatusCode;
        if ((int)status is >= 400 and < 500 && status is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests))
        {
            response.Dispose();
            throw new VaultLoginException($"{vaultName} recusou o login ({(int)status})");
        }

        EnsureSuccess(response, "no login");
    }

    /// <summary>
    /// Lê o corpo como JSON (source generator, compatível com AOT), respeitando <see cref="VaultHttpSettings.MaxResponseBytes"/>.
    /// </summary>
    /// <exception cref="JsonException">Corpo inválido ou vazio.</exception>
    public async Task<T> ReadJsonAsync<T>(HttpResponseMessage response, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(typeInfo);

        var body = await ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
        try
        {
            return JsonSerializer.Deserialize(body, typeInfo) ?? throw new JsonException("Resposta vazia.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);   // a resposta pode conter valores de segredos
        }
    }

    /// <summary>
    /// Lê o corpo, respeitando <see cref="VaultHttpSettings.MaxResponseBytes"/> e <see cref="VaultHttpSettings.NetworkTimeout"/>
    /// (contado do início da leitura). O chamador zera o array devolvido se ele puder conter valores.
    /// </summary>
    /// <exception cref="VaultResponseTooLargeException">Resposta acima do limite.</exception>
    /// <exception cref="TimeoutException">O corpo não chegou inteiro dentro do tempo limite de rede.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> cancelado.</exception>
    public async Task<byte[]> ReadBytesAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        var limit = _settings.MaxResponseBytes;
        if (response.Content.Headers.ContentLength > limit)
            throw new VaultResponseTooLargeException(limit);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_settings.NetworkTimeout);
        try
        {
            return await ReadLimitedAsync(response, limit, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"O cofre não terminou de enviar a resposta em {_settings.NetworkTimeout.TotalSeconds:0} segundos.");
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(HttpResponseMessage response, int limit, CancellationToken cancellationToken)
    {
        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            var buffer = new byte[Math.Min(limit + 1, 16 * 1024)];
            var total = 0;
            while (true)
            {
                if (total == buffer.Length)
                {
                    if (buffer.Length > limit)
                    {
                        CryptographicOperations.ZeroMemory(buffer);
                        throw new VaultResponseTooLargeException(limit);
                    }

                    var larger = new byte[Math.Min(buffer.Length * 2, limit + 1)];
                    buffer.AsSpan(0, total).CopyTo(larger);
                    CryptographicOperations.ZeroMemory(buffer);
                    buffer = larger;
                }

                var read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                total += read;
            }

            if (total > limit)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw new VaultResponseTooLargeException(limit);
            }

            var result = buffer.AsSpan(0, total).ToArray();
            CryptographicOperations.ZeroMemory(buffer);
            return result;
        }
    }

    /// <inheritdoc />
    public void Dispose() => _client.Dispose();

    /// <summary>
    /// Lê o corpo de uma resposta 4xx (com teto e tempo limite), troca o status pelo de <see cref="ErrorStatusMapper"/> e devolve o
    /// corpo à resposta (lido de novo por quem a recebe). Descarta a resposta se a leitura falhar.
    /// </summary>
    private async Task MapErrorStatusAsync(HttpResponseMessage response, Func<HttpStatusCode, ReadOnlyMemory<byte>, HttpStatusCode> map,
        CancellationToken cancellationToken)
    {
        byte[] body;
        try
        {
            body = await ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            response.Dispose();
            throw;
        }

        var contentType = response.Content.Headers.ContentType;
        response.Content.Dispose();
        response.Content = new ByteArrayContent(body) { Headers = { ContentType = contentType } };
        response.StatusCode = map(response.StatusCode, body);
    }

    private async Task<bool> IsTokenRejectedAsync(string token, CancellationToken cancellationToken)
    {
        if (_isTokenRejected is null)
            return true;
        if (_confirmed is { } confirmed && string.Equals(confirmed.Token, token, StringComparison.Ordinal) && _time.GetUtcNow() < confirmed.Until)
            return false;   // confirmado há pouco: rajada de 403 de política sem repetir a checagem

        if (await _isTokenRejected(token, cancellationToken).ConfigureAwait(false))
            return true;

        _confirmed = new ConfirmedToken(token, _time.GetUtcNow() + ForbiddenConfirmationCacheDuration);
        return false;
    }

    private static bool IsTransient(HttpStatusCode status, bool idempotent) =>
        status == HttpStatusCode.TooManyRequests ||
        (idempotent && status is HttpStatusCode.RequestTimeout or HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout or HttpStatusCode.InternalServerError);

    private TimeSpan? RetryAfter(HttpResponseMessage response)
    {
        if (response.Headers.RetryAfter is not { } header)
            return null;
        if (header.Delta is { } delta)
            return delta < TimeSpan.Zero ? TimeSpan.Zero : delta;
        if (header.Date is { } date)
        {
            var wait = date - _time.GetUtcNow();
            return wait < TimeSpan.Zero ? TimeSpan.Zero : wait;
        }

        return null;
    }

    private Task DelayAsync(int attempt, TimeSpan? retryAfter, CancellationToken cancellationToken)
    {
        // Backoff exponencial com jitter (0,8s, 1,6s, 3,2s... até 30s); Retry-After do cofre tem precedência
        var delay = retryAfter ?? TimeSpan.FromMilliseconds(Math.Min(30_000, 800 * Math.Pow(2, attempt)) * (0.8 + RandomNumberGenerator.GetInt32(0, 400) / 1000.0));
        return delay <= TimeSpan.Zero ? Task.CompletedTask : Task.Delay(delay, _time, cancellationToken);
    }
}
