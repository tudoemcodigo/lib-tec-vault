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
/// tempo limite por tentativa, autenticação por token renovada uma vez em 401 (e em 403, se pedido), limite de tamanho de resposta e
/// redirecionamento desligado. Thread-safe; uma instância por provedor.
/// </summary>
/// <remarks>
/// Só operações idempotentes são repetidas após falha de rede, tempo limite ou 5xx; as demais só após 429 (a requisição foi
/// recusada antes de ser processada). Assim uma criação nunca é aplicada duas vezes por retentativa.
/// </remarks>
public sealed class VaultHttpClient : IDisposable
{
    private readonly HttpClient _client;
    private readonly VaultHttpSettings _settings;
    private readonly TimeProvider _time;
    private readonly VaultTokenSource? _tokens;
    private readonly Action<HttpRequestMessage, string>? _applyToken;
    private readonly bool _reauthenticateOnForbidden;

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
    {
        ArgumentNullException.ThrowIfNull(baseAddress);
        ArgumentNullException.ThrowIfNull(settings);

        _settings = settings;
        _time = settings.TimeProvider ?? TimeProvider.System;
        _tokens = tokens;
        _reauthenticateOnForbidden = reauthenticateOnForbidden;
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

            // Token expirado ou revogado no cofre: um novo login, uma vez por chamada (não conta como tentativa)
            if (token is not null && !reauthenticated &&
                (response.StatusCode == HttpStatusCode.Unauthorized || (_reauthenticateOnForbidden && response.StatusCode == HttpStatusCode.Forbidden)))
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

    /// <summary>Lê o corpo, respeitando <see cref="VaultHttpSettings.MaxResponseBytes"/>.</summary>
    /// <exception cref="VaultResponseTooLargeException">Resposta acima do limite.</exception>
    public async Task<byte[]> ReadBytesAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        var limit = _settings.MaxResponseBytes;
        if (response.Content.Headers.ContentLength > limit)
            throw new VaultResponseTooLargeException(limit);

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
