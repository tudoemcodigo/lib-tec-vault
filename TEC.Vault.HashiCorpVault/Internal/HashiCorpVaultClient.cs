using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TEC.Core.Text.Codecs;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.HashiCorpVault.Internal;

/// <summary>Resposta JSON do Vault. Ao descartar, o buffer (que pode conter valores) é zerado.</summary>
internal sealed class VaultResponse : IDisposable
{
    private readonly byte[] _buffer;
    private readonly JsonDocument _document;

    internal VaultResponse(byte[] buffer)
    {
        _buffer = buffer;
        try
        {
            _document = JsonDocument.Parse(buffer);
        }
        catch (JsonException)
        {
            CryptographicOperations.ZeroMemory(buffer);   // a resposta fora do formato também pode conter valores
            throw;
        }
    }

    public JsonElement Root => _document.RootElement;

    /// <summary><c>data</c> da resposta (formato padrão do Vault).</summary>
    public JsonElement Data => Root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object
        ? data
        : throw new JsonException("Resposta sem data.");

    public void Dispose()
    {
        _document.Dispose();
        CryptographicOperations.ZeroMemory(_buffer);
    }
}

/// <summary>
/// Acesso HTTP ao Vault compartilhado pelos stores (segredos, chaves e certificados): um login e um token para todos.
/// </summary>
internal sealed class HashiCorpVaultClient : IDisposable
{
    private readonly VaultHttpClient _login;
    private readonly VaultTokenSource _tokens;
    private readonly VaultHttpClient _http;
    private readonly VaultCredentialInput _credential;
    private IssuedToken? _issued;   // último token do login, candidato a renew-self (lido e gravado só no login, um de cada vez)
    private int _disposed;

    /// <summary>Token emitido no login. Sem <c>ToString</c> com o valor.</summary>
    private sealed class IssuedToken(string value, DateTimeOffset expiresOn, bool renewable)
    {
        public string Value { get; } = value;

        public DateTimeOffset ExpiresOn { get; } = expiresOn;

        public bool Renewable { get; } = renewable;

        public override string ToString() => $"IssuedToken {{ Value = ***, ExpiresOn = {ExpiresOn:O}, Renewable = {Renewable} }}";
    }

    internal HashiCorpVaultClient(HashiCorpVaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var address = options.Validate();
        Options = options;
        Time = options.TimeProvider ?? TimeProvider.System;
        _credential = options.Auth.Credential();
        CircuitBreaker = VaultCircuitBreaker.Create(HashiCorpVaultStoreBase.Provider, options.Http.CircuitBreaker, Time,
            "HashiCorpVaultOptions.Http.CircuitBreaker");

        _login = new VaultHttpClient(address, options.Http);
        _tokens = new VaultTokenSource(LoginAsync, Time);
        // O Vault responde 403 (não 401) tanto a token vencido ou revogado quanto a falta de permissão na política: antes de
        // refazer o login, auth/token/lookup-self confirma se o token é o problema (sem isso, cada 403 de política seria um login)
        _http = new VaultHttpClient(address, options.Http, _tokens, static (request, token) => request.Headers.Add("X-Vault-Token", token),
            reauthenticateOnForbidden: true, isTokenRejected: IsTokenRejectedAsync);

        var kvBase = string.IsNullOrEmpty(options.Kv.BasePath) ? null : options.Kv.BasePath;
        Secrets = new KvFolder(this, kvBase);
        Certificates = new KvFolder(this, kvBase is null ? options.Kv.CertificatesPath : kvBase + "/" + options.Kv.CertificatesPath);
        CertificateKeys = new KvFolder(this, kvBase is null ? options.Kv.CertificateKeysPath : kvBase + "/" + options.Kv.CertificateKeysPath);
    }

    internal HashiCorpVaultOptions Options { get; }

    internal TimeProvider Time { get; }

    /// <summary>Circuit breaker do cofre (compartilhado pelos stores deste cliente); <c>null</c> = desligado.</summary>
    internal VaultCircuitBreaker? CircuitBreaker { get; }

    /// <summary>Pasta dos segredos no KV.</summary>
    internal KvFolder Secrets { get; }

    /// <summary>Pasta dos certificados no KV (parte pública).</summary>
    internal KvFolder Certificates { get; }

    /// <summary>Pasta das chaves privadas dos certificados no KV (PKCS#12), separada para que a política do Vault a restrinja.</summary>
    internal KvFolder CertificateKeys { get; }

    /// <summary>GET; 404 → <c>null</c>.</summary>
    internal async Task<VaultResponse?> GetAsync(string path, CancellationToken ct)
    {
        using var response = await _http.SendAsync(() => Request(HttpMethod.Get, path, null), idempotent: true, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;
        VaultHttpClient.EnsureSuccess(response);
        return new VaultResponse(await _http.ReadBytesAsync(response, ct).ConfigureAwait(false));
    }

    /// <summary>Listagem (<c>?list=true</c>): nomes diretos, sem pastas. 404 (nada a listar) → vazio.</summary>
    internal async Task<List<string>> ListAsync(string path, CancellationToken ct)
    {
        using var result = await GetAsync(path + "?list=true", ct).ConfigureAwait(false);
        if (result is null)
            return [];
        return result.Data.TryGetProperty("keys", out var keys) && keys.ValueKind == JsonValueKind.Array
            ? keys.EnumerateArray().Select(k => k.GetString()!).Where(k => !k.EndsWith('/')).ToList()
            : [];
    }

    /// <summary>Envia e lê a resposta (204 → <c>null</c>). Status de erro lança <see cref="VaultHttpException"/>.</summary>
    internal async Task<VaultResponse?> SendAsync(HttpMethod method, string path, byte[]? body, bool idempotent, CancellationToken ct)
    {
        try
        {
            using var response = await _http.SendAsync(() => Request(method, path, body), idempotent, ct).ConfigureAwait(false);
            VaultHttpClient.EnsureSuccess(response);
            if (response.StatusCode == HttpStatusCode.NoContent)
                return null;
            var bytes = await _http.ReadBytesAsync(response, ct).ConfigureAwait(false);
            if (bytes.Length == 0)
                return null;
            return new VaultResponse(bytes);
        }
        finally
        {
            if (body is not null)
                CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>Corpo JSON escrito com <see cref="Utf8JsonWriter"/> (compatível com AOT). O chamador não guarda o array: <see cref="SendAsync"/> zera.</summary>
    internal static byte[] Json(Action<Utf8JsonWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }

        var result = buffer.WrittenSpan.ToArray();
        buffer.Clear();
        return result;
    }

    /// <summary>Caminho da API: <c>v1/</c> + segmentos já validados nas opções + nome codificado.</summary>
    internal static string Path(params string?[] parts) =>
        "v1/" + string.Join('/', parts.Where(p => !string.IsNullOrEmpty(p)));

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return;
        _http.Dispose();
        _login.Dispose();
        _tokens.Dispose();
    }

    private HttpRequestMessage Request(HttpMethod method, string path, byte[]? body)
    {
        var request = new HttpRequestMessage(method, path);
        if (Options.Namespace is { } ns)
            request.Headers.Add("X-Vault-Namespace", ns);
        if (body is not null)
            request.Content = new ByteArrayContent(body) { Headers = { ContentType = new("application/json") } };
        return request;
    }

    private async Task<VaultToken> LoginAsync(CancellationToken ct)
    {
        string credential;
        try
        {
            credential = _credential.Read();
        }
        catch (InvalidOperationException exception)
        {
            throw new VaultLoginException(exception.Message, exception);
        }

        var auth = Options.Auth;
        if (auth.Method == HashiCorpVaultAuthMethod.Token)
            return new VaultToken(credential, ExpiresOn: null);   // renovado por quem o gerou (ex.: Vault Agent); relido a cada 401/403

        var body = Json(w =>
        {
            if (auth.Method == HashiCorpVaultAuthMethod.AppRole)
            {
                w.WriteString("role_id", auth.RoleId);
                w.WriteString("secret_id", credential);
            }
            else
            {
                w.WriteString("role", auth.Role);
                w.WriteString("jwt", credential);
            }
        });

        var path = $"v1/auth/{VaultEndpoint.Path(auth.EffectiveMount)}/login";
        try
        {
            if (await RenewAsync(ct).ConfigureAwait(false) is { } renewed)
                return renewed;

            using var response = await _login.SendAsync(() => Request(HttpMethod.Post, path, body), idempotent: true, ct).ConfigureAwait(false);
            // 4xx: credencial ou papel recusado; 408/429/5xx (ex.: Vault selado) mantêm o status real e contam no circuit breaker
            VaultHttpClient.EnsureLoginSuccess(response, "o Vault");

            using var result = new VaultResponse(await _login.ReadBytesAsync(response, ct).ConfigureAwait(false));
            return Issued(result) ?? throw new VaultLoginException("o Vault não devolveu token");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>
    /// Renova o último token com <c>auth/token/renew-self</c> enquanto ele for renovável e ainda válido. Só aceita a renovação se
    /// ela estender a validade (no <c>token_max_ttl</c> o Vault devolve só o tempo restante): senão, <c>null</c> e novo login.
    /// Evita um login a cada expiração (no AppRole, cada login consome um uso do <c>secret_id</c>).
    /// </summary>
    private async Task<VaultToken?> RenewAsync(CancellationToken ct)
    {
        var issued = _issued;
        _issued = null;
        if (issued is not { Renewable: true } || Time.GetUtcNow() >= issued.ExpiresOn)
            return null;

        try
        {
            using var response = await _login.SendAsync(() => TokenRequest(HttpMethod.Post, "v1/auth/token/renew-self", issued.Value),
                idempotent: false, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return null;   // token revogado ou sem permissão de renovar: novo login

            using var result = new VaultResponse(await _login.ReadBytesAsync(response, ct).ConfigureAwait(false));
            var token = Issued(result);
            if (token is not null && string.Equals(token.Value, issued.Value, StringComparison.Ordinal) &&
                token.ExpiresOn is { } expires && expires > issued.ExpiresOn)
                return token;

            _issued = null;
            return null;   // não estendeu (limite do token_max_ttl): novo login
        }
        catch (Exception exception) when (exception is HttpRequestException or TimeoutException or VaultHttpException or JsonException)
        {
            return null;   // a renovação é uma otimização: qualquer falha cai no login normal
        }
    }

    /// <summary>Token de <c>auth</c> (login ou renew-self); um token renovável fica como candidato à próxima renovação.</summary>
    private VaultToken? Issued(VaultResponse result)
    {
        if (!result.Root.TryGetProperty("auth", out var authData) || authData.ValueKind != JsonValueKind.Object ||
            !authData.TryGetProperty("client_token", out var token) || string.IsNullOrEmpty(token.GetString()))
            return null;

        var value = token.GetString()!;
        var lease = authData.TryGetProperty("lease_duration", out var duration) && duration.TryGetInt64(out var seconds) ? seconds : 0;
        if (lease <= 0)
            return new VaultToken(value, null);

        var expires = Time.GetUtcNow().AddSeconds(lease);
        _issued = new IssuedToken(value, expires,
            authData.TryGetProperty("renewable", out var renewable) && renewable.ValueKind == JsonValueKind.True);
        return new VaultToken(value, expires);
    }

    /// <summary>
    /// Confirma um 403 com <c>auth/token/lookup-self</c> (permitido pela política <c>default</c>): 403/401 = token inválido (novo
    /// login); 200 = token válido e o 403 era da política. Outro desfecho (rede, 5xx) não refaz o login: o 403 original é devolvido.
    /// </summary>
    private async Task<bool> IsTokenRejectedAsync(string token, CancellationToken ct)
    {
        try
        {
            using var response = await _login.SendAsync(() => TokenRequest(HttpMethod.Get, "v1/auth/token/lookup-self", token),
                idempotent: false, ct).ConfigureAwait(false);
            return response.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized;
        }
        catch (Exception exception) when (exception is HttpRequestException or TimeoutException or VaultHttpException)
        {
            return false;
        }
    }

    private HttpRequestMessage TokenRequest(HttpMethod method, string path, string token)
    {
        var request = Request(method, path, null);
        request.Headers.Add("X-Vault-Token", token);
        return request;
    }
}

/// <summary>Leitura de campos comuns das respostas do Vault.</summary>
internal static class VaultJson
{
    internal static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    internal static DateTimeOffset? Date(JsonElement element, string name) =>
        String(element, name) is { Length: > 0 } text && DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var date) && date.Year > 1
            ? date
            : null;

    internal static Dictionary<string, string> Map(JsonElement element, string name)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (element.TryGetProperty(name, out var map) && map.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in map.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                    result[property.Name] = property.Value.GetString()!;
            }
        }

        return result;
    }

    /// <summary>
    /// Texto base64 (ou Base64Url sem preenchimento, o formato JWS do Transit) → bytes. Texto inválido é resposta fora do
    /// formato: <see cref="JsonException"/>, convertida em <c>VaultErrors.ProviderFailure</c> (não em exceção inesperada).
    /// </summary>
    internal static byte[] FromBase64(string text, bool url = false)
    {
        if (url)
            return Base64UrlEncoder.TryDecode(text, out var decoded) ? decoded : throw new JsonException("Base64Url inválido na resposta.");

        var buffer = new byte[text.Length / 4 * 3 + 3];
        return Convert.TryFromBase64String(text, buffer, out int written)
            ? buffer.AsSpan(0, written).ToArray()
            : throw new JsonException("Base64 inválido na resposta.");
    }

    internal static string Utf8(ReadOnlySpan<byte> bytes) => Encoding.UTF8.GetString(bytes);
}
