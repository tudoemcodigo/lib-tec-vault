using System.Buffers;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.GoogleSecretManager.Internal;

/// <summary>
/// Login no Google para a <see cref="VaultTokenSource"/> (que guarda o token, renova antes de expirar, faz um login só em
/// concorrência e segura falhas por um intervalo): token estático, Service Account JSON (JWT RS256 trocado no <c>token_uri</c>
/// validado) ou Metadata Server. Thread-safe.
/// </summary>
internal sealed class GoogleCredentials : IDisposable
{
    private const string Scope = "https://www.googleapis.com/auth/cloud-platform";
    private const string MetadataTokenPath = "computeMetadata/v1/instance/service-accounts/default/token";
    private const int MaxTokenLength = 16 * 1024;
    private const int MaxTokenResponseBytes = 64 * 1024;

    private readonly GoogleSecretManagerOptions _options;
    private readonly GoogleSecretManagerOptions.Resolved _resolved;
    private readonly TimeProvider _time;
    private readonly HashSet<string> _allowedTokenHosts;
    private readonly ConcurrentDictionary<string, VaultHttpClient> _tokenClients = new(StringComparer.OrdinalIgnoreCase);
    private readonly VaultHttpClient? _metadata;
    private int _disposed;

    internal GoogleCredentials(GoogleSecretManagerOptions options, GoogleSecretManagerOptions.Resolved resolved, TimeProvider time)
    {
        _options = options;
        _resolved = resolved;
        _time = time;
        _allowedTokenHosts = new HashSet<string>(options.AllowedTokenHosts.Select(h => h.Trim()), StringComparer.OrdinalIgnoreCase);
        if (resolved.Credentials == GoogleCredentialKind.MetadataServer)
            _metadata = new VaultHttpClient(new Uri("http://metadata.google.internal/"), LocalSettings(options.Http));
    }

    /// <summary>Login da <see cref="VaultTokenSource"/>.</summary>
    internal Task<VaultToken> LoginAsync(CancellationToken cancellationToken) => _resolved.Credentials switch
    {
        GoogleCredentialKind.StaticToken => Task.FromResult(StaticToken()),
        GoogleCredentialKind.ServiceAccount => ServiceAccountAsync(cancellationToken),
        _ => MetadataServerAsync(cancellationToken)
    };

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return;
        _metadata?.Dispose();
        foreach (var client in _tokenClients.Values)
            client.Dispose();
    }

    private static VaultHttpSettings LocalSettings(VaultHttpSettings http) => new()
    {
        MaxRetries = Math.Min(http.MaxRetries, 2),
        NetworkTimeout = http.NetworkTimeout < TimeSpan.FromSeconds(5) ? http.NetworkTimeout : TimeSpan.FromSeconds(5),
        MaxRetryDelay = http.MaxRetryDelay,
        MaxResponseBytes = MaxTokenResponseBytes,
        Handler = http.Handler,
        TimeProvider = http.TimeProvider
    };

    // ---------- 1. Token estático ----------

    /// <summary>Token do código ou da variável (relida a cada login: depois de um 401, a variável é lida de novo).</summary>
    private VaultToken StaticToken()
    {
        string token;
        if (!string.IsNullOrWhiteSpace(_options.AccessToken))
        {
            token = _options.AccessToken.Trim();
        }
        else
        {
            try
            {
                token = VaultCredentialInput.FromVariable(_options.AccessTokenVariable!.Trim(), "GoogleSecretManagerOptions.AccessTokenVariable").Read();
            }
            catch (InvalidOperationException exception)
            {
                throw new VaultLoginException(exception.Message, exception);
            }
        }

        return new VaultToken(CheckToken(token, "token estático"), ExpiresOn: null);
    }

    // ---------- 2. Service Account JSON ----------

    private async Task<VaultToken> ServiceAccountAsync(CancellationToken cancellationToken)
    {
        var account = ServiceAccount.Read(_resolved.CredentialsJsonFile, _options.CredentialsJsonVariable, _allowedTokenHosts);
        var assertion = account.CreateJwt(_time.GetUtcNow(), Scope);
        var form = Encoding.ASCII.GetBytes("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + assertion);
        try
        {
            var client = _tokenClients.GetOrAdd(account.TokenUri.GetLeftPart(UriPartial.Authority),
                static (authority, http) => new VaultHttpClient(new Uri(authority + "/"), http), _options.Http);
            using var response = await client.SendAsync(() => new HttpRequestMessage(HttpMethod.Post, account.TokenUri)
            {
                Content = new ByteArrayContent(form) { Headers = { ContentType = new("application/x-www-form-urlencoded") } }
            }, idempotent: true, cancellationToken).ConfigureAwait(false);

            await EnsureLoginSuccessAsync(client, response, "o Google", cancellationToken).ConfigureAwait(false);
            return await ReadTokenAsync(client, response, "Google OAuth2", cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(form);
        }
    }

    // ---------- 3. Metadata Server ----------

    private async Task<VaultToken> MetadataServerAsync(CancellationToken cancellationToken)
    {
        using var response = await _metadata!.SendAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, MetadataTokenPath);
            request.Headers.TryAddWithoutValidation("Metadata-Flavor", "Google");
            return request;
        }, idempotent: true, cancellationToken).ConfigureAwait(false);

        await EnsureLoginSuccessAsync(_metadata, response, "o Metadata Server do Google", cancellationToken).ConfigureAwait(false);
        // O Metadata Server responde com Metadata-Flavor: Google; sem ele, a resposta veio de outro servidor (proxy, outra nuvem)
        if (!response.Headers.TryGetValues("Metadata-Flavor", out var flavor) || !flavor.Contains("Google", StringComparer.Ordinal))
            throw new VaultLoginException("a resposta não veio do Metadata Server do Google (sem Metadata-Flavor: Google)");
        return await ReadTokenAsync(_metadata, response, "Metadata Server", cancellationToken).ConfigureAwait(false);
    }

    // ---------- Comum ----------

    /// <summary>
    /// 4xx (exceto 408 e 429) é login recusado (<see cref="VaultLoginException"/>, com o código OAuth2 do erro, ex.:
    /// <c>invalid_grant</c>); 408, 429 e 5xx mantêm o status real (indisponível ou limite, contam no circuit breaker).
    /// </summary>
    private static async Task EnsureLoginSuccessAsync(VaultHttpClient client, HttpResponseMessage response, string source,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
            return;

        var status = response.StatusCode;
        if ((int)status is >= 400 and < 500 && status is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests))
        {
            string? code = null;
            try
            {
                var body = await client.ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
                code = OAuthError(body);
            }
            catch (Exception exception) when (exception is VaultResponseTooLargeException or TimeoutException or HttpRequestException)
            {
                // O código do erro é só para o log
            }

            response.Dispose();
            throw new VaultLoginException($"{source} recusou o login ({(int)status}{(code is null ? "" : " " + code)})");
        }

        VaultHttpClient.EnsureSuccess(response, "no login");
    }

    /// <summary>Código OAuth2 do erro (<c>error</c>, ex.: <c>invalid_grant</c>), só se for um código simples (seguro para log).</summary>
    private static string? OAuthError(byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                   document.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String &&
                   error.GetString() is { Length: > 0 and <= 64 } code && code.All(c => char.IsAsciiLetterOrDigit(c) || c == '_')
                ? code
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Resposta de token (<c>access_token</c> e <c>expires_in</c>), com o buffer zerado depois.</summary>
    private async Task<VaultToken> ReadTokenAsync(VaultHttpClient client, HttpResponseMessage response, string source,
        CancellationToken cancellationToken)
    {
        var body = await client.ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 8 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("access_token", out var token) || token.ValueKind != JsonValueKind.String)
                throw new VaultLoginException($"{source} não devolveu token");

            DateTimeOffset? expires = root.TryGetProperty("expires_in", out var seconds) && seconds.TryGetInt32(out var life) && life > 0
                ? _time.GetUtcNow().AddSeconds(life)
                : null;
            return new VaultToken(CheckToken(token.GetString(), source), expires);
        }
        catch (JsonException exception)
        {
            throw new VaultLoginException($"{source} devolveu uma resposta fora do formato", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>O token vai para o cabeçalho Authorization: só ASCII visível, com tamanho limitado.</summary>
    private static string CheckToken(string? token, string source) =>
        token is { Length: > 0 and <= MaxTokenLength } && token.All(c => c is > ' ' and <= '~')
            ? token
            : throw new VaultLoginException($"token do Google fora do formato ({source})");

    /// <summary>Service Account JSON lida (com teto) a cada login. <see cref="ToString"/> não mostra a chave.</summary>
    private sealed class ServiceAccount
    {
        private ServiceAccount(string clientEmail, string? privateKeyId, string privateKey, Uri tokenUri)
        {
            ClientEmail = clientEmail;
            PrivateKeyId = privateKeyId;
            PrivateKey = privateKey;
            TokenUri = tokenUri;
        }

        public string ClientEmail { get; }

        public string? PrivateKeyId { get; }

        public string PrivateKey { get; }

        public Uri TokenUri { get; }

        /// <summary>Lê e confere o JSON: tipo <c>service_account</c>, e-mail, chave e <c>token_uri</c> HTTPS de host permitido.</summary>
        internal static ServiceAccount Read(string? file, string? variable, HashSet<string> allowedTokenHosts)
        {
            string json;
            try
            {
                // Leitura limitada (BoundedFileReader, 64 KB), UTF-8 estrito; o arquivo é relido a cada login (rotação da chave)
                var input = !string.IsNullOrWhiteSpace(variable)
                    ? VaultCredentialInput.FromVariable(variable.Trim(), "GoogleSecretManagerOptions.CredentialsJsonVariable")
                    : VaultCredentialInput.FromFile(file!, "GoogleSecretManagerOptions.CredentialsJsonFile");
                json = input.Read();
            }
            catch (InvalidOperationException exception)
            {
                throw new VaultLoginException(exception.Message, exception);
            }

            try
            {
                using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                    throw new VaultLoginException("credencial do Google fora do formato (esperado um objeto JSON)");
                if (String(root, "type") is { } type && !string.Equals(type, "service_account", StringComparison.Ordinal))
                    throw new VaultLoginException("credencial do Google não suportada: só Service Account (type = service_account)");

                var email = String(root, "client_email");
                if (email is not { Length: > 0 and <= 320 } || !email.All(c => c is > ' ' and <= '~'))
                    throw new VaultLoginException("Service Account sem client_email válido");
                var key = String(root, "private_key");
                if (string.IsNullOrWhiteSpace(key))
                    throw new VaultLoginException("Service Account sem private_key");
                var keyId = String(root, "private_key_id");
                if (keyId is not null && (keyId.Length > 128 || !keyId.All(char.IsAsciiLetterOrDigit)))
                    keyId = null;   // o kid é opcional: um valor estranho não vai para o cabeçalho do JWT

                return new ServiceAccount(email, keyId, key, ParseTokenUri(String(root, "token_uri"), allowedTokenHosts));
            }
            catch (JsonException exception)
            {
                throw new VaultLoginException("credencial do Google com JSON inválido", exception);
            }
        }

        /// <summary>
        /// <c>token_uri</c> do JSON: HTTPS, porta padrão, sem usuário, query ou fragmento e host da lista permitida. O JWT assinado
        /// (que vale como credencial por até uma hora) só vai para lá.
        /// </summary>
        private static Uri ParseTokenUri(string? text, HashSet<string> allowedHosts)
        {
            if (!Uri.TryCreate(text ?? GoogleSecretManagerOptions.DefaultTokenUri, UriKind.Absolute, out var uri) ||
                uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort || !string.IsNullOrEmpty(uri.UserInfo) ||
                !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || !allowedHosts.Contains(uri.IdnHost))
            {
                throw new VaultLoginException("token_uri da Service Account recusado: precisa ser HTTPS e de um host de AllowedTokenHosts");
            }

            return uri;
        }

        /// <summary>JWT RS256 do fluxo de Service Account (iss, scope, aud = token_uri, iat e exp de uma hora), com JSON escapado.</summary>
        internal string CreateJwt(DateTimeOffset now, string scope)
        {
            var issuedAt = now.ToUnixTimeSeconds();
            var header = Segment(w =>
            {
                w.WriteString("alg", "RS256");
                w.WriteString("typ", "JWT");
                if (PrivateKeyId is not null)
                    w.WriteString("kid", PrivateKeyId);
            });
            var claims = Segment(w =>
            {
                w.WriteString("iss", ClientEmail);
                w.WriteString("scope", scope);
                w.WriteString("aud", TokenUri.AbsoluteUri);
                w.WriteNumber("iat", issuedAt);
                w.WriteNumber("exp", issuedAt + 3600);
            });

            var signingInput = header + "." + claims;
            using var rsa = RSA.Create();
            try
            {
                rsa.ImportFromPem(PrivateKey);
            }
            catch (Exception exception) when (exception is ArgumentException or CryptographicException)
            {
                throw new VaultLoginException("private_key da Service Account inválida", exception);
            }

            var signature = rsa.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return signingInput + "." + Base64Url.EncodeToString(signature);
        }

        /// <inheritdoc />
        public override string ToString() => $"ServiceAccount {{ ClientEmail = {ClientEmail}, PrivateKey = *** }}";

        private static string Segment(Action<Utf8JsonWriter> write)
        {
            var buffer = new ArrayBufferWriter<byte>(256);
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                write(writer);
                writer.WriteEndObject();
            }

            return Base64Url.EncodeToString(buffer.WrittenSpan);
        }

        private static string? String(JsonElement element, string name) =>
            element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}
