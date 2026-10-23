using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TEC.Vault.GoogleSecretManager.Internal;

/// <summary>
/// Gerenciador nativo de tokens de autenticação OAuth2 para serviços do Google Cloud.
/// Não utiliza bibliotecas pesadas de terceiros; compatível com Native AOT.
/// </summary>
internal sealed class GoogleTokenSource
{
    private readonly GoogleSecretManagerOptions _options;
    private readonly HttpClient _authClient;
    private readonly TimeProvider _time;
    private readonly Lock _lock = new();

    private string? _cachedToken;
    private DateTimeOffset _expiresAt = DateTimeOffset.MinValue;

    public GoogleTokenSource(GoogleSecretManagerOptions options, HttpClient authClient)
    {
        _options = options;
        _authClient = authClient;
        _time = options.TimeProvider ?? TimeProvider.System;
    }

    public async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        // 1. Token estático
        if (!string.IsNullOrWhiteSpace(_options.AccessToken))
            return _options.AccessToken;

        if (!string.IsNullOrWhiteSpace(_options.AccessTokenVariable) &&
            Environment.GetEnvironmentVariable(_options.AccessTokenVariable) is { Length: > 0 } envToken)
            return envToken;

        // 2. Cache em memória com renovação com margem de segurança de 1 minuto
        var now = _time.GetUtcNow();
        lock (_lock)
        {
            if (_cachedToken is not null && _expiresAt > now.AddMinutes(1))
                return _cachedToken;
        }

        // 3. Service Account JSON
        var jsonContent = GetServiceAccountJson();
        if (jsonContent is not null)
        {
            var token = await AcquireTokenFromServiceAccountAsync(jsonContent, cancellationToken).ConfigureAwait(false);
            return token;
        }

        // 4. Servidor de Metadados GCP (Compute Engine, Cloud Run, GKE)
        if (_options.UseMetadataServer)
        {
            try
            {
                var token = await AcquireTokenFromMetadataServerAsync(cancellationToken).ConfigureAwait(false);
                return token;
            }
            catch
            {
                // Cai para fallback ou falha
            }
        }

        throw new InvalidOperationException("Nenhuma credencial do Google Cloud foi configurada (AccessToken, GOOGLE_APPLICATION_CREDENTIALS ou Metadata Server).");
    }

    private string? GetServiceAccountJson()
    {
        if (!string.IsNullOrWhiteSpace(_options.CredentialsJsonVariable) &&
            Environment.GetEnvironmentVariable(_options.CredentialsJsonVariable) is { Length: > 0 } varContent)
            return varContent;

        if (!string.IsNullOrWhiteSpace(_options.CredentialsJsonFile) && File.Exists(_options.CredentialsJsonFile))
            return File.ReadAllText(_options.CredentialsJsonFile);

        return null;
    }

    private async Task<string> AcquireTokenFromServiceAccountAsync(string json, CancellationToken cancellationToken)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var clientEmail = root.GetProperty("client_email").GetString()
            ?? throw new InvalidOperationException("Service Account JSON inválido: client_email ausente.");
        var privateKeyPem = root.GetProperty("private_key").GetString()
            ?? throw new InvalidOperationException("Service Account JSON inválido: private_key ausente.");
        var tokenUri = root.TryGetProperty("token_uri", out var tu) ? tu.GetString() ?? "https://oauth2.googleapis.com/token" : "https://oauth2.googleapis.com/token";

        var assertion = CreateSignedJwt(clientEmail, tokenUri, privateKeyPem);

        var body = $"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={Uri.EscapeDataString(assertion)}";
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenUri)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded")
        };

        using var response = await _authClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var responseContent = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"Falha na autenticação OAuth2 do Google Cloud: {response.StatusCode} - {responseContent}");

        using var resDoc = JsonDocument.Parse(responseContent);
        var resRoot = resDoc.RootElement;
        var token = resRoot.GetProperty("access_token").GetString()
            ?? throw new InvalidOperationException("Token OAuth2 não retornado na resposta do Google.");

        var expiresIn = resRoot.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;

        lock (_lock)
        {
            _cachedToken = token;
            _expiresAt = _time.GetUtcNow().AddSeconds(expiresIn);
        }

        return token;
    }

    private async Task<string> AcquireTokenFromMetadataServerAsync(CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token");
        request.Headers.Add("Metadata-Flavor", "Google");

        using var response = await _authClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(content);
        var token = doc.RootElement.GetProperty("access_token").GetString()!;
        var expiresIn = doc.RootElement.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;

        lock (_lock)
        {
            _cachedToken = token;
            _expiresAt = _time.GetUtcNow().AddSeconds(expiresIn);
        }

        return token;
    }

    private string CreateSignedJwt(string clientEmail, string audience, string privateKeyPem)
    {
        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        var exp = now + 3600;

        var header = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"RS256\",\"typ\":\"JWT\"}"));
        var payload = Base64UrlEncode(Encoding.UTF8.GetBytes($"{{\"iss\":\"{clientEmail}\",\"scope\":\"https://www.googleapis.com/auth/cloud-platform\",\"aud\":\"{audience}\",\"exp\":{exp},\"iat\":{now}}}"));

        var unsignedToken = $"{header}.{payload}";
        var dataToSign = Encoding.UTF8.GetBytes(unsignedToken);

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);

        var signature = rsa.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{unsignedToken}.{Base64UrlEncode(signature)}";
    }

    private static string Base64UrlEncode(byte[] input) =>
        Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
