using TEC.Core.Text.Codecs;
using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using TEC.Vault.AzureKeyVault;

namespace TEC.Vault.LoadGenerator;

/// <summary>
/// Azure Key Vault simulado no nível HTTP, com estado e seguro para uso concorrente: o provedor roda com o SDK real (desafio de
/// autenticação, serialização, pipeline, mapeamento de erros) sem rede. Simula segredos (leitura, gravação, listagens) e chaves
/// RSA (leitura e as operações remotas decrypt, unwrap e sign), com latência e falhas injetáveis.
/// </summary>
/// <remarks>
/// Mede o custo do componente e do SDK, não o do serviço: a latência do cofre real é simulada por <see cref="Latency"/>.
/// </remarks>
public sealed class SimulatedKeyVault : HttpMessageHandler
{
    /// <summary>Endereço do cofre simulado (nenhuma requisição sai do processo).</summary>
    public const string DefaultVaultUri = "https://kv-carga.vault.azure.net/";

    private readonly ConcurrentDictionary<string, ConcurrentQueue<SecretVersion>> _secrets = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, (string Version, RSA Rsa)> _keys = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _requests = new(StringComparer.Ordinal);

    /// <param name="vaultUri">
    /// Host próprio: o SDK guarda o desafio de autenticação em cache estático por host (instâncias com o mesmo host compartilham).
    /// </param>
    public SimulatedKeyVault(string vaultUri = DefaultVaultUri)
    {
        VaultUri = vaultUri;
    }

    /// <summary>Endereço do cofre simulado.</summary>
    public string VaultUri { get; }

    /// <summary>Latência de cada resposta (simula a rede e o serviço). Padrão: zero.</summary>
    public TimeSpan Latency { get; set; }

    /// <summary>Fração das requisições autenticadas que falham (0 a 1), com <see cref="FaultStatus"/>.</summary>
    public double FaultRate { get; set; }

    /// <summary>Status das falhas injetadas (padrão 429, throttling; 503 simula o serviço fora do ar).</summary>
    public HttpStatusCode FaultStatus { get; set; } = HttpStatusCode.TooManyRequests;

    /// <summary>Total de requisições autenticadas recebidas.</summary>
    public long TotalRequests => _requests.Values.Sum();

    /// <summary>Requisições autenticadas por operação (ex.: <c>GET secret</c>, <c>POST unwrapkey</c>).</summary>
    public IReadOnlyDictionary<string, long> Requests => _requests;

    /// <summary>Grava um segredo direto no estado (sem passar pelo provedor).</summary>
    public void AddSecret(string name, string value) =>
        _secrets.GetOrAdd(name, _ => new ConcurrentQueue<SecretVersion>()).Enqueue(new SecretVersion(NewVersion(), value, Now()));

    /// <summary>Cria uma chave RSA 2048 no estado (sem passar pelo provedor) e devolve a versão.</summary>
    public string AddRsaKey(string name)
    {
        string version = NewVersion();
        var rsa = RSA.Create(2048);
        // O par é gerado de forma preguiçosa no primeiro uso: com a exportação da chave pública e a primeira decifração
        // concorrentes, cada uma poderia gerar um par diferente. Exportar aqui gera o par antes de qualquer requisição
        _ = rsa.ExportParameters(false);
        _keys[name] = (version, rsa);
        return version;
    }

    /// <summary>Zera os contadores de requisições.</summary>
    public void ResetCounters() => _requests.Clear();

    /// <summary>Opções do provedor apontando para este cofre (credencial falsa, sem retentativas por padrão).</summary>
    public void Configure(AzureKeyVaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.VaultUri = new Uri(VaultUri);
        options.Credential = new StaticCredential();
        options.MaxRetries = 0;
        options.Transport = new HttpClientTransport(new HttpClient(this, disposeHandler: false));
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request.Headers.Authorization is null)
        {
            // Desafio de autenticação, como o serviço real
            var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent(string.Empty) };
            challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                "Bearer authorization=\"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001\", resource=\"https://vault.azure.net\"");
            return challenge;
        }

        if (Latency > TimeSpan.Zero)
            await Task.Delay(Latency, cancellationToken).ConfigureAwait(false);

        string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string[] segments = request.RequestUri!.AbsolutePath.Trim('/').Split('/');

        if (FaultRate > 0 && Random.Shared.NextDouble() < FaultRate)
        {
            Count($"{request.Method.Method} falha {(int)FaultStatus}");
            return Json(FaultStatus, Error(FaultStatus == HttpStatusCode.TooManyRequests ? "Throttled" : "ServiceUnavailable"));
        }

        var (status, json, kind) = segments switch
        {
            ["secrets"] when request.Method == HttpMethod.Get => ListSecrets(),
            ["secrets", var name] when request.Method == HttpMethod.Put => SetSecret(name, body),
            ["secrets", var name] when request.Method == HttpMethod.Get => GetSecret(name, null),
            ["secrets", var name, "versions"] when request.Method == HttpMethod.Get => ListSecretVersions(name),
            ["secrets", var name, var version] when request.Method == HttpMethod.Get => GetSecret(name, version),
            ["keys", var name] when request.Method == HttpMethod.Get => GetKey(name, null),
            ["keys", var name, var version] when request.Method == HttpMethod.Get => GetKey(name, version),
            ["keys", var name, var version, var operation] when request.Method == HttpMethod.Post => KeyOperation(name, version, operation, body),
            _ => (HttpStatusCode.BadRequest, Error("BadParameter"), "não suportada")
        };

        Count($"{request.Method.Method} {kind}");
        return Json(status, json);
    }

    private (HttpStatusCode, string, string) ListSecrets()
    {
        var items = _secrets.Where(s => !s.Value.IsEmpty)
            .Select(s => $$"""{"id":"{{VaultUri}}secrets/{{s.Key}}","attributes":{{Attributes(s.Value.Last().CreatedOn)}}}""");
        return (HttpStatusCode.OK, $$"""{"value":[{{string.Join(',', items)}}],"nextLink":null}""", "list secrets");
    }

    private (HttpStatusCode, string, string) ListSecretVersions(string name)
    {
        if (!_secrets.TryGetValue(name, out var versions))
            return (HttpStatusCode.NotFound, Error("SecretNotFound"), "list secret versions");

        var items = versions.Select(v => $$"""{"id":"{{VaultUri}}secrets/{{name}}/{{v.Version}}","attributes":{{Attributes(v.CreatedOn)}}}""");
        return (HttpStatusCode.OK, $$"""{"value":[{{string.Join(',', items)}}],"nextLink":null}""", "list secret versions");
    }

    private (HttpStatusCode, string, string) GetSecret(string name, string? version)
    {
        if (!_secrets.TryGetValue(name, out var versions) || versions.IsEmpty)
            return (HttpStatusCode.NotFound, Error("SecretNotFound"), "secret");

        var found = version is null ? versions.Last() : versions.FirstOrDefault(v => string.Equals(v.Version, version, StringComparison.OrdinalIgnoreCase));
        return found is null
            ? (HttpStatusCode.NotFound, Error("SecretNotFound"), "secret")
            : (HttpStatusCode.OK, SecretBundle(name, found, includeValue: true), "secret");
    }

    private (HttpStatusCode, string, string) SetSecret(string name, string body)
    {
        using var json = JsonDocument.Parse(body);
        var created = new SecretVersion(NewVersion(), json.RootElement.GetProperty("value").GetString() ?? string.Empty, Now());
        _secrets.GetOrAdd(name, _ => new ConcurrentQueue<SecretVersion>()).Enqueue(created);
        return (HttpStatusCode.OK, SecretBundle(name, created, includeValue: true), "set secret");
    }

    private (HttpStatusCode, string, string) GetKey(string name, string? version)
    {
        if (!_keys.TryGetValue(name, out var key) || (version is not null && !string.Equals(version, key.Version, StringComparison.OrdinalIgnoreCase)))
            return (HttpStatusCode.NotFound, Error("KeyNotFound"), "key");

        var parameters = key.Rsa.ExportParameters(false);
        string json = $$"""
            {"key":{"kid":"{{VaultUri}}keys/{{name}}/{{key.Version}}","kty":"RSA","key_ops":["encrypt","decrypt","wrapKey","unwrapKey","sign","verify"],
             "n":"{{Base64Url(parameters.Modulus!)}}","e":"{{Base64Url(parameters.Exponent!)}}"},"attributes":{{Attributes(1700000000)}}}
            """;
        return (HttpStatusCode.OK, json, "key");
    }

    private (HttpStatusCode, string, string) KeyOperation(string name, string version, string operation, string body)
    {
        operation = operation.ToLowerInvariant();
        if (!_keys.TryGetValue(name, out var key) || !string.Equals(version, key.Version, StringComparison.OrdinalIgnoreCase))
            return (HttpStatusCode.NotFound, Error("KeyNotFound"), operation);

        using var json = JsonDocument.Parse(body);
        string alg = json.RootElement.GetProperty("alg").GetString() ?? string.Empty;
        byte[] value = FromBase64Url(json.RootElement.GetProperty("value").GetString() ?? string.Empty);
        try
        {
            byte[]? result = (operation, alg) switch
            {
                ("decrypt" or "unwrapkey", "RSA-OAEP-256") => key.Rsa.Decrypt(value, RSAEncryptionPadding.OaepSHA256),
                ("encrypt" or "wrapkey", "RSA-OAEP-256") => key.Rsa.Encrypt(value, RSAEncryptionPadding.OaepSHA256),
                ("sign", "RS256") => key.Rsa.SignHash(value, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                ("sign", "PS256") => key.Rsa.SignHash(value, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                _ => null
            };

            return result is null
                ? (HttpStatusCode.BadRequest, Error("BadParameter"), operation)
                : (HttpStatusCode.OK, $$"""{"kid":"{{VaultUri}}keys/{{name}}/{{key.Version}}","value":"{{Base64Url(result)}}"}""", operation);
        }
        catch (CryptographicException)
        {
            return (HttpStatusCode.BadRequest, Error("BadParameter"), operation);
        }
    }

    private string SecretBundle(string name, SecretVersion version, bool includeValue) =>
        "{" + (includeValue ? $"\"value\":{JsonSerializer.Serialize(version.Value)}," : string.Empty) +
        $$$"""
        "id":"{{{VaultUri}}}secrets/{{{name}}}/{{{version.Version}}}","contentType":"text/plain","attributes":{{{Attributes(version.CreatedOn)}}},"tags":{}}
        """;

    private static string Attributes(long created) =>
        $$"""{"enabled":true,"created":{{created}},"updated":{{created}},"recoveryLevel":"Recoverable+Purgeable"}""";

    private static string Error(string code) => $$$"""{"error":{"code":"{{{code}}}","message":"Erro simulado."}}""";

    private static HttpResponseMessage Json(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private void Count(string kind) => _requests.AddOrUpdate(kind, 1, (_, count) => count + 1);

    private static string NewVersion() => Guid.NewGuid().ToString("N");

    private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    private static string Base64Url(byte[] data) => Base64UrlEncoder.Encode(data);

    private static byte[] FromBase64Url(string value) =>
        Base64UrlEncoder.TryDecode(value, out var bytes) ? bytes : throw new FormatException("Base64Url inválido na requisição.");

    private sealed record SecretVersion(string Version, string Value, long CreatedOn);

    /// <summary>Credencial falsa: o cofre simulado só confere a presença do cabeçalho de autorização.</summary>
    private sealed class StaticCredential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            new("token-de-carga", DateTimeOffset.UtcNow.AddHours(1));

        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(requestContext, cancellationToken));
    }
}
