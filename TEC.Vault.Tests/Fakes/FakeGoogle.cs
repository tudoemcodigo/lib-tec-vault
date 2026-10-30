using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TEC.Vault.GoogleSecretManager;

namespace TEC.Vault.Tests.Fakes;

/// <summary>
/// Google Cloud simulado em HTTP: Secret Manager (API REST v1, Bearer obrigatório), troca do JWT da Service Account por token
/// (assinatura RS256 e claims conferidos) e Metadata Server (com <c>Metadata-Flavor: Google</c>).
/// </summary>
internal sealed class FakeGoogle : HttpMessageHandler
{
    public const string ProjectId = "projeto-teste";
    public const string ClientEmail = "app@projeto-teste.iam.gserviceaccount.com";

    private sealed class Secret
    {
        public List<(int Number, string Value, string State)> Versions { get; } = [];

        public Dictionary<string, string> Labels { get; } = new(StringComparer.Ordinal);
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, Secret> _secrets = new(StringComparer.Ordinal);
    private readonly HashSet<string> _tokens = new(StringComparer.Ordinal);
    private int _issued;

    /// <summary>Chave da Service Account (a pública confere o JWT).</summary>
    public RSA ServiceAccountKey { get; } = RSA.Create(2048);

    public int ExpiresIn { get; set; } = 3600;

    public bool MetadataFlavor { get; set; } = true;

    public HttpStatusCode? MetadataStatus { get; set; }

    /// <summary>Itens por página que a API simulada devolve (no máximo o pageSize pedido).</summary>
    public int PageSize { get; set; } = 100;

    public int TokenCalls;
    public int MetadataCalls;

    public ConcurrentQueue<string> Requests { get; } = new();

    /// <summary>Hosts inesperados que receberam alguma requisição (ex.: um token_uri adulterado).</summary>
    public ConcurrentQueue<string> UnexpectedHosts { get; } = new();

    /// <summary>Status a devolver nas próximas trocas de JWT (com <c>error = invalid_grant</c>).</summary>
    public ConcurrentQueue<HttpStatusCode> TokenFailures { get; } = new();

    public void AddToken(string token)
    {
        lock (_sync)
            _tokens.Add(token);
    }

    public void RevokeTokens()
    {
        lock (_sync)
            _tokens.Clear();
    }

    public void Seed(string name, string value, IReadOnlyDictionary<string, string>? labels = null)
    {
        lock (_sync)
        {
            var secret = new Secret();
            secret.Versions.Add((1, value, "ENABLED"));
            foreach (var (key, label) in labels ?? new Dictionary<string, string>())
                secret.Labels[key] = label;
            _secrets[name] = secret;
        }
    }

    public IReadOnlyDictionary<string, string> LabelsOf(string name)
    {
        lock (_sync)
            return new Dictionary<string, string>(_secrets[name].Labels, StringComparer.Ordinal);
    }

    public string StateOf(string name, int version)
    {
        lock (_sync)
            return _secrets[name].Versions.Single(v => v.Number == version).State;
    }

    /// <summary>JSON de Service Account com a chave deste fake (o <c>token_uri</c> pode ser trocado pelo teste).</summary>
    public string ServiceAccountJson(string? tokenUri = "https://oauth2.googleapis.com/token", string type = "service_account")
    {
        var json = new JsonObject
        {
            ["type"] = type,
            ["project_id"] = ProjectId,
            ["private_key_id"] = "abc123",
            ["private_key"] = ServiceAccountKey.ExportPkcs8PrivateKeyPem(),
            ["client_email"] = ClientEmail
        };
        if (tokenUri is not null)
            json["token_uri"] = tokenUri;
        return json.ToJsonString();
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Enqueue($"{request.Method} {request.RequestUri!.Host}{request.RequestUri.PathAndQuery}");
        return request.RequestUri.Host switch
        {
            "oauth2.googleapis.com" => Token(body),
            "metadata.google.internal" => Metadata(request),
            "secretmanager.googleapis.com" => Api(request, body),
            var other => Unexpected(other)
        };
    }

    private HttpResponseMessage Unexpected(string host)
    {
        UnexpectedHosts.Enqueue(host);
        return Json(new JsonObject { ["access_token"] = "token-roubado", ["expires_in"] = 3600 });
    }

    // ---------- Troca do JWT ----------

    private HttpResponseMessage Token(string body)
    {
        Interlocked.Increment(ref TokenCalls);
        if (TokenFailures.TryDequeue(out var failure))
            return Json(new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "detalhe-interno" }, failure);

        var form = body.Split('&').Select(p => p.Split('=', 2)).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]), StringComparer.Ordinal);
        if (form.GetValueOrDefault("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || form.GetValueOrDefault("assertion") is not { } jwt)
            return Json(new JsonObject { ["error"] = "unsupported_grant_type" }, HttpStatusCode.BadRequest);

        var parts = jwt.Split('.');
        if (parts.Length != 3 || !ServiceAccountKey.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Base64Url.DecodeFromChars(parts[2]),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            return Json(new JsonObject { ["error"] = "invalid_grant" }, HttpStatusCode.BadRequest);

        using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
        using var claims = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
        var c = claims.RootElement;
        var valid = header.RootElement.GetProperty("alg").GetString() == "RS256" &&
                    c.GetProperty("iss").GetString() == ClientEmail &&
                    c.GetProperty("aud").GetString() == "https://oauth2.googleapis.com/token" &&
                    c.GetProperty("scope").GetString() == "https://www.googleapis.com/auth/cloud-platform" &&
                    c.GetProperty("exp").GetInt64() - c.GetProperty("iat").GetInt64() <= 3600;
        if (!valid)
            return Json(new JsonObject { ["error"] = "invalid_grant" }, HttpStatusCode.BadRequest);

        var token = "ya29.sa-" + Interlocked.Increment(ref _issued).ToString(CultureInfo.InvariantCulture);
        AddToken(token);
        return Json(new JsonObject { ["access_token"] = token, ["expires_in"] = ExpiresIn, ["token_type"] = "Bearer" });
    }

    // ---------- Metadata Server ----------

    private HttpResponseMessage Metadata(HttpRequestMessage request)
    {
        Interlocked.Increment(ref MetadataCalls);
        if (!request.Headers.TryGetValues("Metadata-Flavor", out var flavor) || flavor.Single() != "Google")
            return new HttpResponseMessage(HttpStatusCode.Forbidden);

        HttpResponseMessage response;
        if (MetadataStatus is { } status)
        {
            response = new HttpResponseMessage(status);
        }
        else
        {
            var token = "ya29.md-" + Interlocked.Increment(ref _issued).ToString(CultureInfo.InvariantCulture);
            AddToken(token);
            response = Json(new JsonObject { ["access_token"] = token, ["expires_in"] = ExpiresIn, ["token_type"] = "Bearer" });
        }

        if (MetadataFlavor)
            response.Headers.Add("Metadata-Flavor", "Google");
        return response;
    }

    // ---------- Secret Manager ----------

    private HttpResponseMessage Api(HttpRequestMessage request, string body)
    {
        bool authorized;
        lock (_sync)
            authorized = request.Headers.Authorization is { Scheme: "Bearer", Parameter: { } token } && _tokens.Contains(token);
        if (!authorized)
            return Status(HttpStatusCode.Unauthorized, "UNAUTHENTICATED");

        var prefix = $"/v1/projects/{ProjectId}/secrets";
        var path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
        var query = request.RequestUri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2)).ToDictionary(p => p[0], p => Uri.UnescapeDataString(p.Length > 1 ? p[1] : ""), StringComparer.Ordinal);
        if (!path.StartsWith(prefix, StringComparison.Ordinal))
            return Status(HttpStatusCode.NotFound, "NOT_FOUND");

        var rest = path[prefix.Length..].TrimStart('/');
        lock (_sync)
        {
            if (rest.Length == 0)
            {
                if (request.Method == HttpMethod.Get)
                    return Page(_secrets.OrderBy(s => s.Key, StringComparer.Ordinal).Select(s => (JsonNode)SecretJson(s.Key, s.Value)).ToList(), "secrets", query);

                var name = query["secretId"];
                if (_secrets.ContainsKey(name))
                    return Status(HttpStatusCode.Conflict, "ALREADY_EXISTS");
                var created = new Secret();
                foreach (var label in JsonNode.Parse(body)!["labels"]?.AsObject() ?? new JsonObject())
                    created.Labels[label.Key] = (string)label.Value!;
                _secrets[name] = created;
                return Json(SecretJson(name, created));
            }

            var segments = rest.Split('/');
            var secretName = segments[0].Split(':')[0];
            if (!_secrets.TryGetValue(secretName, out var secret))
                return Status(HttpStatusCode.NotFound, "NOT_FOUND");

            if (segments.Length == 1)
            {
                if (segments[0].EndsWith(":addVersion", StringComparison.Ordinal))
                {
                    var value = Encoding.UTF8.GetString(Convert.FromBase64String((string)JsonNode.Parse(body)!["payload"]!["data"]!));
                    secret.Versions.Add((secret.Versions.Count + 1, value, "ENABLED"));
                    return Json(VersionJson(secretName, secret.Versions[^1]));
                }

                if (request.Method == HttpMethod.Delete)
                {
                    _secrets.Remove(secretName);
                    return Json(new JsonObject());
                }

                if (request.Method == HttpMethod.Patch)
                {
                    if (query.GetValueOrDefault("updateMask") != "labels")
                        return Status(HttpStatusCode.BadRequest, "INVALID_ARGUMENT");
                    secret.Labels.Clear();
                    foreach (var label in JsonNode.Parse(body)!["labels"]?.AsObject() ?? new JsonObject())
                        secret.Labels[label.Key] = (string)label.Value!;
                }

                return Json(SecretJson(secretName, secret));
            }

            if (segments.Length == 2 && segments[1] == "versions")
                return Page(secret.Versions.Select(v => (JsonNode)VersionJson(secretName, v)).ToList(), "versions", query);

            var versionText = segments[2].Split(':')[0];
            var action = segments[2].Contains(':', StringComparison.Ordinal) ? segments[2][(segments[2].IndexOf(':') + 1)..] : null;
            var index = versionText == "latest" ? secret.Versions.Count - 1 : int.Parse(versionText, CultureInfo.InvariantCulture) - 1;
            if (index < 0 || index >= secret.Versions.Count)
                return Status(HttpStatusCode.NotFound, "NOT_FOUND");

            var version = secret.Versions[index];
            switch (action)
            {
                case "access":
                    if (version.State != "ENABLED")
                        return Status(HttpStatusCode.BadRequest, "FAILED_PRECONDITION");
                    var access = VersionJson(secretName, version);
                    access["payload"] = new JsonObject { ["data"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(version.Value)) };
                    return Json(access);
                case "enable" or "disable":
                    secret.Versions[index] = version with { State = action == "enable" ? "ENABLED" : "DISABLED" };
                    return Json(VersionJson(secretName, secret.Versions[index]));
                default:
                    return Json(VersionJson(secretName, version));
            }
        }
    }

    private static JsonObject SecretJson(string name, Secret secret)
    {
        var labels = new JsonObject();
        foreach (var (key, value) in secret.Labels)
            labels[key] = value;
        return new JsonObject
        {
            ["name"] = $"projects/123456/secrets/{name}",
            ["createTime"] = "2026-10-01T12:00:00.123456789Z",
            ["labels"] = labels
        };
    }

    private static JsonObject VersionJson(string name, (int Number, string Value, string State) version) => new()
    {
        ["name"] = $"projects/123456/secrets/{name}/versions/{version.Number.ToString(CultureInfo.InvariantCulture)}",
        ["state"] = version.State,
        ["createTime"] = "2026-10-01T12:00:00Z"
    };

    private HttpResponseMessage Page(List<JsonNode> all, string field, Dictionary<string, string> query)
    {
        var start = int.Parse(query.GetValueOrDefault("pageToken") ?? "0", CultureInfo.InvariantCulture);
        var size = Math.Min(PageSize, int.Parse(query.GetValueOrDefault("pageSize") ?? "100", CultureInfo.InvariantCulture));
        var result = new JsonObject { [field] = new JsonArray(all.Skip(start).Take(size).Select(n => (JsonNode?)n.DeepClone()).ToArray()) };
        if (start + size < all.Count)
            result["nextPageToken"] = (start + size).ToString(CultureInfo.InvariantCulture);
        return Json(result);
    }

    private static HttpResponseMessage Json(JsonNode node, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json")
    };

    private static HttpResponseMessage Status(HttpStatusCode status, string code) =>
        Json(new JsonObject { ["error"] = new JsonObject { ["code"] = (int)status, ["message"] = "detalhe-interno-do-google", ["status"] = code } }, status);
}

/// <summary>Opções do provedor Google apontadas para o <see cref="FakeGoogle"/>, sem tocar no ambiente do processo.</summary>
internal static class GoogleTestOptions
{
    /// <summary>Token estático aceito pelo fake; Metadata Server desligado (cada teste liga o que precisa).</summary>
    public static GoogleSecretManagerOptions Create(FakeGoogle fake, Action<GoogleSecretManagerOptions>? configure = null,
        Dictionary<string, string?>? variables = null)
    {
        variables ??= [];
        fake.AddToken("ya29.estatico");
        var options = new GoogleSecretManagerOptions
        {
            ProjectId = FakeGoogle.ProjectId,
            AccessToken = "ya29.estatico",
            UseMetadataServer = false,
            ReadVariable = name => variables.TryGetValue(name, out var value) ? value : null
        };
        options.Http.Handler = fake;
        options.Http.CircuitBreaker.Enabled = false;
        configure?.Invoke(options);
        return options;
    }
}
