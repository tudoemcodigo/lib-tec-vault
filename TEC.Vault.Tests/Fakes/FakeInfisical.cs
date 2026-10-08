using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TEC.Vault.Tests.Fakes;

/// <summary>
/// Infisical simulado em HTTP (API v4 de segredos, Universal Auth e Kubernetes Auth), com o comportamento documentado:
/// nomes que diferenciam maiúsculas, versões sequenciais, 400 ao criar nome existente, 404 para inexistente.
/// </summary>
internal sealed class FakeInfisical : HttpMessageHandler
{
    public const string ProjectId = "proj-1";
    public const string Environment = "prod";
    public const string ClientId = "client-1";
    public const string IdentityId = "identity-1";

    private sealed record Version(long Number, string Value, Dictionary<string, string> Metadata, DateTimeOffset At);

    private readonly object _sync = new();
    private readonly Dictionary<string, List<Version>> _secrets = new(StringComparer.Ordinal);
    private readonly HashSet<string> _tokens = [];
    private int _tokenCounter;

    public string ClientSecret { get; set; } = "segredo-do-cliente";

    public string ServiceAccountJwt { get; set; } = "jwt-do-pod";

    public string SecretPath { get; set; } = "/";

    public double ExpiresIn { get; set; } = 3600;

    public int Logins;

    public ConcurrentQueue<string> Requests { get; } = new();

    /// <summary>Status a devolver nas próximas requisições de segredos (antes de processá-las).</summary>
    public ConcurrentQueue<HttpStatusCode> Failures { get; } = new();

    /// <summary>Status a devolver nas próximas escritas (POST/PATCH/DELETE de segredos).</summary>
    public ConcurrentQueue<HttpStatusCode> WriteFailures { get; } = new();

    /// <summary>Escritas ficam pendentes de aprovação (resposta com <c>approval</c>).</summary>
    public bool RequireApproval { get; set; }

    /// <summary>Corpo devolvido nas respostas de erro (para conferir que nunca vai para log).</summary>
    public string ErrorBody { get; set; } = """{"statusCode":400,"message":"detalhe-interno-do-servidor","error":"Bad Request"}""";

    public void RevokeTokens()
    {
        lock (_sync)
            _tokens.Clear();
    }

    public void Seed(string key, string value)
    {
        lock (_sync)
            _secrets[key] = [new Version(1, value, [], DateTimeOffset.UtcNow)];
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath.TrimStart('/');
        Requests.Enqueue($"{request.Method} {path}");
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);

        if (path.StartsWith("api/v1/auth/", StringComparison.Ordinal))
            return Login(path, body);

        if (request.Headers.Authorization is not { Scheme: "Bearer" } auth || !IsValid(auth.Parameter))
            return Error(HttpStatusCode.Unauthorized);

        if (Failures.TryDequeue(out var failure))
        {
            var response = Error(failure);
            if (failure == HttpStatusCode.TooManyRequests)
                response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.Zero);
            return response;
        }

        if (request.Method != HttpMethod.Get && WriteFailures.TryDequeue(out var writeFailure))
            return Error(writeFailure);

        var query = Query(request.RequestUri);
        if (!path.StartsWith("api/v4/secrets", StringComparison.Ordinal))
            return Error(HttpStatusCode.NotFound);

        var key = path.Length > "api/v4/secrets/".Length ? Uri.UnescapeDataString(path["api/v4/secrets/".Length..]) : null;
        lock (_sync)
        {
            if (request.Method == HttpMethod.Get)
            {
                if (!Scope(query.GetValueOrDefault("projectId"), query.GetValueOrDefault("environment"), query.GetValueOrDefault("secretPath")))
                    return Error(HttpStatusCode.NotFound);
                var view = query.GetValueOrDefault("viewSecretValue") != "false";
                if (key is null)
                {
                    var list = new JsonArray(_secrets.Select(kv => Secret(kv.Key, kv.Value[^1], view)).ToArray<JsonNode?>());
                    return Json(new JsonObject { ["secrets"] = list, ["imports"] = new JsonArray() });
                }

                if (!_secrets.TryGetValue(key, out var versions))
                    return Error(HttpStatusCode.NotFound);
                var version = query.TryGetValue("version", out var v) ? versions.FirstOrDefault(x => x.Number == long.Parse(v, CultureInfo.InvariantCulture)) : versions[^1];
                return version is null ? Error(HttpStatusCode.NotFound) : Json(new JsonObject { ["secret"] = Secret(key, version, view) });
            }

            var json = JsonNode.Parse(body ?? "{}")!.AsObject();
            if (!Scope((string?)json["projectId"], (string?)json["environment"], (string?)json["secretPath"]))
                return Error(HttpStatusCode.NotFound);
            if (key is null)
                return Error(HttpStatusCode.NotFound);
            if (RequireApproval)
                return Json(new JsonObject { ["approval"] = new JsonObject { ["id"] = Guid.NewGuid().ToString() } });

            var metadata = json["secretMetadata"] is JsonArray items
                ? items.ToDictionary(i => (string)i!["key"]!, i => (string?)i!["value"] ?? "")
                : null;

            if (request.Method == HttpMethod.Post)
            {
                if (_secrets.ContainsKey(key))
                    return Error(HttpStatusCode.BadRequest);
                var created = new Version(1, (string)json["secretValue"]!, metadata ?? [], DateTimeOffset.UtcNow);
                _secrets[key] = [created];
                return Json(new JsonObject { ["secret"] = Secret(key, created, view: true) });
            }

            if (!_secrets.TryGetValue(key, out var existing))
                return Error(HttpStatusCode.NotFound);

            if (request.Method == HttpMethod.Patch)
            {
                var last = existing[^1];
                var next = new Version(last.Number + 1, (string?)json["secretValue"] ?? last.Value, metadata ?? last.Metadata, DateTimeOffset.UtcNow);
                existing.Add(next);
                return Json(new JsonObject { ["secret"] = Secret(key, next, view: true) });
            }

            if (request.Method == HttpMethod.Delete)
            {
                _secrets.Remove(key);
                return Json(new JsonObject { ["secret"] = Secret(key, existing[^1], view: false) });
            }
        }

        return Error(HttpStatusCode.MethodNotAllowed);
    }

    private HttpResponseMessage Login(string path, string? body)
    {
        var json = JsonNode.Parse(body ?? "{}")!.AsObject();
        var ok = path switch
        {
            "api/v1/auth/universal-auth/login" => (string?)json["clientId"] == ClientId && (string?)json["clientSecret"] == ClientSecret,
            "api/v1/auth/kubernetes-auth/login" => (string?)json["identityId"] == IdentityId && (string?)json["jwt"] == ServiceAccountJwt,
            _ => false
        };
        if (!ok)
            return Error(HttpStatusCode.Unauthorized);

        Interlocked.Increment(ref Logins);
        var token = "tok-" + Interlocked.Increment(ref _tokenCounter);
        lock (_sync)
            _tokens.Add(token);
        return Json(new JsonObject { ["accessToken"] = token, ["expiresIn"] = ExpiresIn, ["accessTokenMaxTTL"] = 86400, ["tokenType"] = "Bearer" });
    }

    private bool IsValid(string? token)
    {
        lock (_sync)
            return token is not null && _tokens.Contains(token);
    }

    private bool Scope(string? project, string? environment, string? secretPath) =>
        project == ProjectId && environment == Environment && (secretPath ?? "/") == SecretPath;

    private JsonObject Secret(string key, Version version, bool view) => new()
    {
        ["id"] = key + "-id",
        ["_id"] = key + "-id",
        ["workspace"] = ProjectId,
        ["environment"] = Environment,
        ["version"] = version.Number,
        ["type"] = "shared",
        ["secretKey"] = key,
        ["secretValue"] = view ? version.Value : "<hidden-by-infisical>",
        ["secretValueHidden"] = !view,
        ["secretComment"] = "",
        ["secretPath"] = SecretPath,
        ["createdAt"] = version.At.ToString("O"),
        ["updatedAt"] = version.At.ToString("O"),
        ["secretMetadata"] = new JsonArray(version.Metadata.Select(m => (JsonNode?)new JsonObject { ["key"] = m.Key, ["value"] = m.Value, ["isEncrypted"] = false }).ToArray())
    };

    private static Dictionary<string, string> Query(Uri uri) =>
        uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => p[0], p => Uri.UnescapeDataString(p.Length > 1 ? p[1] : ""));

    private static HttpResponseMessage Json(JsonNode node) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json")
    };

    private HttpResponseMessage Error(HttpStatusCode status) => new(status)
    {
        Content = new StringContent(ErrorBody, Encoding.UTF8, "application/json")
    };
}
