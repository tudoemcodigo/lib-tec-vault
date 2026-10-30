using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using TEC.Vault.AwsSecretsManager;

namespace TEC.Vault.Tests.Fakes;

/// <summary>
/// AWS simulada em HTTP, com o comportamento documentado: Secrets Manager (protocolo JSON 1.1, erros em HTTP 400 com
/// <c>__type</c>, assinatura SigV4 conferida contra a requisição enviada), STS (<c>AssumeRoleWithWebIdentity</c> em XML),
/// endpoint de credenciais do container e IMDSv2.
/// </summary>
internal sealed partial class FakeAws : HttpMessageHandler
{
    public const string Region = "sa-east-1";
    public const string StaticAccessKey = "AKIAIOSFODNN7EXAMPLE";
    public const string StaticSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    public const string Endpoint = "https://secretsmanager.sa-east-1.amazonaws.com/";
    public const string ImdsRole = "papel-da-instancia";

    private sealed class Secret
    {
        public List<(string Id, string Value, DateTimeOffset At)> Versions { get; } = [];

        public Dictionary<string, string> Tags { get; } = new(StringComparer.Ordinal);

        public DateTimeOffset? DeletedAt { get; set; }
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, Secret> _secrets = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (string Secret, string? Session)> _keys = new(StringComparer.Ordinal)
    {
        [StaticAccessKey] = (StaticSecretKey, null)
    };
    private readonly HashSet<string> _expired = new(StringComparer.Ordinal);
    private int _issued;

    public string WebIdentityToken { get; set; } = "jwt-da-service-account";

    public string? ContainerAuthorization { get; set; }

    public bool ImdsReachable { get; set; } = true;

    public TimeSpan CredentialLifetime { get; set; } = TimeSpan.FromHours(1);

    public Func<DateTimeOffset> Now { get; set; } = () => DateTimeOffset.UtcNow;

    /// <summary>Itens por página que a API simulada devolve (no máximo o MaxResults pedido).</summary>
    public int PageSize { get; set; } = 100;

    public int StsCalls;
    public int ContainerCalls;
    public int ImdsCalls;

    /// <summary>Ações recebidas pelo Secrets Manager (<c>X-Amz-Target</c> sem o prefixo).</summary>
    public ConcurrentQueue<string> Actions { get; } = new();

    /// <summary>Respostas de erro a devolver nas próximas chamadas ao Secrets Manager (status e <c>__type</c>).</summary>
    public ConcurrentQueue<(HttpStatusCode Status, string? Type)> Failures { get; } = new();

    /// <summary>Respostas de erro a devolver nas próximas chamadas ao STS (status e <c>Code</c>).</summary>
    public ConcurrentQueue<(HttpStatusCode Status, string Code)> StsFailures { get; } = new();

    /// <summary><c>ClientRequestToken</c> recebidos nas gravações.</summary>
    public ConcurrentQueue<string> ClientRequestTokens { get; } = new();

    /// <summary>Tokens de web identity recebidos pelo STS.</summary>
    public ConcurrentQueue<string> ReceivedWebIdentityTokens { get; } = new();

    public void Seed(string name, string value, IReadOnlyDictionary<string, string>? tags = null)
    {
        lock (_sync)
        {
            var secret = new Secret();
            secret.Versions.Add((Guid.NewGuid().ToString(), value, Now()));
            foreach (var (key, tagValue) in tags ?? new Dictionary<string, string>())
                secret.Tags[key] = tagValue;
            _secrets[name] = secret;
        }
    }

    public IReadOnlyDictionary<string, string> TagsOf(string name)
    {
        lock (_sync)
            return new Dictionary<string, string>(_secrets[name].Tags, StringComparer.Ordinal);
    }

    public int VersionCount(string name)
    {
        lock (_sync)
            return _secrets[name].Versions.Count;
    }

    /// <summary>Faz a credencial temporária ou estática deixar de valer (a AWS responde <c>ExpiredTokenException</c>).</summary>
    public void Expire(string accessKey)
    {
        lock (_sync)
        {
            _keys.Remove(accessKey);
            _expired.Add(accessKey);
        }
    }

    /// <summary>Chaves de acesso aceitas no momento (as temporárias emitidas e a estática, se não expirou).</summary>
    public IReadOnlyCollection<string> ValidKeys
    {
        get
        {
            lock (_sync)
                return [.. _keys.Keys];
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var host = request.RequestUri!.Host;
        if (host == "169.254.169.254")
            return Imds(request);
        if (host is "169.254.170.2" or "169.254.170.23")
            return Container(request);
        if (host.StartsWith("sts.", StringComparison.Ordinal))
            return Sts(body);
        return SecretsManager(request, body);
    }

    // ---------- Secrets Manager ----------

    private HttpResponseMessage SecretsManager(HttpRequestMessage request, byte[] body)
    {
        var action = request.Headers.TryGetValues("X-Amz-Target", out var targets) ? targets.Single()["secretsmanager.".Length..] : "";
        Actions.Enqueue(action);
        if (Verify(request, body) is { } authError)
            return Error(HttpStatusCode.BadRequest, authError);
        if (Failures.TryDequeue(out var failure))
            return Error(failure.Status, failure.Type);

        var input = JsonNode.Parse(body)!.AsObject();
        var id = (string?)input["SecretId"] ?? (string?)input["Name"];
        lock (_sync)
        {
            _secrets.TryGetValue(id ?? "", out var secret);
            var alive = secret is { DeletedAt: null };
            switch (action)
            {
                case "GetSecretValue":
                {
                    if (!alive)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    var wanted = (string?)input["VersionId"];
                    var version = wanted is null ? secret!.Versions[^1] : secret!.Versions.Find(v => v.Id == wanted);
                    if (version.Id is null)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    return Json(new JsonObject
                    {
                        ["Name"] = id, ["VersionId"] = version.Id, ["SecretString"] = version.Value, ["CreatedDate"] = Epoch(version.At)
                    });
                }
                case "DescribeSecret":
                    if (secret is null)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    return Json(Describe(id!, secret));
                case "ListSecrets":
                {
                    var start = int.Parse((string?)input["NextToken"] ?? "0", CultureInfo.InvariantCulture);
                    var size = Math.Min(PageSize, (int?)input["MaxResults"] ?? 100);
                    var all = _secrets.Where(s => s.Value.DeletedAt is null).OrderBy(s => s.Key, StringComparer.Ordinal).ToList();
                    var page = all.Skip(start).Take(size).Select(s => (JsonNode?)Describe(s.Key, s.Value, listing: true)).ToArray();
                    var result = new JsonObject { ["SecretList"] = new JsonArray(page) };
                    if (start + size < all.Count)
                        result["NextToken"] = (start + size).ToString(CultureInfo.InvariantCulture);
                    return Json(result);
                }
                case "ListSecretVersionIds":
                    if (!alive)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    return Json(new JsonObject
                    {
                        ["Versions"] = new JsonArray(secret!.Versions.Select(v => (JsonNode?)new JsonObject
                        {
                            ["VersionId"] = v.Id, ["CreatedDate"] = Epoch(v.At),
                            ["VersionStages"] = new JsonArray(v.Id == secret.Versions[^1].Id ? "AWSCURRENT" : "AWSPREVIOUS")
                        }).ToArray())
                    });
                case "CreateSecret":
                {
                    var token = (string)input["ClientRequestToken"]!;
                    ClientRequestTokens.Enqueue(token);
                    if (secret is not null)
                        return Error(HttpStatusCode.BadRequest, secret.DeletedAt is null ? "ResourceExistsException" : "InvalidRequestException");
                    var created = new Secret();
                    created.Versions.Add((token, (string)input["SecretString"]!, Now()));
                    foreach (var tag in input["Tags"]?.AsArray() ?? [])
                        created.Tags[(string)tag!["Key"]!] = (string)tag["Value"]!;
                    _secrets[id!] = created;
                    return Json(new JsonObject { ["Name"] = id, ["VersionId"] = token });
                }
                case "PutSecretValue":
                {
                    var token = (string)input["ClientRequestToken"]!;
                    ClientRequestTokens.Enqueue(token);
                    if (!alive)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    // Mesmo token e mesmo valor: idempotente (a AWS ignora a repetição)
                    if (secret!.Versions.All(v => v.Id != token))
                        secret.Versions.Add((token, (string)input["SecretString"]!, Now()));
                    return Json(new JsonObject { ["Name"] = id, ["VersionId"] = token });
                }
                case "TagResource":
                    if (secret is null)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    foreach (var tag in input["Tags"]!.AsArray())
                        secret.Tags[(string)tag!["Key"]!] = (string)tag["Value"]!;
                    return Empty();
                case "UntagResource":
                    if (secret is null)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    foreach (var key in input["TagKeys"]!.AsArray())
                        secret.Tags.Remove((string)key!);
                    return Empty();
                case "DeleteSecret":
                    if (!alive)
                        return Error(HttpStatusCode.BadRequest, "ResourceNotFoundException");
                    secret!.DeletedAt = Now();
                    return Json(new JsonObject { ["Name"] = id, ["DeletionDate"] = Epoch(Now().AddDays(30)) });
                default:
                    return Error(HttpStatusCode.BadRequest, "InvalidAction");
            }
        }
    }

    private static JsonObject Describe(string name, Secret secret, bool listing = false)
    {
        var stages = new JsonObject();
        foreach (var version in secret.Versions)
            stages[version.Id] = new JsonArray(version.Id == secret.Versions[^1].Id ? "AWSCURRENT" : "AWSPREVIOUS");
        var result = new JsonObject
        {
            ["Name"] = name,
            ["CreatedDate"] = Epoch(secret.Versions[0].At),
            ["LastChangedDate"] = Epoch(secret.Versions[^1].At),
            [listing ? "SecretVersionsToStages" : "VersionIdsToStages"] = stages,
            ["Tags"] = new JsonArray(secret.Tags.Select(t => (JsonNode?)new JsonObject { ["Key"] = t.Key, ["Value"] = t.Value }).ToArray())
        };
        if (secret.DeletedAt is { } deleted)
            result["DeletedDate"] = Epoch(deleted);
        return result;
    }

    /// <summary>
    /// Confere a assinatura SigV4 como a AWS: refaz a requisição canônica a partir do que foi enviado (cabeçalhos assinados, corpo e
    /// endereço) e compara a assinatura. Devolve o tipo do erro, ou <c>null</c> se a assinatura vale.
    /// </summary>
    private string? Verify(HttpRequestMessage request, byte[] body)
    {
        if (!request.Headers.TryGetValues("Authorization", out var values))
            return "MissingAuthenticationToken";
        var match = AuthorizationPattern().Match(values.Single());
        if (!match.Success)
            return "IncompleteSignature";

        var accessKey = match.Groups["key"].Value;
        (string Secret, string? Session) key;
        lock (_sync)
        {
            if (!_keys.TryGetValue(accessKey, out key))
                return _expired.Contains(accessKey) ? "ExpiredTokenException" : "UnrecognizedClientException";
        }

        var signed = match.Groups["headers"].Value.Split(';');
        foreach (var required in new[] { "content-type", "host", "x-amz-date", "x-amz-target" })
        {
            if (!signed.Contains(required))
                return "IncompleteSignature";
        }

        var session = request.Headers.TryGetValues("x-amz-security-token", out var tokens) ? tokens.Single() : null;
        if (!string.Equals(session, key.Session, StringComparison.Ordinal) || (session is not null && !signed.Contains("x-amz-security-token")))
            return "UnrecognizedClientException";

        var uri = request.RequestUri!;
        var canonicalHeaders = new StringBuilder();
        foreach (var name in signed)
        {
            var value = name switch
            {
                "host" => uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}",
                "content-type" => request.Content!.Headers.ContentType!.ToString(),
                _ => string.Join(',', request.Headers.GetValues(name))
            };
            canonicalHeaders.Append(name).Append(':').Append(value.Trim()).Append('\n');
        }

        var amzDate = request.Headers.GetValues("x-amz-date").Single();
        var scope = $"{amzDate[..8]}/{Region}/secretsmanager/aws4_request";
        if (match.Groups["scope"].Value != scope)
            return "IncompleteSignature";

        var canonical = $"{request.Method.Method}\n{uri.AbsolutePath}\n\n{canonicalHeaders}\n{match.Groups["headers"].Value}\n{Hex(SHA256.HashData(body))}";
        var toSign = $"AWS4-HMAC-SHA256\n{amzDate}\n{scope}\n{Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))}";
        var signingKey = HMACSHA256.HashData(Encoding.UTF8.GetBytes("AWS4" + key.Secret), Encoding.UTF8.GetBytes(amzDate[..8]));
        signingKey = HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(Region));
        signingKey = HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes("secretsmanager"));
        signingKey = HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes("aws4_request"));
        var expected = Hex(HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(toSign)));
        return expected == match.Groups["signature"].Value ? null : "InvalidSignatureException";
    }

    [GeneratedRegex(@"^AWS4-HMAC-SHA256 Credential=(?<key>[A-Za-z0-9]+)/(?<scope>[^,]+), SignedHeaders=(?<headers>[a-z0-9;-]+), Signature=(?<signature>[0-9a-f]{64})$")]
    private static partial Regex AuthorizationPattern();

    // ---------- Credenciais temporárias (STS, container, IMDS) ----------

    private JsonObject Issue()
    {
        var number = Interlocked.Increment(ref _issued);
        var accessKey = "ASIATEMPORARIA" + number.ToString("D6", CultureInfo.InvariantCulture);
        var secret = "segredo-temporario-" + number.ToString(CultureInfo.InvariantCulture);
        var session = "token-de-sessao-" + number.ToString(CultureInfo.InvariantCulture);
        lock (_sync)
            _keys[accessKey] = (secret, session);
        return new JsonObject
        {
            ["AccessKeyId"] = accessKey,
            ["SecretAccessKey"] = secret,
            ["Token"] = session,
            ["Expiration"] = Now().Add(CredentialLifetime).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
        };
    }

    private HttpResponseMessage Sts(byte[] body)
    {
        Interlocked.Increment(ref StsCalls);
        if (StsFailures.TryDequeue(out var failure))
            return Xml(failure.Status, $"<ErrorResponse><Error><Type>Sender</Type><Code>{failure.Code}</Code><Message>falha</Message></Error></ErrorResponse>");

        var form = Encoding.UTF8.GetString(body).Split('&')
            .Select(p => p.Split('=', 2))
            .ToDictionary(p => p[0], p => Uri.UnescapeDataString(p[1]), StringComparer.Ordinal);
        if (form.GetValueOrDefault("Action") != "AssumeRoleWithWebIdentity" || form.GetValueOrDefault("Version") != "2011-06-15" ||
            string.IsNullOrEmpty(form.GetValueOrDefault("RoleArn")) || string.IsNullOrEmpty(form.GetValueOrDefault("RoleSessionName")))
            return Xml(HttpStatusCode.BadRequest, "<ErrorResponse><Error><Code>InvalidParameterValue</Code></Error></ErrorResponse>");

        var token = form.GetValueOrDefault("WebIdentityToken") ?? "";
        ReceivedWebIdentityTokens.Enqueue(token);
        if (token != WebIdentityToken)
            return Xml(HttpStatusCode.BadRequest, "<ErrorResponse><Error><Code>InvalidIdentityToken</Code></Error></ErrorResponse>");

        var credentials = Issue();
        return Xml(HttpStatusCode.OK, $"""
            <AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
              <AssumeRoleWithWebIdentityResult>
                <AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/papel/sessao</Arn></AssumedRoleUser>
                <Credentials>
                  <SessionToken>{credentials["Token"]}</SessionToken>
                  <SecretAccessKey>{credentials["SecretAccessKey"]}</SecretAccessKey>
                  <Expiration>{credentials["Expiration"]}</Expiration>
                  <AccessKeyId>{credentials["AccessKeyId"]}</AccessKeyId>
                </Credentials>
              </AssumeRoleWithWebIdentityResult>
            </AssumeRoleWithWebIdentityResponse>
            """);
    }

    private HttpResponseMessage Container(HttpRequestMessage request)
    {
        Interlocked.Increment(ref ContainerCalls);
        var authorization = request.Headers.TryGetValues("Authorization", out var values) ? values.Single() : null;
        if (ContainerAuthorization is not null && authorization != ContainerAuthorization)
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        var credentials = Issue();
        credentials["RoleArn"] = "arn:aws:iam::123456789012:role/papel-da-task";
        return Json(credentials);
    }

    private HttpResponseMessage Imds(HttpRequestMessage request)
    {
        Interlocked.Increment(ref ImdsCalls);
        if (!ImdsReachable)
            throw new HttpRequestException("rede inalcançável (fora do EC2)");

        var path = request.RequestUri!.AbsolutePath;
        if (request.Method == HttpMethod.Put && path == "/latest/api/token")
        {
            return request.Headers.TryGetValues("X-aws-ec2-metadata-token-ttl-seconds", out _)
                ? Text("token-do-imds")
                : new HttpResponseMessage(HttpStatusCode.BadRequest);
        }

        // IMDSv2: sem o token da sessão, 401
        if (!request.Headers.TryGetValues("X-aws-ec2-metadata-token", out var token) || token.Single() != "token-do-imds")
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        if (path == "/latest/meta-data/iam/security-credentials/")
            return Text(ImdsRole + "\n");
        if (path == "/latest/meta-data/iam/security-credentials/" + ImdsRole)
        {
            var credentials = Issue();
            credentials["Code"] = "Success";
            credentials["Type"] = "AWS-HMAC";
            return Json(credentials);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    // ---------- Respostas ----------

    private static double Epoch(DateTimeOffset at) => at.ToUnixTimeMilliseconds() / 1000.0;

    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);

    private static HttpResponseMessage Json(JsonNode node) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/x-amz-json-1.1")
    };

    private static HttpResponseMessage Empty() => new(HttpStatusCode.OK) { Content = new ByteArrayContent([]) };

    private static HttpResponseMessage Text(string text) => new(HttpStatusCode.OK) { Content = new StringContent(text, Encoding.UTF8, "text/plain") };

    private static HttpResponseMessage Xml(HttpStatusCode status, string xml) => new(status) { Content = new StringContent(xml, Encoding.UTF8, "text/xml") };

    private static HttpResponseMessage Error(HttpStatusCode status, string? type) => new(status)
    {
        Content = new StringContent(type is null ? "{}" : $$"""{"__type":"com.amazonaws.secretsmanager#{{type}}","message":"detalhe-interno-da-aws"}""",
            Encoding.UTF8, "application/x-amz-json-1.1")
    };
}

/// <summary>Opções do provedor AWS apontadas para o <see cref="FakeAws"/>, sem tocar no ambiente do processo.</summary>
internal static class AwsTestOptions
{
    /// <summary>Chaves estáticas nas variáveis simuladas; container e IMDS desligados (cada teste liga o que precisa).</summary>
    public static AwsSecretsManagerOptions Create(FakeAws fake, Dictionary<string, string?>? variables = null,
        Action<AwsSecretsManagerOptions>? configure = null)
    {
        variables ??= new Dictionary<string, string?>
        {
            ["AWS_ACCESS_KEY_ID"] = FakeAws.StaticAccessKey,
            ["AWS_SECRET_ACCESS_KEY"] = FakeAws.StaticSecretKey
        };
        var options = new AwsSecretsManagerOptions
        {
            Region = FakeAws.Region,
            UseContainerCredentials = false,
            UseInstanceMetadata = false,
            ReadVariable = name => variables.TryGetValue(name, out var value) ? value : null
        };
        options.Http.Handler = fake;
        options.Http.CircuitBreaker.Enabled = false;
        configure?.Invoke(options);
        return options;
    }
}
