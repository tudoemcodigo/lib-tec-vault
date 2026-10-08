using TEC.Core.Text.Codecs;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Nodes;

namespace TEC.Vault.Tests.Fakes;

/// <summary>
/// HashiCorp Vault simulado em HTTP, com o comportamento documentado da API: KV v2 (versões, exclusão lógica, undelete,
/// destroy, custom_metadata, LIST com 404 quando vazio), Transit (RSA/ECDSA com criptografia real, valores
/// <c>vault:vN:...</c>, exclusão só com <c>deletion_allowed</c>), PKI (assina CSR com uma CA própria) e logins.
/// </summary>
internal sealed class FakeHashiCorpVault : HttpMessageHandler
{
    public const string Role = "minha-api";
    public const string RoleId = "role-id-1";

    private sealed class KvVersion
    {
        public required int Number;
        public required Dictionary<string, string> Data;
        public DateTimeOffset Created = DateTimeOffset.UtcNow;
        public DateTimeOffset? Deleted;
        public bool Destroyed { get; set; }
    }

    private sealed class KvItem
    {
        public List<KvVersion> Versions { get; } = [];
        public Dictionary<string, string> Custom { get; set; } = [];
        public DateTimeOffset Updated = DateTimeOffset.UtcNow;
    }

    private sealed class TransitKey
    {
        public required string Type;
        public List<(AsymmetricAlgorithm Key, DateTimeOffset Created)> Versions { get; } = [];
        public bool DeletionAllowed;
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, KvItem> _kv = new(StringComparer.Ordinal);
    private readonly Dictionary<string, TransitKey> _transit = new(StringComparer.Ordinal);
    private readonly HashSet<string> _tokens = [];
    private readonly RSA _caKey = RSA.Create(2048);
    private readonly X509Certificate2 _ca;
    private int _tokenCounter;

    public FakeHashiCorpVault()
    {
        var request = new CertificateRequest("CN=Fake Vault CA", _caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        _ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    }

    public string ServiceAccountJwt { get; set; } = "jwt-do-pod";

    public string SecretId { get; set; } = "secret-id-1";

    /// <summary>Token estático aceito (método Token).</summary>
    public string StaticToken { get; set; } = "hvs.token-estatico";

    public long LeaseDuration { get; set; } = 3600;

    public int Logins;

    public X509Certificate2 Ca => _ca;

    public ConcurrentQueue<string> Requests { get; } = new();

    public ConcurrentQueue<string?> Namespaces { get; } = new();

    public ConcurrentQueue<HttpStatusCode> Failures { get; } = new();

    public void RevokeTokens()
    {
        lock (_sync)
            _tokens.Clear();
    }

    /// <summary>Grava direto no KV (simula outra ferramenta).</summary>
    public void SeedKv(string path, Dictionary<string, string> data)
    {
        lock (_sync)
        {
            if (!_kv.TryGetValue(path, out var item))
                _kv[path] = item = new KvItem();
            item.Versions.Add(new KvVersion { Number = item.Versions.Count + 1, Data = data });
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri!;
        var path = Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/'));
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=', 2))
            .ToDictionary(p => p[0], p => p.Length > 1 ? Uri.UnescapeDataString(p[1]) : "");
        Requests.Enqueue($"{request.Method} {path}");
        Namespaces.Enqueue(request.Headers.TryGetValues("X-Vault-Namespace", out var ns) ? ns.First() : null);
        var body = request.Content is null ? new JsonObject() : JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken)) as JsonObject ?? [];

        if (path.StartsWith("v1/auth/", StringComparison.Ordinal))
            return Login(path, body);

        if (!request.Headers.TryGetValues("X-Vault-Token", out var tokens) || !IsValid(tokens.First()))
            return Errors(HttpStatusCode.Forbidden, "permission denied");

        if (Failures.TryDequeue(out var failure))
            return Errors(failure, "falha simulada");

        lock (_sync)
        {
            if (path.StartsWith("v1/secret/", StringComparison.Ordinal))
                return Kv(request.Method, path["v1/secret/".Length..], query, body);
            if (path.StartsWith("v1/transit/", StringComparison.Ordinal))
                return Transit(request.Method, path["v1/transit/".Length..], query, body);
            if (path.StartsWith("v1/pki/", StringComparison.Ordinal))
                return Pki(path["v1/pki/".Length..], body);
        }

        return Errors(HttpStatusCode.NotFound, "no handler for route");
    }

    // ---------- Login ----------

    private HttpResponseMessage Login(string path, JsonObject body)
    {
        var ok = path switch
        {
            "v1/auth/kubernetes/login" => (string?)body["role"] == Role && (string?)body["jwt"] == ServiceAccountJwt,
            "v1/auth/jwt/login" => (string?)body["role"] == Role && (string?)body["jwt"] == ServiceAccountJwt,
            "v1/auth/approle/login" => (string?)body["role_id"] == RoleId && (string?)body["secret_id"] == SecretId,
            _ => false
        };
        if (!ok)
            return Errors(HttpStatusCode.BadRequest, "invalid role or credentials");

        Interlocked.Increment(ref Logins);
        var token = "hvs.tok-" + Interlocked.Increment(ref _tokenCounter);
        lock (_sync)
            _tokens.Add(token);
        return Json(new JsonObject
        {
            ["auth"] = new JsonObject { ["client_token"] = token, ["lease_duration"] = LeaseDuration, ["renewable"] = true }
        });
    }

    private bool IsValid(string token)
    {
        lock (_sync)
            return token == StaticToken || _tokens.Contains(token);
    }

    // ---------- KV v2 ----------

    private HttpResponseMessage Kv(HttpMethod method, string path, Dictionary<string, string> query, JsonObject body)
    {
        var slash = path.IndexOf('/');
        var operation = slash < 0 ? path : path[..slash];
        var key = slash < 0 ? "" : path[(slash + 1)..];

        if (operation == "metadata" && method == HttpMethod.Get && query.GetValueOrDefault("list") == "true")
        {
            var prefix = key.Length == 0 ? "" : key + "/";
            var children = _kv.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal))
                .Select(k => k[prefix.Length..])
                .Select(rest => rest.Contains('/') ? rest[..(rest.IndexOf('/') + 1)] : rest)
                .Distinct().Order(StringComparer.Ordinal).ToList();
            return children.Count == 0
                ? Errors(HttpStatusCode.NotFound, "")
                : Json(Data(new JsonObject { ["keys"] = new JsonArray(children.Select(c => (JsonNode?)c).ToArray()) }));
        }

        _kv.TryGetValue(key, out var item);
        switch (operation, method.Method)
        {
            case ("data", "GET"):
            {
                if (item is null)
                    return Errors(HttpStatusCode.NotFound, "");
                var version = query.TryGetValue("version", out var v) ? item.Versions.FirstOrDefault(x => x.Number == int.Parse(v, CultureInfo.InvariantCulture)) : item.Versions[^1];
                if (version is null)
                    return Errors(HttpStatusCode.NotFound, "");
                var metadata = new JsonObject
                {
                    ["created_time"] = version.Created.ToString("O"),
                    ["deletion_time"] = version.Deleted?.ToString("O") ?? "",
                    ["destroyed"] = version.Destroyed,
                    ["version"] = version.Number
                };
                if (version.Deleted is not null || version.Destroyed)
                    return Json(Data(new JsonObject { ["data"] = null, ["metadata"] = metadata }), HttpStatusCode.NotFound);
                var data = new JsonObject();
                foreach (var (k, value) in version.Data)
                    data[k] = value;
                return Json(Data(new JsonObject { ["data"] = data, ["metadata"] = metadata }));
            }
            case ("data", "POST"):
            {
                if (item is null)
                    _kv[key] = item = new KvItem();
                var data = body["data"]!.AsObject().ToDictionary(p => p.Key, p => (string)p.Value!);
                var version = new KvVersion { Number = item.Versions.Count + 1, Data = data };
                item.Versions.Add(version);
                item.Updated = DateTimeOffset.UtcNow;
                return Json(Data(new JsonObject { ["version"] = version.Number, ["created_time"] = version.Created.ToString("O"), ["deletion_time"] = "", ["destroyed"] = false }));
            }
            case ("metadata", "GET"):
            {
                if (item is null)
                    return Errors(HttpStatusCode.NotFound, "");
                var versions = new JsonObject();
                foreach (var version in item.Versions)
                {
                    versions[version.Number.ToString(CultureInfo.InvariantCulture)] = new JsonObject
                    {
                        ["created_time"] = version.Created.ToString("O"),
                        ["deletion_time"] = version.Deleted?.ToString("O") ?? "",
                        ["destroyed"] = version.Destroyed
                    };
                }

                var custom = new JsonObject();
                foreach (var (k, value) in item.Custom)
                    custom[k] = value;
                return Json(Data(new JsonObject
                {
                    ["current_version"] = item.Versions.Count,
                    ["versions"] = versions,
                    ["custom_metadata"] = item.Custom.Count == 0 ? null : custom,
                    ["created_time"] = item.Versions[0].Created.ToString("O"),
                    ["updated_time"] = item.Updated.ToString("O")
                }));
            }
            case ("metadata", "POST"):
            {
                if (item is null)
                    _kv[key] = item = new KvItem();
                item.Custom = body["custom_metadata"]?.AsObject().ToDictionary(p => p.Key, p => (string)p.Value!) ?? [];
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }
            case ("metadata", "DELETE"):
                _kv.Remove(key);
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            case ("delete", "POST"):
            case ("undelete", "POST"):
            {
                if (item is null)
                    return Errors(HttpStatusCode.NotFound, "");
                foreach (var number in body["versions"]!.AsArray().Select(n => (int)n!))
                {
                    var version = item.Versions.FirstOrDefault(x => x.Number == number);
                    if (version is not null && !version.Destroyed)
                        version.Deleted = operation == "delete" ? DateTimeOffset.UtcNow : null;
                }

                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }
        }

        return Errors(HttpStatusCode.MethodNotAllowed, "");
    }

    // ---------- Transit ----------

    private HttpResponseMessage Transit(HttpMethod method, string path, Dictionary<string, string> query, JsonObject body)
    {
        var parts = path.Split('/');
        if (parts[0] == "keys" && parts.Length == 1 && query.GetValueOrDefault("list") == "true")
        {
            return _transit.Count == 0
                ? Errors(HttpStatusCode.NotFound, "")
                : Json(Data(new JsonObject { ["keys"] = new JsonArray(_transit.Keys.Order(StringComparer.Ordinal).Select(k => (JsonNode?)k).ToArray()) }));
        }

        if (parts.Length < 2)
            return Errors(HttpStatusCode.NotFound, "");
        var name = parts[1];
        _transit.TryGetValue(name, out var key);

        switch (parts[0], parts.Length, method.Method)
        {
            case ("keys", 2, "POST"):
                if (key is null)
                {
                    var type = (string)body["type"]!;
                    _transit[name] = key = new TransitKey { Type = type };
                    key.Versions.Add((Generate(type), DateTimeOffset.UtcNow));
                }

                return new HttpResponseMessage(HttpStatusCode.NoContent);
            case ("keys", 2, "GET"):
                return key is null ? Errors(HttpStatusCode.NotFound, "") : Json(Data(KeyInfo(name, key)));
            case ("keys", 2, "DELETE"):
                if (key is null)
                    return new HttpResponseMessage(HttpStatusCode.NoContent);
                if (!key.DeletionAllowed)
                    return Errors(HttpStatusCode.BadRequest, "deletion is not allowed for this key");
                _transit.Remove(name);
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            case ("keys", 3, "POST") when parts[2] == "rotate":
                if (key is null)
                    return Errors(HttpStatusCode.BadRequest, "key not found");
                key.Versions.Add((Generate(key.Type), DateTimeOffset.UtcNow));
                return Json(Data(KeyInfo(name, key)));
            case ("keys", 3, "POST") when parts[2] == "config":
                if (key is null)
                    return Errors(HttpStatusCode.BadRequest, "key not found");
                key.DeletionAllowed = (bool?)body["deletion_allowed"] ?? key.DeletionAllowed;
                return Json(Data(KeyInfo(name, key)));
            case ("encrypt", 2, "POST"):
            {
                if (key?.Versions is null || key.Versions[0].Key is not RSA)
                    return Errors(HttpStatusCode.BadRequest, key is null ? "encryption key not found" : "key type does not support encryption");
                var version = (int?)body["key_version"] ?? key.Versions.Count;
                if (version < 1 || version > key.Versions.Count)
                    return Errors(HttpStatusCode.BadRequest, "invalid key version");
                var ciphertext = ((RSA)key.Versions[version - 1].Key).Encrypt(Convert.FromBase64String((string)body["plaintext"]!), RSAEncryptionPadding.OaepSHA256);
                return Json(Data(new JsonObject { ["ciphertext"] = $"vault:v{version}:{Convert.ToBase64String(ciphertext)}", ["key_version"] = version }));
            }
            case ("decrypt", 2, "POST"):
            {
                if (key is null || key.Versions[0].Key is not RSA)
                    return Errors(HttpStatusCode.BadRequest, "invalid key");
                var (version, bytes) = ParseValue((string)body["ciphertext"]!, url: false);
                if (version < 1 || version > key.Versions.Count)
                    return Errors(HttpStatusCode.BadRequest, "invalid ciphertext: no version");
                try
                {
                    var plaintext = ((RSA)key.Versions[version - 1].Key).Decrypt(bytes, RSAEncryptionPadding.OaepSHA256);
                    return Json(Data(new JsonObject { ["plaintext"] = Convert.ToBase64String(plaintext) }));
                }
                catch (CryptographicException)
                {
                    return Errors(HttpStatusCode.BadRequest, "invalid ciphertext: unable to decrypt");
                }
            }
            case ("sign", 3, "POST"):
            {
                if (key is null)
                    return Errors(HttpStatusCode.BadRequest, "signing key not found");
                var version = (int?)body["key_version"] ?? key.Versions.Count;
                var data = Convert.FromBase64String((string)body["input"]!);
                var hash = Hash(parts[2]);
                byte[] signature;
                bool url;
                if (key.Versions[version - 1].Key is RSA rsa)
                {
                    signature = rsa.SignData(data, hash, (string?)body["signature_algorithm"] == "pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                    url = false;
                }
                else
                {
                    var ec = (ECDsa)key.Versions[version - 1].Key;
                    signature = (string?)body["marshaling_algorithm"] == "jws"
                        ? ec.SignData(data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
                        : ec.SignData(data, hash, DSASignatureFormat.Rfc3279DerSequence);
                    url = (string?)body["marshaling_algorithm"] == "jws";
                }

                var encoded = url ? Base64UrlEncoder.Encode(signature) : Convert.ToBase64String(signature);
                return Json(Data(new JsonObject { ["signature"] = $"vault:v{version}:{encoded}", ["key_version"] = version }));
            }
            case ("verify", 3, "POST"):
            {
                if (key is null)
                    return Errors(HttpStatusCode.BadRequest, "signature verification key not found");
                var jws = (string?)body["marshaling_algorithm"] == "jws";
                var (version, signature) = ParseValue((string)body["signature"]!, jws);
                if (version < 1 || version > key.Versions.Count)
                    return Errors(HttpStatusCode.BadRequest, "invalid key version");
                var data = Convert.FromBase64String((string)body["input"]!);
                var hash = Hash(parts[2]);
                var valid = key.Versions[version - 1].Key switch
                {
                    RSA rsa => rsa.VerifyData(data, signature, hash, (string?)body["signature_algorithm"] == "pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1),
                    ECDsa ec => ec.VerifyData(data, signature, hash, jws ? DSASignatureFormat.IeeeP1363FixedFieldConcatenation : DSASignatureFormat.Rfc3279DerSequence),
                    _ => false
                };
                return Json(Data(new JsonObject { ["valid"] = valid }));
            }
        }

        return Errors(HttpStatusCode.MethodNotAllowed, "");
    }

    private static JsonObject KeyInfo(string name, TransitKey key)
    {
        var keys = new JsonObject();
        for (var i = 0; i < key.Versions.Count; i++)
        {
            var (k, created) = key.Versions[i];
            var spki = k is RSA rsa ? rsa.ExportSubjectPublicKeyInfo() : ((ECDsa)k).ExportSubjectPublicKeyInfo();
            keys[(i + 1).ToString(CultureInfo.InvariantCulture)] = new JsonObject
            {
                ["creation_time"] = created.ToString("O"),
                ["name"] = key.Type,
                ["public_key"] = PemEncoding.WriteString("PUBLIC KEY", spki)
            };
        }

        return new JsonObject
        {
            ["name"] = name,
            ["type"] = key.Type,
            ["keys"] = keys,
            ["latest_version"] = key.Versions.Count,
            ["min_decryption_version"] = 1,
            ["min_encryption_version"] = 0,
            ["deletion_allowed"] = key.DeletionAllowed,
            ["exportable"] = false
        };
    }

    private static AsymmetricAlgorithm Generate(string type) => type switch
    {
        "rsa-2048" => RSA.Create(2048),
        "rsa-3072" => RSA.Create(3072),
        "rsa-4096" => RSA.Create(4096),
        "ecdsa-p256" => ECDsa.Create(ECCurve.NamedCurves.nistP256),
        "ecdsa-p384" => ECDsa.Create(ECCurve.NamedCurves.nistP384),
        "ecdsa-p521" => ECDsa.Create(ECCurve.NamedCurves.nistP521),
        _ => throw new InvalidOperationException("tipo não suportado no fake: " + type)
    };

    private static HashAlgorithmName Hash(string name) => name switch
    {
        "sha2-384" => HashAlgorithmName.SHA384,
        "sha2-512" => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256
    };

    private static (int Version, byte[] Bytes) ParseValue(string value, bool url)
    {
        var parts = value.Split(':');
        var text = parts[2];
        var bytes = url
            ? (Base64UrlEncoder.TryDecode(text, out var decoded) ? decoded : throw new FormatException("Base64Url inválido."))
            : Convert.FromBase64String(text);
        return (int.Parse(parts[1][1..], CultureInfo.InvariantCulture), bytes);
    }

    // ---------- PKI ----------

    private HttpResponseMessage Pki(string path, JsonObject body)
    {
        var parts = path.Split('/');
        var isSign = (parts.Length == 2 && parts[0] == "sign" && parts[1] == Role) ||
                     (parts.Length == 4 && parts[0] == "issuer" && parts[2] == "sign" && parts[3] == Role);
        if (!isSign)
            return Errors(HttpStatusCode.BadRequest, "unknown role");
        if (parts.Length == 4 && parts[1] != "default")
            return Errors(HttpStatusCode.BadRequest, "unable to find issuer");

        var csr = CertificateRequest.LoadSigningRequestPem((string)body["csr"]!, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var hours = double.Parse(((string)body["ttl"]!).TrimEnd('h'), CultureInfo.InvariantCulture);
        var now = DateTimeOffset.UtcNow;
        var serial = RandomNumberGenerator.GetBytes(16);
        using var issued = csr.Create(_ca.SubjectName, X509SignatureGenerator.CreateForRSA(_caKey, RSASignaturePadding.Pkcs1),
            now.AddMinutes(-1), now.AddHours(hours), serial);
        return Json(Data(new JsonObject
        {
            ["certificate"] = issued.ExportCertificatePem(),
            ["issuing_ca"] = _ca.ExportCertificatePem(),
            ["serial_number"] = Convert.ToHexString(serial)
        }));
    }

    // ---------- Respostas ----------

    private static JsonObject Data(JsonObject data) => new() { ["request_id"] = Guid.NewGuid().ToString(), ["data"] = data };

    private static HttpResponseMessage Json(JsonNode node, HttpStatusCode status = HttpStatusCode.OK) => new(status)
    {
        Content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json")
    };

    private static HttpResponseMessage Errors(HttpStatusCode status, string message) => new(status)
    {
        Content = new StringContent(new JsonObject { ["errors"] = new JsonArray(message.Length == 0 ? [] : [(JsonNode?)message]) }.ToJsonString(),
            Encoding.UTF8, "application/json")
    };
}
