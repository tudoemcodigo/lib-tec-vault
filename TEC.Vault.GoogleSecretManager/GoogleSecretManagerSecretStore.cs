using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.GoogleSecretManager.Internal;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.GoogleSecretManager;

/// <summary>
/// Provedor para Google Cloud Secret Manager via API REST v1 nativa sem SDKs pesados de terceiros.
/// Compatível com Native AOT e zero dependências pesadas externas.
/// </summary>
public sealed partial class GoogleSecretManagerSecretStore : VaultHttpProviderBase, ISecretStore, IVaultHealthProbe, IDisposable
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "GoogleSecretManager";

    /// <summary>Tamanho máximo permitido de segredo no Google Secret Manager (64 KB).</summary>
    public const int MaxSecretValueBytes = 64 * 1024;

    private static readonly VaultProviderRules Rules = new(NamePattern(), "use de 1 a 255 caracteres: letras, números, hífen e sublinhado.")
    {
        VersionPattern = VersionPattern(),
        MaxSecretValueBytes = MaxSecretValueBytes,
        MaxTags = 50,
        MaxTagKeyLength = 63,
        MaxTagValueLength = 63,
        MaxBackupBytes = 0
    };

    private readonly GoogleSecretManagerOptions _options;
    private readonly string _projectId;
    private readonly HttpClient _httpClient;
    private readonly GoogleTokenSource _tokenSource;
    private readonly TimeProvider _time;
    private bool _disposed;

    /// <summary>Cria uma nova instância do provedor Google Secret Manager.</summary>
    public GoogleSecretManagerSecretStore(GoogleSecretManagerOptions options, ILogger<GoogleSecretManagerSecretStore>? logger = null)
        : base(Provider, logger ?? (ILogger)NullLogger.Instance, CreateCircuitBreaker(options))
    {
        ArgumentNullException.ThrowIfNull(options);
        _projectId = options.ResolveProjectId();
        _options = options;
        _time = options.TimeProvider ?? TimeProvider.System;

        var handler = options.Http.Handler ?? new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(15),
            EnableMultipleHttp2Connections = true,
            AllowAutoRedirect = false
        };

        _httpClient = new HttpClient(handler, disposeHandler: options.Http.Handler is null)
        {
            BaseAddress = options.Endpoint,
            Timeout = options.Http.NetworkTimeout
        };

        _tokenSource = new GoogleTokenSource(options, _httpClient);
    }

    private static VaultCircuitBreaker? CreateCircuitBreaker(GoogleSecretManagerOptions? options) => options is null
        ? null
        : VaultCircuitBreaker.Create(Provider, options.Http.CircuitBreaker, options.TimeProvider, "GoogleSecretManagerOptions.Http.CircuitBreaker");

    [GeneratedRegex(@"^[0-9a-zA-Z_-]{1,255}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"^(latest|[0-9]+)\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VersionPattern();

    // ---------- ISecretReader ----------

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            var targetVersion = string.IsNullOrWhiteSpace(version) ? "latest" : version;
            var path = $"v1/projects/{_projectId}/secrets/{name}/versions/{targetVersion}:access";

            var (status, body) = await SendGcpRequestAsync(HttpMethod.Get, path, null, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();
            if (status != HttpStatusCode.OK)
                return MapGcpError(status, body);

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("payload", out var payload) || !payload.TryGetProperty("data", out var dataProp))
                return VaultErrors.NotFound();

            var base64Data = dataProp.GetString() ?? string.Empty;
            var secretValue = Encoding.UTF8.GetString(Convert.FromBase64String(base64Data));

            var fullVersionName = root.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            var versionId = fullVersionName.Contains("/versions/") ? fullVersionName[(fullVersionName.LastIndexOf('/') + 1)..] : targetVersion;

            var properties = new SecretProperties
            {
                Name = name,
                Version = versionId,
                Enabled = true
            };

            return Result<VaultSecret>.Success(new VaultSecret(properties, secretValue));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.exists", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var path = $"v1/projects/{_projectId}/secrets/{name}";
            var (status, body) = await SendGcpRequestAsync(HttpMethod.Get, path, null, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
                return Result<bool>.Success(false);
            if (status == HttpStatusCode.OK)
                return Result<bool>.Success(true);

            return MapGcpError(status, body);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.list", null, null, isWrite: false, async ct =>
        {
            var secrets = new List<SecretProperties>();
            string? pageToken = null;

            do
            {
                var query = $"pageSize={Math.Min(100, _options.MaxListItems)}";
                if (!string.IsNullOrEmpty(pageToken))
                    query += $"&pageToken={Uri.EscapeDataString(pageToken)}";

                var path = $"v1/projects/{_projectId}/secrets?{query}";
                var (status, body) = await SendGcpRequestAsync(HttpMethod.Get, path, null, ct).ConfigureAwait(false);

                if (status != HttpStatusCode.OK)
                    return MapGcpError(status, body);

                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                if (root.TryGetProperty("secrets", out var list) && list.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in list.EnumerateArray())
                    {
                        if (item.TryGetProperty("name", out var n) && n.GetString() is { } fullName)
                        {
                            var secretName = fullName.Contains("/secrets/") ? fullName[(fullName.LastIndexOf('/') + 1)..] : fullName;
                            secrets.Add(new SecretProperties
                            {
                                Name = secretName,
                                Enabled = true
                            });

                            if (secrets.Count >= _options.MaxListItems)
                                return Result<IReadOnlyList<SecretProperties>>.Success(secrets.ToArray());
                        }
                    }
                }

                pageToken = root.TryGetProperty("nextPageToken", out var pt) ? pt.GetString() : null;
            } while (!string.IsNullOrEmpty(pageToken));

            return Result<IReadOnlyList<SecretProperties>>.Success(secrets.ToArray());
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var path = $"v1/projects/{_projectId}/secrets/{name}/versions?pageSize=100";
            var (status, body) = await SendGcpRequestAsync(HttpMethod.Get, path, null, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();
            if (status != HttpStatusCode.OK)
                return MapGcpError(status, body);

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var versions = new List<SecretProperties>();

            if (root.TryGetProperty("versions", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in list.EnumerateArray())
                {
                    var fullName = item.TryGetProperty("name", out var n) ? n.GetString() : null;
                    if (fullName is null)
                        continue;

                    var versionId = fullName.Contains("/versions/") ? fullName[(fullName.LastIndexOf('/') + 1)..] : fullName;
                    var state = item.TryGetProperty("state", out var s) ? s.GetString() : "ENABLED";
                    var isEnabled = string.Equals(state, "ENABLED", StringComparison.OrdinalIgnoreCase);

                    var createTime = item.TryGetProperty("createTime", out var ctProp) && DateTimeOffset.TryParse(ctProp.GetString(), out var dto)
                        ? dto
                        : (DateTimeOffset?)null;

                    versions.Add(new SecretProperties
                    {
                        Name = name,
                        Version = versionId,
                        Enabled = isEnabled,
                        CreatedOn = createTime
                    });
                }
            }

            return Result<IReadOnlyList<SecretProperties>>.Success(versions.ToArray());
        }, cancellationToken);

    // ---------- ISecretStore ----------

    /// <inheritdoc />
    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new SecretWriteOptions();
        if (options.ContentType is not null || options.NotBefore is not null || options.ExpiresOn is not null)
            return Task.FromResult(Result<SecretProperties>.Failure(VaultErrors.InvalidInput("options", "O Google Secret Manager não suporta tipo de conteúdo nem período de validade: informe apenas valor e tags.")));

        var inputError = Rules.SetSecret(name, value, options, _time.GetUtcNow());

        return ExecuteAsync("secret.set", name, inputError, isWrite: true, async ct =>
        {
            var base64Data = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
            byte[] addVersionBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteStartObject("payload");
                    writer.WriteString("data", base64Data);
                    writer.WriteEndObject();
                    writer.WriteEndObject();
                }
                addVersionBytes = buffer.ToArray();
            }

            var addVersionPath = $"v1/projects/{_projectId}/secrets/{name}:addVersion";
            var (status, body) = await SendGcpRequestAsync(HttpMethod.Post, addVersionPath, addVersionBytes, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
            {
                byte[] createBytes;
                using (var buffer = new MemoryStream())
                {
                    using (var writer = new Utf8JsonWriter(buffer))
                    {
                        writer.WriteStartObject();
                        writer.WriteStartObject("replication");
                        writer.WriteStartObject("automatic");
                        writer.WriteEndObject();
                        writer.WriteEndObject();
                        if (options.Tags is { Count: > 0 })
                        {
                            writer.WriteStartObject("labels");
                            foreach (var (k, v) in options.Tags)
                                writer.WriteString(k, v);
                            writer.WriteEndObject();
                        }
                        writer.WriteEndObject();
                    }
                    createBytes = buffer.ToArray();
                }

                var createPath = $"v1/projects/{_projectId}/secrets?secretId={Uri.EscapeDataString(name)}";
                var (createStatus, createBody) = await SendGcpRequestAsync(HttpMethod.Post, createPath, createBytes, ct).ConfigureAwait(false);

                if (createStatus != HttpStatusCode.OK && createStatus != HttpStatusCode.Conflict)
                    return MapGcpError(createStatus, createBody);

                (status, body) = await SendGcpRequestAsync(HttpMethod.Post, addVersionPath, addVersionBytes, ct).ConfigureAwait(false);
            }

            if (status != HttpStatusCode.OK)
                return MapGcpError(status, body);

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var fullName = root.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
            var versionId = fullName.Contains("/versions/") ? fullName[(fullName.LastIndexOf('/') + 1)..] : "1";

            return Result<SecretProperties>.Success(new SecretProperties { Name = name, Version = versionId, Enabled = true });
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (update.ContentType is not null || update.ExpiresOn is not null || update.NotBefore is not null)
            return Task.FromResult(Result<SecretProperties>.Failure(VaultErrors.InvalidInput("update", "O Google Secret Manager não suporta tipo de conteúdo nem período de validade.")));

        var inputError = Rules.UpdateSecret(name, version, update, _time.GetUtcNow());

        return ExecuteAsync("secret.update", name, inputError, isWrite: true, async ct =>
        {
            var targetVersion = string.IsNullOrWhiteSpace(version) ? "latest" : version;
            if (update.Enabled is false)
            {
                var disablePath = $"v1/projects/{_projectId}/secrets/{name}/versions/{targetVersion}:disable";
                var (dStatus, dBody) = await SendGcpRequestAsync(HttpMethod.Post, disablePath, null, ct).ConfigureAwait(false);
                if (dStatus != HttpStatusCode.OK)
                    return MapGcpError(dStatus, dBody);

                return Result<SecretProperties>.Success(new SecretProperties { Name = name, Version = targetVersion, Enabled = false });
            }

            if (update.Enabled is true)
            {
                var enablePath = $"v1/projects/{_projectId}/secrets/{name}/versions/{targetVersion}:enable";
                var (eStatus, eBody) = await SendGcpRequestAsync(HttpMethod.Post, enablePath, null, ct).ConfigureAwait(false);
                if (eStatus != HttpStatusCode.OK)
                    return MapGcpError(eStatus, eBody);

                return Result<SecretProperties>.Success(new SecretProperties { Name = name, Version = targetVersion, Enabled = true });
            }

            var path = $"v1/projects/{_projectId}/secrets/{name}";
            var (status, body) = await SendGcpRequestAsync(HttpMethod.Get, path, null, ct).ConfigureAwait(false);

            if (status != HttpStatusCode.OK)
                return MapGcpError(status, body);

            return Result<SecretProperties>.Success(new SecretProperties { Name = name, Version = targetVersion, Enabled = true });
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var path = $"v1/projects/{_projectId}/secrets/{name}";
            var (status, body) = await SendGcpRequestAsync(HttpMethod.Delete, path, null, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
                return Result<DeletedVaultItem>.Failure(VaultErrors.NotFound());

            if (status == HttpStatusCode.OK)
                return Result<DeletedVaultItem>.Success(new DeletedVaultItem(name, _time.GetUtcNow(), ScheduledPurgeDate: null));

            return MapGcpError(status, body);
        }, cancellationToken);

    // ---------- IVaultHealthProbe ----------

    /// <inheritdoc />
    public async Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var path = $"v1/projects/{_projectId}/secrets?pageSize=1";
            var (status, body) = await SendGcpRequestAsync(HttpMethod.Get, path, null, cancellationToken).ConfigureAwait(false);

            return status == HttpStatusCode.OK
                ? Result.Success()
                : Result.Failure(VaultErrors.Unavailable());
        }
        catch
        {
            return Result.Failure(VaultErrors.Unavailable());
        }
    }

    // ---------- HTTP Helper ----------

    private async Task<(HttpStatusCode Status, string Body)> SendGcpRequestAsync(HttpMethod method, string path, byte[]? payloadBytes, CancellationToken cancellationToken)
    {
        var token = await _tokenSource.GetTokenAsync(cancellationToken).ConfigureAwait(false);

        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        if (payloadBytes is not null)
        {
            request.Content = new ByteArrayContent(payloadBytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return (response.StatusCode, responseBody);
    }

    private static Error MapGcpError(HttpStatusCode status, string responseBody) => status switch
    {
        HttpStatusCode.NotFound => VaultErrors.NotFound(),
        HttpStatusCode.Conflict => VaultErrors.Conflict(),
        HttpStatusCode.Unauthorized => VaultErrors.AuthenticationFailed(),
        HttpStatusCode.Forbidden => VaultErrors.AccessDenied(),
        (HttpStatusCode)429 => VaultErrors.Throttled(),
        HttpStatusCode.BadRequest => VaultErrors.InvalidInput("request", "Requisição inválida enviada ao Google Secret Manager."),
        HttpStatusCode.ServiceUnavailable or HttpStatusCode.BadGateway or HttpStatusCode.GatewayTimeout => VaultErrors.Unavailable(),
        _ => VaultErrors.ProviderFailure()
    };

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            _httpClient.Dispose();
            _disposed = true;
        }
    }
}
