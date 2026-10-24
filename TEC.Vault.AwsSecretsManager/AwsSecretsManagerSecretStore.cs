using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Abstractions;
using TEC.Vault.AwsSecretsManager.Internal;
using TEC.Vault.Common;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.AwsSecretsManager;

/// <summary>
/// Provedor para AWS Secrets Manager via HTTP puro e protocolo JSON 1.1 da AWS com assinatura SigV4 nativa.
/// Compatível com Native AOT e zero dependências pesadas externas.
/// </summary>
public sealed partial class AwsSecretsManagerSecretStore : VaultHttpProviderBase, ISecretStore, IVaultHealthProbe, IDisposable
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "AwsSecretsManager";

    /// <summary>Tamanho máximo permitido de segredo no AWS Secrets Manager (64 KB).</summary>
    public const int MaxSecretValueBytes = 64 * 1024;

    private static readonly VaultProviderRules Rules = new(NamePattern(), "use letras, números, hífen, sublinhado e barra (/ ou _ ou -).")
    {
        VersionPattern = VersionPattern(),
        MaxSecretValueBytes = MaxSecretValueBytes,
        MaxTags = 50,
        MaxTagKeyLength = 128,
        MaxTagValueLength = 256,
        MaxBackupBytes = 0
    };

    private readonly AwsSecretsManagerOptions _options;
    private readonly string _accessKey;
    private readonly string _secretKey;
    private readonly string? _sessionToken;
    private readonly Uri _endpoint;
    private readonly HttpClient _httpClient;
    private readonly TimeProvider _time;
    private bool _disposed;

    /// <summary>Cria uma nova instância do provedor AWS Secrets Manager.</summary>
    public AwsSecretsManagerSecretStore(AwsSecretsManagerOptions options, ILogger<AwsSecretsManagerSecretStore>? logger = null)
        : base(Provider, logger ?? (ILogger)NullLogger.Instance, CreateCircuitBreaker(options))
    {
        ArgumentNullException.ThrowIfNull(options);
        var resolved = options.Resolve();

        _options = options;
        _accessKey = resolved.AccessKey;
        _secretKey = resolved.SecretKey;
        _sessionToken = resolved.SessionToken;
        _endpoint = resolved.EndpointUri;
        _time = options.TimeProvider ?? TimeProvider.System;

        var handler = options.Http.Handler ?? new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(15),
            EnableMultipleHttp2Connections = true,
            AllowAutoRedirect = false
        };

        _httpClient = new HttpClient(handler, disposeHandler: options.Http.Handler is null)
        {
            BaseAddress = _endpoint,
            Timeout = options.Http.NetworkTimeout
        };
    }

    private static VaultCircuitBreaker? CreateCircuitBreaker(AwsSecretsManagerOptions? options) => options is null
        ? null
        : VaultCircuitBreaker.Create(Provider, options.Http.CircuitBreaker, options.TimeProvider, "AwsSecretsManagerOptions.Http.CircuitBreaker");

    [GeneratedRegex(@"^[0-9a-zA-Z/_+=.@-]{1,512}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"^[0-9a-zA-Z_-]{1,64}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VersionPattern();

    // ---------- ISecretReader ----------

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            byte[] payloadBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("SecretId", name);
                    if (!string.IsNullOrWhiteSpace(version))
                        writer.WriteString("VersionId", version);
                    writer.WriteEndObject();
                }
                payloadBytes = buffer.ToArray();
            }

            var (status, body) = await SendAwsRequestAsync("secretsmanager.GetSecretValue", payloadBytes, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();

            if (status != HttpStatusCode.OK)
                return MapAwsError(status, body);

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var secretString = root.TryGetProperty("SecretString", out var s) ? s.GetString() : null;

            if (secretString is null)
                return VaultErrors.InvalidInput("SecretString", "Segredos binários puros não são suportados como string direta.");

            var versionId = root.TryGetProperty("VersionId", out var v) ? v.GetString() ?? "1" : "1";
            var createdDate = root.TryGetProperty("CreatedDate", out var cd) && cd.TryGetDouble(out var seconds)
                ? DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000))
                : (DateTimeOffset?)null;

            var properties = new SecretProperties
            {
                Name = name,
                Version = versionId,
                Enabled = true,
                CreatedOn = createdDate,
                UpdatedOn = createdDate
            };

            return Result<VaultSecret>.Success(new VaultSecret(properties, secretString));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.exists", name, Rules.Name(name), isWrite: false, async ct =>
        {
            byte[] payloadBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("SecretId", name);
                    writer.WriteEndObject();
                }
                payloadBytes = buffer.ToArray();
            }

            var (status, body) = await SendAwsRequestAsync("secretsmanager.DescribeSecret", payloadBytes, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound || body.Contains("ResourceNotFoundException", StringComparison.OrdinalIgnoreCase))
                return Result<bool>.Success(false);

            if (status == HttpStatusCode.OK)
                return Result<bool>.Success(true);

            return MapAwsError(status, body);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.list", null, null, isWrite: false, async ct =>
        {
            var secrets = new List<SecretProperties>();
            string? nextToken = null;

            do
            {
                byte[] payloadBytes;
                using (var buffer = new MemoryStream())
                {
                    using (var writer = new Utf8JsonWriter(buffer))
                    {
                        writer.WriteStartObject();
                        writer.WriteNumber("MaxResults", Math.Min(100, _options.MaxListItems));
                        if (!string.IsNullOrEmpty(nextToken))
                            writer.WriteString("NextToken", nextToken);
                        writer.WriteEndObject();
                    }
                    payloadBytes = buffer.ToArray();
                }

                var (status, body) = await SendAwsRequestAsync("secretsmanager.ListSecrets", payloadBytes, ct).ConfigureAwait(false);
                if (status != HttpStatusCode.OK)
                    return MapAwsError(status, body);

                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                if (root.TryGetProperty("SecretList", out var list) && list.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in list.EnumerateArray())
                    {
                        if (item.TryGetProperty("Name", out var n) && n.GetString() is { } name)
                        {
                            var created = item.TryGetProperty("CreatedDate", out var cd) && cd.TryGetDouble(out var cSec)
                                ? DateTimeOffset.FromUnixTimeMilliseconds((long)(cSec * 1000))
                                : (DateTimeOffset?)null;

                            secrets.Add(new SecretProperties
                            {
                                Name = name,
                                Enabled = true,
                                CreatedOn = created
                            });

                            if (secrets.Count >= _options.MaxListItems)
                                return Result<IReadOnlyList<SecretProperties>>.Success(secrets.ToArray());
                        }
                    }
                }

                nextToken = root.TryGetProperty("NextToken", out var tokenProp) ? tokenProp.GetString() : null;
            } while (!string.IsNullOrEmpty(nextToken));

            return Result<IReadOnlyList<SecretProperties>>.Success(secrets.ToArray());
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            byte[] payloadBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("SecretId", name);
                    writer.WriteNumber("MaxResults", 100);
                    writer.WriteEndObject();
                }
                payloadBytes = buffer.ToArray();
            }

            var (status, body) = await SendAwsRequestAsync("secretsmanager.ListSecretVersionIds", payloadBytes, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();
            if (status != HttpStatusCode.OK)
                return MapAwsError(status, body);

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            var versions = new List<SecretProperties>();

            if (root.TryGetProperty("Versions", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in list.EnumerateArray())
                {
                    var versionId = item.TryGetProperty("VersionId", out var v) ? v.GetString() : null;
                    if (versionId is null)
                        continue;

                    var createdDate = item.TryGetProperty("CreatedDate", out var cd) && cd.TryGetDouble(out var seconds)
                        ? DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000))
                        : (DateTimeOffset?)null;

                    versions.Add(new SecretProperties
                    {
                        Name = name,
                        Version = versionId,
                        Enabled = true,
                        CreatedOn = createdDate
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
            return Task.FromResult(Result<SecretProperties>.Failure(VaultErrors.InvalidInput("options", "O AWS Secrets Manager não suporta tipo de conteúdo nem período de validade: informe apenas valor e tags.")));

        var inputError = Rules.SetSecret(name, value, options, _time.GetUtcNow());

        return ExecuteAsync("secret.set", name, inputError, isWrite: true, async ct =>
        {
            byte[] createPayloadBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("Name", name);
                    writer.WriteString("SecretString", value);
                    if (options.Tags is { Count: > 0 })
                    {
                        writer.WriteStartArray("Tags");
                        foreach (var (k, v) in options.Tags)
                        {
                            writer.WriteStartObject();
                            writer.WriteString("Key", k);
                            writer.WriteString("Value", v);
                            writer.WriteEndObject();
                        }
                        writer.WriteEndArray();
                    }
                    writer.WriteEndObject();
                }
                createPayloadBytes = buffer.ToArray();
            }

            var (status, body) = await SendAwsRequestAsync("secretsmanager.CreateSecret", createPayloadBytes, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.OK)
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                var versionId = root.TryGetProperty("VersionId", out var v) ? v.GetString() ?? "1" : "1";
                return Result<SecretProperties>.Success(new SecretProperties { Name = name, Version = versionId, Enabled = true });
            }

            if (body.Contains("ResourceExistsException", StringComparison.OrdinalIgnoreCase))
            {
                byte[] putPayloadBytes;
                using (var buffer = new MemoryStream())
                {
                    using (var writer = new Utf8JsonWriter(buffer))
                    {
                        writer.WriteStartObject();
                        writer.WriteString("SecretId", name);
                        writer.WriteString("SecretString", value);
                        writer.WriteEndObject();
                    }
                    putPayloadBytes = buffer.ToArray();
                }

                var (putStatus, putBody) = await SendAwsRequestAsync("secretsmanager.PutSecretValue", putPayloadBytes, ct).ConfigureAwait(false);
                if (putStatus != HttpStatusCode.OK)
                    return MapAwsError(putStatus, putBody);

                using var putDoc = JsonDocument.Parse(putBody);
                var putRoot = putDoc.RootElement;
                var versionId = putRoot.TryGetProperty("VersionId", out var v) ? v.GetString() ?? "1" : "1";
                return Result<SecretProperties>.Success(new SecretProperties { Name = name, Version = versionId, Enabled = true });
            }

            return MapAwsError(status, body);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (update.ContentType is not null || update.Enabled is not null || update.ExpiresOn is not null || update.NotBefore is not null)
            return Task.FromResult(Result<SecretProperties>.Failure(VaultErrors.InvalidInput("update", "O AWS Secrets Manager não suporta tipo de conteúdo, habilitar/desabilitar nem validade.")));

        var inputError = Rules.UpdateSecret(name, version, update, _time.GetUtcNow());

        return ExecuteAsync("secret.update", name, inputError, isWrite: true, async ct =>
        {
            byte[] payloadBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("SecretId", name);
                    writer.WriteEndObject();
                }
                payloadBytes = buffer.ToArray();
            }

            var (status, body) = await SendAwsRequestAsync("secretsmanager.DescribeSecret", payloadBytes, ct).ConfigureAwait(false);

            if (status != HttpStatusCode.OK)
                return MapAwsError(status, body);

            return Result<SecretProperties>.Success(new SecretProperties { Name = name, Version = version ?? "1", Enabled = true });
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            byte[] payloadBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("SecretId", name);
                    writer.WriteEndObject();
                }
                payloadBytes = buffer.ToArray();
            }

            var (status, body) = await SendAwsRequestAsync("secretsmanager.DeleteSecret", payloadBytes, ct).ConfigureAwait(false);
            if (status == HttpStatusCode.NotFound)
                return Result<DeletedVaultItem>.Failure(VaultErrors.NotFound());

            if (status == HttpStatusCode.OK)
                return Result<DeletedVaultItem>.Success(new DeletedVaultItem(name, _time.GetUtcNow(), ScheduledPurgeDate: _time.GetUtcNow().AddDays(30)));

            return MapAwsError(status, body);
        }, cancellationToken);

    // ---------- IVaultHealthProbe ----------

    /// <inheritdoc />
    public async Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            byte[] payloadBytes;
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("MaxResults", 1);
                    writer.WriteEndObject();
                }
                payloadBytes = buffer.ToArray();
            }

            var (status, body) = await SendAwsRequestAsync("secretsmanager.ListSecrets", payloadBytes, cancellationToken).ConfigureAwait(false);

            return status == HttpStatusCode.OK
                ? Result.Success()
                : Result.Failure(VaultErrors.Unavailable());
        }
        catch
        {
            return Result.Failure(VaultErrors.Unavailable());
        }
    }

    // ---------- HTTP & SigV4 Helper ----------

    private async Task<(HttpStatusCode Status, string Body)> SendAwsRequestAsync(string target, byte[] jsonBytes, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new ByteArrayContent(jsonBytes)
        };

        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-amz-json-1.1");
        request.Headers.Add("x-amz-target", target);

        AwsSigV4Signer.Sign(request, jsonBytes, _options.Region, _accessKey, _secretKey, _sessionToken, _time.GetUtcNow());

        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        var responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return (response.StatusCode, responseBody);
    }

    private static Error MapAwsError(HttpStatusCode status, string responseBody)
    {
        if (responseBody.Contains("ResourceNotFoundException", StringComparison.OrdinalIgnoreCase))
            return VaultErrors.NotFound();
        if (responseBody.Contains("ResourceExistsException", StringComparison.OrdinalIgnoreCase))
            return VaultErrors.Conflict();
        if (responseBody.Contains("AccessDeniedException", StringComparison.OrdinalIgnoreCase) || status == HttpStatusCode.Forbidden)
            return VaultErrors.AccessDenied();
        if (responseBody.Contains("ThrottlingException", StringComparison.OrdinalIgnoreCase) || status == (HttpStatusCode)429)
            return VaultErrors.Throttled();
        if (responseBody.Contains("InvalidRequestException", StringComparison.OrdinalIgnoreCase) ||
            responseBody.Contains("InvalidParameterException", StringComparison.OrdinalIgnoreCase))
            return VaultErrors.InvalidInput("request", "Parâmetro inválido na requisição ao AWS Secrets Manager.");

        return status switch
        {
            HttpStatusCode.NotFound => VaultErrors.NotFound(),
            HttpStatusCode.Conflict => VaultErrors.Conflict(),
            HttpStatusCode.Unauthorized => VaultErrors.AuthenticationFailed(),
            HttpStatusCode.Forbidden => VaultErrors.AccessDenied(),
            (HttpStatusCode)429 => VaultErrors.Throttled(),
            HttpStatusCode.ServiceUnavailable or HttpStatusCode.BadGateway or HttpStatusCode.GatewayTimeout => VaultErrors.Unavailable(),
            _ => VaultErrors.ProviderFailure()
        };
    }

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
