using System.Buffers;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
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
/// Segredos no AWS Secrets Manager pela API HTTP (protocolo JSON 1.1) com assinatura SigV4 feita no próprio pacote, sem o SDK da
/// AWS (provedor <c>AwsSecretsManager</c>). Thread-safe; uma instância por aplicação.
/// </summary>
/// <remarks>
/// <para><b>Transporte</b>: o mesmo dos demais provedores HTTP (<see cref="VaultHttpClient"/>): retentativa com backoff,
/// tempo limite também na leitura do corpo, teto de resposta (<see cref="VaultHttpSettings.MaxResponseBytes"/>), sem
/// redirecionamento, e circuit breaker. A AWS responde quase todo erro com HTTP 400 e o tipo no corpo: <c>ThrottlingException</c> é
/// repetida como um 429, e <c>ExpiredTokenException</c> (ou outra recusa da credencial) renova a credencial e repete a chamada uma
/// vez. Gravações levam um <c>ClientRequestToken</c>, e por isso também podem ser repetidas sem criar versões duplicadas.</para>
/// <para><b>Credenciais</b>: veja <see cref="AwsSecretsManagerOptions"/> (web identity, container, IMDSv2 e chaves estáticas). A
/// credencial fica em cache e as temporárias são renovadas antes de expirar.</para>
/// <para><b>Tags</b> valem para o segredo inteiro (não por versão) e são substituídas por inteiro (<c>TagResource</c> e
/// <c>UntagResource</c>). Não há tipo de conteúdo, habilitar/desabilitar nem validade: pedir esses campos retorna
/// <see cref="VaultErrors.InvalidInput"/>.</para>
/// <para><b>Listagens</b> passam de página em página até o fim e falham com <see cref="VaultErrors.TooManyItems"/> acima de
/// <see cref="AwsSecretsManagerOptions.MaxListItems"/> (nunca devolvem uma lista cortada).</para>
/// </remarks>
public sealed partial class AwsSecretsManagerSecretStore : VaultHttpProviderBase, ISecretStore, IVaultHealthProbe, IDisposable
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "AwsSecretsManager";

    /// <summary>Tamanho máximo de um valor no AWS Secrets Manager: 64 KB.</summary>
    public const int MaxSecretValueBytes = 64 * 1024;

    private const int PageSize = 100;
    private const string CurrentStage = "AWSCURRENT";

    private static readonly VaultProviderRules Rules = new(NamePattern(), "use de 1 a 512 caracteres: letras, números e /_+=.@-.")
    {
        VersionPattern = VersionPattern(),
        MaxSecretValueBytes = MaxSecretValueBytes,
        MaxTags = 50,
        MaxTagKeyLength = 128,
        MaxTagValueLength = 256,
        MaxBackupBytes = 0
    };

    private readonly string _region;
    private readonly int _maxListItems;
    private readonly TimeProvider _time;
    private readonly AwsCredentialSource _credentials;
    private readonly VaultTokenSource _tokens;
    private readonly VaultHttpClient _http;
    private int _disposed;

    /// <summary>Cria o store. As opções são validadas aqui (falha na inicialização, não na primeira requisição).</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas ou nenhuma fonte de credenciais.</exception>
    public AwsSecretsManagerSecretStore(AwsSecretsManagerOptions options, ILogger<AwsSecretsManagerSecretStore>? logger = null)
        : base(Provider, logger ?? (ILogger)NullLogger.Instance, CreateCircuitBreaker(options))
    {
        ArgumentNullException.ThrowIfNull(options);
        var resolved = options.Validate();
        _region = options.Region;
        _maxListItems = options.MaxListItems;
        _time = options.TimeProvider ?? TimeProvider.System;

        _credentials = new AwsCredentialSource(options, resolved, logger ?? (ILogger)NullLogger.Instance);
        _tokens = new VaultTokenSource(_credentials.LoginAsync, _time);
        _http = new VaultHttpClient(resolved.Endpoint, options.Http, _tokens, Sign) { ErrorStatusMapper = AwsErrors.JsonStatus };
    }

    private static VaultCircuitBreaker? CreateCircuitBreaker(AwsSecretsManagerOptions? options) => options is null
        ? null
        : VaultCircuitBreaker.Create(Provider, options.Http.CircuitBreaker, options.TimeProvider, "AwsSecretsManagerOptions.Http.CircuitBreaker");

    [GeneratedRegex(@"^[0-9a-zA-Z/_+=.@-]{1,512}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"^[0-9a-zA-Z_-]{1,64}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VersionPattern();

    // ---------- Leitura ----------

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultSecret>("secret.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            using var response = await CallAsync("GetSecretValue", w =>
            {
                w.WriteString("SecretId", name);
                if (version is not null)
                    w.WriteString("VersionId", version);
            }, idempotent: true, ct).ConfigureAwait(false);
            if (response.Status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();

            if (String(response.Root, "SecretString") is not { } value)
                return VaultErrors.InvalidInput("SecretString", "O segredo é binário (SecretBinary): o provedor lê só SecretString.");

            var created = Epoch(response.Root, "CreatedDate");
            return new VaultSecret(new SecretProperties
            {
                Name = name,
                Version = String(response.Root, "VersionId"),
                Enabled = true,
                CreatedOn = created,
                UpdatedOn = created
            }, value);
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Um segredo agendado para exclusão (na janela de recuperação) não conta como existente.</remarks>
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<bool>("secret.exists", name, Rules.Name(name), isWrite: false, async ct =>
        {
            using var described = await CallAsync("DescribeSecret", w => w.WriteString("SecretId", name), idempotent: true, ct).ConfigureAwait(false);
            return described.Status == HttpStatusCode.OK && Epoch(described.Root, "DeletedDate") is null;
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Devolve nome, versão atual (<c>AWSCURRENT</c>), datas e tags de cada segredo.</remarks>
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.list", null, null, isWrite: false, async ct =>
        {
            var secrets = new List<SecretProperties>();
            await PagesAsync("ListSecrets", null, "SecretList", item =>
            {
                if (String(item, "Name") is not { } secretName)
                    return;
                EnsureListLimit(secrets.Count + 1, _maxListItems);
                secrets.Add(new SecretProperties
                {
                    Name = secretName,
                    Version = CurrentVersion(item, "SecretVersionsToStages"),
                    Enabled = true,
                    CreatedOn = Epoch(item, "CreatedDate"),
                    UpdatedOn = Epoch(item, "LastChangedDate"),
                    Tags = CopyTags(TagMap(item))
                });
            }, ct).ConfigureAwait(false);
            return secrets;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var versions = new List<SecretProperties>();
            var status = await PagesAsync("ListSecretVersionIds", name, "Versions", item =>
            {
                if (String(item, "VersionId") is not { } id)
                    return;
                EnsureListLimit(versions.Count + 1, _maxListItems);
                versions.Add(new SecretProperties { Name = name, Version = id, Enabled = true, CreatedOn = Epoch(item, "CreatedDate") });
            }, ct).ConfigureAwait(false);

            if (status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();
            return versions;
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Lista um segredo (exige a permissão <c>secretsmanager:ListSecrets</c>), pelo circuit breaker e com métrica.</remarks>
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.health", null, null, isWrite: false, async ct =>
        {
            using var page = await CallAsync("ListSecrets", w => w.WriteNumber("MaxResults", 1), idempotent: true, ct).ConfigureAwait(false);
        }, cancellationToken);

    // ---------- Escrita ----------

    /// <inheritdoc />
    /// <remarks>
    /// Cria o segredo (<c>CreateSecret</c>) ou, se ele já existir, grava uma nova versão (<c>PutSecretValue</c>). Com
    /// <see cref="SecretWriteOptions.Tags"/> informado, as tags do segredo passam a ser exatamente essas, também quando ele já existia.
    /// </remarks>
    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SecretWriteOptions();
        var inputError = Rules.SetSecret(name, value, options, _time.GetUtcNow()) ??
            (options.ContentType is not null || !options.Enabled || options.ExpiresOn is not null || options.NotBefore is not null
                ? VaultErrors.InvalidInput("options", "O AWS Secrets Manager não tem tipo de conteúdo, habilitar/desabilitar nem validade: informe só valor e tags.")
                : null);

        return ExecuteAsync<SecretProperties>("secret.set", name, inputError, isWrite: true, async ct =>
        {
            // O token vira o VersionId e torna a gravação idempotente: repetida, ela não cria outra versão
            var requestToken = Guid.NewGuid().ToString("N");
            using (var created = await CallAsync("CreateSecret", w =>
                   {
                       w.WriteString("Name", name);
                       w.WriteString("ClientRequestToken", requestToken);
                       w.WriteString("SecretString", value);
                       if (options.Tags is { Count: > 0 } tags)
                           WriteTags(w, tags);
                   }, idempotent: true, ct, conflictAllowed: true).ConfigureAwait(false))
            {
                if (created.Status == HttpStatusCode.OK)
                    return Written(name, String(created.Root, "VersionId") ?? requestToken, options.Tags);
            }

            // Já existe: nova versão com o mesmo token
            string version;
            using (var put = await CallAsync("PutSecretValue", w =>
                   {
                       w.WriteString("SecretId", name);
                       w.WriteString("ClientRequestToken", requestToken);
                       w.WriteString("SecretString", value);
                   }, idempotent: true, ct).ConfigureAwait(false))
            {
                if (put.Status == HttpStatusCode.NotFound)
                    return VaultErrors.NotFound();
                version = String(put.Root, "VersionId") ?? requestToken;
            }

            if (options.Tags is { } desired && await ReplaceTagsAsync(name, desired, ct).ConfigureAwait(false) is { } tagError)
                return tagError;
            return Written(name, version, options.Tags);
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Só <see cref="SecretPropertiesUpdate.Tags"/> é suportado, e as tags valem para o segredo inteiro: com tags, não informe a
    /// versão. As tags passam a ser exatamente as informadas (<c>UntagResource</c> das que saíram e <c>TagResource</c> das novas ou
    /// alteradas; as duas chamadas não são atômicas). Sem nada a alterar, confere que o segredo (e a versão, se informada) existe.
    /// Permissões: <c>secretsmanager:DescribeSecret</c>, <c>TagResource</c> e <c>UntagResource</c>.
    /// </remarks>
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateSecret(name, version, update, _time.GetUtcNow()) ??
            (update.ContentType is not null || update.Enabled is not null || update.ExpiresOn is not null || update.NotBefore is not null
                ? VaultErrors.InvalidInput("update", "O AWS Secrets Manager só altera as tags: não há tipo de conteúdo, habilitar/desabilitar nem validade.")
                : null) ??
            (update.Tags is not null && version is not null
                ? VaultErrors.InvalidInput("version", "As tags do AWS Secrets Manager valem para o segredo inteiro, não para uma versão: não informe a versão.")
                : null);

        return ExecuteAsync<SecretProperties>("secret.update", name, inputError, isWrite: true, async ct =>
        {
            Dictionary<string, string> current;
            DateTimeOffset? createdOn, updatedOn;
            string? currentVersion;
            using (var described = await CallAsync("DescribeSecret", w => w.WriteString("SecretId", name), idempotent: true, ct).ConfigureAwait(false))
            {
                if (described.Status == HttpStatusCode.NotFound)
                    return VaultErrors.NotFound();
                if (Epoch(described.Root, "DeletedDate") is not null)
                    return VaultErrors.Conflict();   // agendado para exclusão
                if (version is not null && !HasVersion(described.Root, version))
                    return VaultErrors.NotFound();

                current = TagMap(described.Root);
                createdOn = Epoch(described.Root, "CreatedDate");
                updatedOn = Epoch(described.Root, "LastChangedDate");
                currentVersion = CurrentVersion(described.Root, "VersionIdsToStages");
            }

            IReadOnlyDictionary<string, string> tags = current;
            if (update.Tags is { } desired)
            {
                if (await ApplyTagsAsync(name, current, desired, ct).ConfigureAwait(false) is { } tagError)
                    return tagError;
                tags = desired;
            }

            return new SecretProperties
            {
                Name = name,
                Version = version ?? currentVersion,
                Enabled = true,
                CreatedOn = createdOn,
                UpdatedOn = updatedOn,
                Tags = CopyTags(tags)
            };
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// Agenda a exclusão com a janela de recuperação padrão da AWS (30 dias); <see cref="DeletedVaultItem.ScheduledPurgeDate"/> é a
    /// data informada pela AWS. O provedor não expõe a recuperação.
    /// </remarks>
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<DeletedVaultItem>("secret.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var deleted = await CallAsync("DeleteSecret", w => w.WriteString("SecretId", name), idempotent: false, ct).ConfigureAwait(false);
            if (deleted.Status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();

            var now = _time.GetUtcNow();
            return new DeletedVaultItem(name, now, ScheduledPurgeDate: Epoch(deleted.Root, "DeletionDate") ?? now.AddDays(30));
        }, cancellationToken);

    /// <inheritdoc />
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 1)
            return;
        _http.Dispose();
        _tokens.Dispose();
        _credentials.Dispose();
    }

    // ---------- HTTP ----------

    /// <summary>Assina a tentativa com a credencial atual (data de agora: cada retentativa é assinada de novo).</summary>
    private void Sign(HttpRequestMessage request, string token) =>
        AwsSigV4Signer.Sign(request, AwsCredentials.Decode(token), _region, _time.GetUtcNow());

    /// <summary>
    /// Chama uma ação da API. Devolve 200 com o JSON, 404 (item inexistente) e, só com <paramref name="conflictAllowed"/>, 409; os
    /// demais erros lançam <see cref="VaultHttpException"/> com o status equivalente e o código da AWS (seguro para log). O corpo
    /// enviado é zerado no fim (pode conter o valor do segredo).
    /// </summary>
    private async Task<AwsResponse> CallAsync(string action, Action<Utf8JsonWriter> write, bool idempotent, CancellationToken ct,
        bool conflictAllowed = false)
    {
        var payload = Json(write);
        var payloadHash = AwsSigV4Signer.HashPayload(payload);
        try
        {
            using var response = await _http.SendAsync(() => Request(action, payload, payloadHash), idempotent, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotFound || (conflictAllowed && response.StatusCode == HttpStatusCode.Conflict))
                return new AwsResponse(response.StatusCode, null);
            if (!response.IsSuccessStatusCode)
                await ThrowAsync(response, ct).ConfigureAwait(false);

            return new AwsResponse(HttpStatusCode.OK, await _http.ReadBytesAsync(response, ct).ConfigureAwait(false));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    private HttpRequestMessage Request(string action, byte[] payload, string payloadHash)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, _http.BaseAddress)
        {
            Content = new ByteArrayContent(payload) { Headers = { ContentType = new MediaTypeHeaderValue("application/x-amz-json-1.1") } }
        };
        request.Headers.TryAddWithoutValidation("X-Amz-Target", "secretsmanager." + action);
        request.Options.Set(AwsSigV4Signer.PayloadHashKey, payloadHash);
        return request;
    }

    /// <summary>Lança o erro com o código da AWS como detalhe (o código é só para o log; a conversão usa o status equivalente).</summary>
    private async Task ThrowAsync(HttpResponseMessage response, CancellationToken ct)
    {
        string? code = null;
        try
        {
            var body = await _http.ReadBytesAsync(response, ct).ConfigureAwait(false);
            code = AwsErrors.JsonCode(body);
        }
        catch (Exception exception) when (exception is VaultResponseTooLargeException or TimeoutException or HttpRequestException)
        {
            // Sem o código: o status basta para a conversão
        }

        VaultHttpClient.EnsureSuccess(response, code);
    }

    /// <summary>Passa por todas as páginas (<c>NextToken</c>), com proteção contra paginação sem fim. 404 → devolve o status.</summary>
    private async Task<HttpStatusCode> PagesAsync(string action, string? secretId, string arrayName, Action<JsonElement> each, CancellationToken ct)
    {
        string? next = null;
        var pages = 0;
        do
        {
            if (++pages > _maxListItems + 1)
                throw new JsonException("Paginação da listagem sem fim.");

            var token = next;
            using var page = await CallAsync(action, w =>
            {
                if (secretId is not null)
                    w.WriteString("SecretId", secretId);
                w.WriteNumber("MaxResults", PageSize);
                if (token is not null)
                    w.WriteString("NextToken", token);
            }, idempotent: true, ct).ConfigureAwait(false);
            if (page.Status == HttpStatusCode.NotFound)
                return HttpStatusCode.NotFound;

            if (page.Root.TryGetProperty(arrayName, out var items) && items.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in items.EnumerateArray())
                    each(item);
            }

            next = String(page.Root, "NextToken");
            if (next is not null && string.Equals(next, token, StringComparison.Ordinal))
                throw new JsonException("A listagem devolveu a mesma página de novo.");
        }
        while (next is not null);

        return HttpStatusCode.OK;
    }

    /// <summary>Lê as tags atuais e as substitui pelas informadas. <c>null</c> = sucesso.</summary>
    private async Task<Error?> ReplaceTagsAsync(string name, IReadOnlyDictionary<string, string> desired, CancellationToken ct)
    {
        Dictionary<string, string> current;
        using (var described = await CallAsync("DescribeSecret", w => w.WriteString("SecretId", name), idempotent: true, ct).ConfigureAwait(false))
        {
            if (described.Status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();
            current = TagMap(described.Root);
        }

        return await ApplyTagsAsync(name, current, desired, ct).ConfigureAwait(false);
    }

    /// <summary>Remove as tags que saíram e grava as novas ou alteradas (chaves comparadas exatamente, como na AWS).</summary>
    private async Task<Error?> ApplyTagsAsync(string name, Dictionary<string, string> current, IReadOnlyDictionary<string, string> desired,
        CancellationToken ct)
    {
        var wanted = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in desired)
            wanted[key] = value;

        var remove = current.Keys.Where(k => !wanted.ContainsKey(k)).ToList();
        if (remove.Count > 0)
        {
            using var untagged = await CallAsync("UntagResource", w =>
            {
                w.WriteString("SecretId", name);
                w.WriteStartArray("TagKeys");
                foreach (var key in remove)
                    w.WriteStringValue(key);
                w.WriteEndArray();
            }, idempotent: true, ct).ConfigureAwait(false);
            if (untagged.Status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();
        }

        var put = wanted.Where(t => !current.TryGetValue(t.Key, out var old) || !string.Equals(old, t.Value, StringComparison.Ordinal)).ToList();
        if (put.Count > 0)
        {
            using var tagged = await CallAsync("TagResource", w =>
            {
                w.WriteString("SecretId", name);
                WriteTags(w, put);
            }, idempotent: true, ct).ConfigureAwait(false);
            if (tagged.Status == HttpStatusCode.NotFound)
                return VaultErrors.NotFound();
        }

        return null;
    }

    // ---------- JSON ----------

    /// <summary>Corpo JSON escrito com <see cref="Utf8JsonWriter"/> (compatível com AOT). O buffer intermediário é zerado.</summary>
    private static byte[] Json(Action<Utf8JsonWriter> write)
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

    private static void WriteTags(Utf8JsonWriter writer, IEnumerable<KeyValuePair<string, string>> tags)
    {
        writer.WriteStartArray("Tags");
        foreach (var (key, value) in tags)
        {
            writer.WriteStartObject();
            writer.WriteString("Key", key);
            writer.WriteString("Value", value);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
    }

    private static Result<SecretProperties> Written(string name, string version, IReadOnlyDictionary<string, string>? tags) =>
        new SecretProperties { Name = name, Version = version, Enabled = true, Tags = CopyTags(tags) };

    private static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>Data em segundos desde 1970 (número com fração), como a AWS devolve. Fora da faixa: <c>null</c>.</summary>
    private static DateTimeOffset? Epoch(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var seconds) &&
        double.IsFinite(seconds) && seconds is > 0 and < 253_402_300_799
            ? DateTimeOffset.FromUnixTimeMilliseconds((long)(seconds * 1000))
            : null;

    /// <summary>Tags de um segredo (<c>[{"Key":..,"Value":..}]</c>); entradas malformadas são ignoradas.</summary>
    private static Dictionary<string, string> TagMap(JsonElement element)
    {
        var tags = new Dictionary<string, string>(StringComparer.Ordinal);
        if (element.TryGetProperty("Tags", out var list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (var tag in list.EnumerateArray())
            {
                if (tag.ValueKind == JsonValueKind.Object && String(tag, "Key") is { } key)
                    tags[key] = String(tag, "Value") ?? string.Empty;
            }
        }

        return tags;
    }

    /// <summary>Versão com o rótulo <c>AWSCURRENT</c> num mapa versão → rótulos.</summary>
    private static string? CurrentVersion(JsonElement element, string mapName)
    {
        if (!element.TryGetProperty(mapName, out var map) || map.ValueKind != JsonValueKind.Object)
            return null;
        foreach (var version in map.EnumerateObject())
        {
            if (version.Value.ValueKind == JsonValueKind.Array &&
                version.Value.EnumerateArray().Any(stage => stage.ValueKind == JsonValueKind.String && stage.ValueEquals(CurrentStage)))
                return version.Name;
        }

        return null;
    }

    private static bool HasVersion(JsonElement element, string version) =>
        element.TryGetProperty("VersionIdsToStages", out var map) && map.ValueKind == JsonValueKind.Object && map.TryGetProperty(version, out _);

    /// <summary>Resposta de uma ação: status (200, 404 ou 409) e o JSON. Ao descartar, o buffer (que pode ter valores) é zerado.</summary>
    private sealed class AwsResponse : IDisposable
    {
        private static readonly byte[] EmptyObject = "{}"u8.ToArray();
        private readonly byte[]? _buffer;
        private readonly JsonDocument _document;

        internal AwsResponse(HttpStatusCode status, byte[]? buffer)
        {
            Status = status;
            _buffer = buffer;
            try
            {
                _document = JsonDocument.Parse(buffer is { Length: > 0 } ? buffer : EmptyObject, new JsonDocumentOptions { MaxDepth = 32 });
                if (_document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    _document.Dispose();
                    throw new JsonException("Resposta da AWS não é um objeto JSON.");
                }
            }
            catch (JsonException)
            {
                if (buffer is not null)
                    CryptographicOperations.ZeroMemory(buffer);   // a resposta fora do formato também pode conter valores
                throw;
            }
        }

        public HttpStatusCode Status { get; }

        public JsonElement Root => _document.RootElement;

        public void Dispose()
        {
            _document.Dispose();
            if (_buffer is not null)
                CryptographicOperations.ZeroMemory(_buffer);
        }
    }
}
