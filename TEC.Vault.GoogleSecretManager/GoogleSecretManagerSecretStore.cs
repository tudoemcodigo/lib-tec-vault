using System.Buffers;
using System.Net;
using System.Security.Cryptography;
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
/// Segredos no Google Cloud Secret Manager pela API REST v1, sem o SDK do Google (provedor <c>GoogleSecretManager</c>).
/// Thread-safe; uma instância por aplicação.
/// </summary>
/// <remarks>
/// <para><b>Transporte</b>: o mesmo dos demais provedores HTTP (<see cref="VaultHttpClient"/>): retentativa com backoff,
/// tempo limite também na leitura do corpo, teto de resposta (<see cref="VaultHttpSettings.MaxResponseBytes"/>), sem
/// redirecionamento, e circuit breaker. Um 401 descarta o token em cache e repete a chamada uma vez com um token novo.</para>
/// <para><b>Credencial</b>: veja <see cref="GoogleSecretManagerOptions"/> (token estático, Service Account JSON ou Metadata Server).</para>
/// <para><b>Tags</b> viram <c>labels</c> do segredo (não por versão), substituídas por inteiro (<c>PATCH</c> com
/// <c>updateMask=labels</c>) e conferidas antes da chamada com as regras do Google: chave começando por letra minúscula, só letras
/// minúsculas, dígitos, <c>_</c> e <c>-</c>, até 63 caracteres. <see cref="SecretPropertiesUpdate.Enabled"/> habilita ou desabilita
/// a versão. Não há tipo de conteúdo nem validade.</para>
/// <para><b>Listagens</b> passam de página em página até o fim e falham com <see cref="VaultErrors.TooManyItems"/> acima de
/// <see cref="GoogleSecretManagerOptions.MaxListItems"/> (nunca devolvem uma lista cortada).</para>
/// </remarks>
public sealed partial class GoogleSecretManagerSecretStore : VaultHttpProviderBase, ISecretStore, IVaultHealthProbe, IDisposable
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "GoogleSecretManager";

    /// <summary>Tamanho máximo de um valor no Google Secret Manager: 64 KB.</summary>
    public const int MaxSecretValueBytes = 64 * 1024;

    private const int PageSize = 100;

    private static readonly VaultProviderRules Rules = new(NamePattern(), "use de 1 a 255 caracteres: letras, números, hífen e sublinhado.")
    {
        VersionPattern = VersionPattern(),
        MaxSecretValueBytes = MaxSecretValueBytes,
        MaxTags = 50,
        MaxTagKeyLength = 63,
        MaxTagValueLength = 63,
        MaxBackupBytes = 0
    };

    private readonly string _projectPath;
    private readonly int _maxListItems;
    private readonly TimeProvider _time;
    private readonly GoogleCredentials _credentials;
    private readonly VaultTokenSource _tokens;
    private readonly VaultHttpClient _http;
    private int _disposed;

    /// <summary>Cria o store. As opções são validadas aqui (falha na inicialização, não na primeira requisição).</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas ou nenhuma credencial.</exception>
    public GoogleSecretManagerSecretStore(GoogleSecretManagerOptions options, ILogger<GoogleSecretManagerSecretStore>? logger = null)
        : base(Provider, logger ?? (ILogger)NullLogger.Instance, CreateCircuitBreaker(options))
    {
        ArgumentNullException.ThrowIfNull(options);
        var resolved = options.Validate();
        _projectPath = "v1/projects/" + VaultEndpoint.Segment(resolved.ProjectId);
        _maxListItems = options.MaxListItems;
        _time = options.TimeProvider ?? TimeProvider.System;

        _credentials = new GoogleCredentials(options, resolved, _time);
        _tokens = new VaultTokenSource(_credentials.LoginAsync, _time);
        _http = new VaultHttpClient(resolved.Endpoint, options.Http, _tokens);
    }

    private static VaultCircuitBreaker? CreateCircuitBreaker(GoogleSecretManagerOptions? options) => options is null
        ? null
        : VaultCircuitBreaker.Create(Provider, options.Http.CircuitBreaker, options.TimeProvider, "GoogleSecretManagerOptions.Http.CircuitBreaker");

    [GeneratedRegex(@"^[0-9a-zA-Z_-]{1,255}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"^(latest|[0-9]{1,19})\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VersionPattern();

    // Regras de labels do Google: chave começa com letra minúscula; letras minúsculas, dígitos, "_" e "-"
    [GeneratedRegex(@"^[\p{Ll}\p{Lo}][\p{Ll}\p{Lo}\p{N}_-]{0,62}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex LabelKeyPattern();

    [GeneratedRegex(@"^[\p{Ll}\p{Lo}\p{N}_-]{0,63}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex LabelValuePattern();

    // ---------- Leitura ----------

    /// <inheritdoc />
    /// <remarks>Sem <paramref name="version"/>, lê <c>latest</c>. O valor vem em Base64 e é decodificado como UTF-8.</remarks>
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultSecret>("secret.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            var target = version ?? "latest";
            using var response = await GetAsync($"{SecretPath(name)}/versions/{VaultEndpoint.Segment(target)}:access", ct).ConfigureAwait(false);
            if (response is null)
                return VaultErrors.NotFound();

            if (!response.Root.TryGetProperty("payload", out var payload) || payload.ValueKind != JsonValueKind.Object ||
                !payload.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.String)
                throw new JsonException("Resposta sem payload.data.");

            var bytes = data.GetBytesFromBase64();   // FormatException em Base64 inválido: convertida em resposta fora do formato
            try
            {
                return new VaultSecret(new SecretProperties
                {
                    Name = name,
                    Version = LastSegment(String(response.Root, "name")) ?? target,
                    Enabled = true
                }, Encoding.UTF8.GetString(bytes));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<bool>("secret.exists", name, Rules.Name(name), isWrite: false, async ct =>
        {
            using var response = await GetAsync(SecretPath(name), ct).ConfigureAwait(false);
            return response is not null;
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Devolve nome, data de criação e labels (como tags) de cada segredo.</remarks>
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.list", null, null, isWrite: false, async ct =>
        {
            var secrets = new List<SecretProperties>();
            await PagesAsync(_projectPath + "/secrets", "secrets", item =>
            {
                if (LastSegment(String(item, "name")) is not { } secretName)
                    return;
                EnsureListLimit(secrets.Count + 1, _maxListItems);
                secrets.Add(new SecretProperties
                {
                    Name = secretName,
                    Enabled = true,
                    CreatedOn = Date(item, "createTime"),
                    Tags = CopyTags(Labels(item))
                });
            }, ct).ConfigureAwait(false);
            return secrets;
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Versões com estado diferente de <c>ENABLED</c> (desabilitadas ou destruídas) voltam com <c>Enabled = false</c>.</remarks>
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var versions = new List<SecretProperties>();
            var found = await PagesAsync(SecretPath(name) + "/versions", "versions", item =>
            {
                if (VersionProperties(name, item) is not { } properties)
                    return;
                EnsureListLimit(versions.Count + 1, _maxListItems);
                versions.Add(properties);
            }, ct).ConfigureAwait(false);

            if (!found)
                return VaultErrors.NotFound();
            return versions;
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Lista um segredo do projeto (exige <c>secretmanager.secrets.list</c>), pelo circuit breaker e com métrica.</remarks>
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.health", null, null, isWrite: false, async ct =>
        {
            using var response = await GetAsync(_projectPath + "/secrets?pageSize=1", ct).ConfigureAwait(false);
            if (response is null)
                throw new VaultHttpException(HttpStatusCode.NotFound, "projeto");
        }, cancellationToken);

    // ---------- Escrita ----------

    /// <inheritdoc />
    /// <remarks>
    /// Grava uma nova versão (<c>:addVersion</c>); se o segredo não existir, cria (replicação automática, com as tags como labels) e
    /// grava. Com <see cref="SecretWriteOptions.Tags"/> informado e o segredo já existente, as labels passam a ser exatamente essas.
    /// </remarks>
    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SecretWriteOptions();
        var inputError = Rules.SetSecret(name, value, options, _time.GetUtcNow()) ?? LabelsError(options.Tags) ??
            (options.ContentType is not null || !options.Enabled || options.ExpiresOn is not null || options.NotBefore is not null
                ? VaultErrors.InvalidInput("options", "O Google Secret Manager não tem tipo de conteúdo nem validade, e grava a versão habilitada: informe só valor e tags.")
                : null);

        return ExecuteAsync<SecretProperties>("secret.set", name, inputError, isWrite: true, async ct =>
        {
            var plain = Encoding.UTF8.GetBytes(value);
            var payload = Json(w =>
            {
                w.WriteStartObject("payload");
                w.WriteBase64String("data", plain);   // sem string intermediária com o valor em Base64
                w.WriteEndObject();
            });
            try
            {
                var created = false;
                var added = await SendAsync(HttpMethod.Post, SecretPath(name) + ":addVersion", payload, idempotent: false, ct).ConfigureAwait(false);
                if (added is null)
                {
                    // Não existe: cria (409 = criado por outra instância no meio) e grava a versão
                    var create = Json(w =>
                    {
                        w.WriteStartObject("replication");
                        w.WriteStartObject("automatic");
                        w.WriteEndObject();
                        w.WriteEndObject();
                        if (options.Tags is { Count: > 0 } tags)
                            WriteLabels(w, tags);
                    });
                    var createResponse = await SendAsync(HttpMethod.Post, $"{_projectPath}/secrets?secretId={Uri.EscapeDataString(name)}", create,
                        idempotent: false, ct, conflictAllowed: true).ConfigureAwait(false);
                    created = createResponse is not null;   // 409: outra instância criou; as labels ainda são aplicadas abaixo
                    createResponse?.Dispose();

                    added = await SendAsync(HttpMethod.Post, SecretPath(name) + ":addVersion", payload, idempotent: false, ct).ConfigureAwait(false)
                        ?? throw new VaultHttpException(HttpStatusCode.NotFound, "segredo removido durante a gravação");
                }

                SecretProperties properties;
                using (added)
                    properties = VersionProperties(name, added.Root) ?? throw new JsonException("Resposta sem name.");

                if (!created && options.Tags is { } desired)
                {
                    using var patched = await PatchLabelsAsync(name, desired, ct).ConfigureAwait(false);
                    if (patched is null)
                        return VaultErrors.NotFound();
                }

                return properties with { Tags = CopyTags(options.Tags) };
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plain);
                CryptographicOperations.ZeroMemory(payload);
            }
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>
    /// <see cref="SecretPropertiesUpdate.Tags"/> substitui as labels do segredo (<c>PATCH</c> com <c>updateMask=labels</c>);
    /// <see cref="SecretPropertiesUpdate.Enabled"/> habilita ou desabilita a versão (<c>latest</c> se <paramref name="version"/> for
    /// <c>null</c>). As duas alterações juntas não são atômicas. Com só tags, não informe a versão (as labels valem para o segredo).
    /// O retorno traz o estado real da versão. Tipo de conteúdo e validade voltam <see cref="VaultErrors.InvalidInput"/>.
    /// </remarks>
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateSecret(name, version, update, _time.GetUtcNow()) ?? LabelsError(update.Tags) ??
            (update.ContentType is not null || update.ExpiresOn is not null || update.NotBefore is not null
                ? VaultErrors.InvalidInput("update", "O Google Secret Manager não tem tipo de conteúdo nem validade: altere só tags (labels) e habilitado.")
                : null) ??
            (update.Tags is not null && update.Enabled is null && version is not null
                ? VaultErrors.InvalidInput("version", "As labels do Google Secret Manager valem para o segredo inteiro, não para uma versão: não informe a versão.")
                : null);

        return ExecuteAsync<SecretProperties>("secret.update", name, inputError, isWrite: true, async ct =>
        {
            var target = SecretPath(name) + "/versions/" + VaultEndpoint.Segment(version ?? "latest");
            IReadOnlyDictionary<string, string>? labels = null;
            if (update.Tags is { } desired)
            {
                using var patched = await PatchLabelsAsync(name, desired, ct).ConfigureAwait(false);
                if (patched is null)
                    return VaultErrors.NotFound();
                labels = Labels(patched.Root);
            }

            using var versionResponse = update.Enabled is { } enabled
                ? await SendAsync(HttpMethod.Post, target + (enabled ? ":enable" : ":disable"), Json(_ => { }), idempotent: true, ct).ConfigureAwait(false)
                : await GetAsync(target, ct).ConfigureAwait(false);
            if (versionResponse is null)
                return VaultErrors.NotFound();

            var properties = VersionProperties(name, versionResponse.Root) ?? throw new JsonException("Resposta sem name.");
            return labels is null ? properties : properties with { Tags = CopyTags(labels) };
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>Remove o segredo e todas as versões, <b>sem recuperação</b>; <see cref="DeletedVaultItem.ScheduledPurgeDate"/> fica <c>null</c>.</remarks>
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<DeletedVaultItem>("secret.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var response = await SendAsync(HttpMethod.Delete, SecretPath(name), null, idempotent: false, ct).ConfigureAwait(false);
            if (response is null)
                return VaultErrors.NotFound();
            return new DeletedVaultItem(name, _time.GetUtcNow(), ScheduledPurgeDate: null);
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

    private string SecretPath(string name) => _projectPath + "/secrets/" + VaultEndpoint.Segment(name);

    private Task<GoogleResponse?> GetAsync(string path, CancellationToken ct) => SendAsync(HttpMethod.Get, path, null, idempotent: true, ct);

    /// <summary>
    /// Envia e lê a resposta: 404 → <c>null</c>; com <paramref name="conflictAllowed"/>, 409 também. Os demais erros lançam
    /// <see cref="VaultHttpException"/> com o <c>error.status</c> do Google como detalhe (seguro para log). Quem passa um corpo com
    /// valor de segredo o zera depois (o mesmo corpo pode ser enviado de novo).
    /// </summary>
    private async Task<GoogleResponse?> SendAsync(HttpMethod method, string path, byte[]? body, bool idempotent, CancellationToken ct,
        bool conflictAllowed = false)
    {
        using var response = await _http.SendAsync(() =>
        {
            var request = new HttpRequestMessage(method, path);
            if (body is not null)
                request.Content = new ByteArrayContent(body) { Headers = { ContentType = new("application/json") } };
            return request;
        }, idempotent, ct).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.NotFound || (conflictAllowed && response.StatusCode == HttpStatusCode.Conflict))
            return null;
        if (!response.IsSuccessStatusCode)
        {
            string? status = null;
            try
            {
                status = ErrorStatus(await _http.ReadBytesAsync(response, ct).ConfigureAwait(false));
            }
            catch (Exception exception) when (exception is VaultResponseTooLargeException or TimeoutException or HttpRequestException)
            {
                // Sem o detalhe: o status HTTP basta para a conversão
            }

            VaultHttpClient.EnsureSuccess(response, status);
        }

        return new GoogleResponse(await _http.ReadBytesAsync(response, ct).ConfigureAwait(false));
    }

    private Task<GoogleResponse?> PatchLabelsAsync(string name, IReadOnlyDictionary<string, string> labels, CancellationToken ct) =>
        SendAsync(HttpMethod.Patch, SecretPath(name) + "?updateMask=labels", Json(w => WriteLabels(w, labels)), idempotent: true, ct);

    /// <summary>Passa por todas as páginas (<c>nextPageToken</c>), com proteção contra paginação sem fim. <c>false</c>: 404.</summary>
    private async Task<bool> PagesAsync(string path, string arrayName, Action<JsonElement> each, CancellationToken ct)
    {
        string? next = null;
        var pages = 0;
        do
        {
            if (++pages > _maxListItems + 1)
                throw new JsonException("Paginação da listagem sem fim.");

            var token = next;
            var query = $"{path}?pageSize={PageSize}" + (token is null ? "" : "&pageToken=" + Uri.EscapeDataString(token));
            using var page = await GetAsync(query, ct).ConfigureAwait(false);
            if (page is null)
                return false;

            if (page.Root.TryGetProperty(arrayName, out var items) && items.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in items.EnumerateArray())
                    each(item);
            }

            next = String(page.Root, "nextPageToken") is { Length: > 0 } text ? text : null;
            if (next is not null && string.Equals(next, token, StringComparison.Ordinal))
                throw new JsonException("A listagem devolveu a mesma página de novo.");
        }
        while (next is not null);

        return true;
    }

    // ---------- JSON ----------

    /// <summary>Converte as falhas próprias do provedor: Base64 inválido no valor é resposta fora do formato.</summary>
    protected override VaultFailure? MapProviderException(Exception exception) => exception is FormatException
        ? new VaultFailure(VaultErrors.ProviderFailure(), "resposta em formato inesperado (Base64)")
        : null;

    private static Error? LabelsError(IReadOnlyDictionary<string, string>? tags) =>
        tags is not null && tags.Any(t => !LabelKeyPattern().IsMatch(t.Key) || !LabelValuePattern().IsMatch(t.Value ?? string.Empty))
            ? VaultErrors.InvalidInput("tags", "As labels do Google aceitam só letras minúsculas, dígitos, \"_\" e \"-\" (a chave começa com letra), até 63 caracteres.")
            : null;

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

    private static void WriteLabels(Utf8JsonWriter writer, IReadOnlyDictionary<string, string> labels)
    {
        writer.WriteStartObject("labels");
        foreach (var (key, value) in labels)
            writer.WriteString(key, value);
        writer.WriteEndObject();
    }

    /// <summary>Metadados de uma versão (<c>projects/.../versions/N</c>, <c>state</c>, <c>createTime</c>). <c>null</c> sem <c>name</c>.</summary>
    private static SecretProperties? VersionProperties(string name, JsonElement version) =>
        LastSegment(String(version, "name")) is { } id
            ? new SecretProperties
            {
                Name = name,
                Version = id,
                Enabled = string.Equals(String(version, "state") ?? "ENABLED", "ENABLED", StringComparison.Ordinal),
                CreatedOn = Date(version, "createTime")
            }
            : null;

    private static Dictionary<string, string> Labels(JsonElement element)
    {
        var labels = new Dictionary<string, string>(StringComparer.Ordinal);
        if (element.TryGetProperty("labels", out var map) && map.ValueKind == JsonValueKind.Object)
        {
            foreach (var label in map.EnumerateObject())
            {
                if (label.Value.ValueKind == JsonValueKind.String)
                    labels[label.Name] = label.Value.GetString()!;
            }
        }

        return labels;
    }

    /// <summary><c>error.status</c> do Google (ex.: <c>PERMISSION_DENIED</c>), só se for um código simples.</summary>
    private static string? ErrorStatus(byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 16 });
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                   document.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                   String(error, "status") is { Length: > 0 and <= 64 } status && status.All(c => char.IsAsciiLetterUpper(c) || c == '_')
                ? status
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? LastSegment(string? resourceName) =>
        resourceName is { Length: > 0 } && resourceName.LastIndexOf('/') is var slash && slash < resourceName.Length - 1
            ? resourceName[(slash + 1)..]
            : null;

    private static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static DateTimeOffset? Date(JsonElement element, string name) =>
        String(element, name) is { Length: > 0 } text && DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var date)
            ? date
            : null;

    /// <summary>Resposta JSON. Ao descartar, o buffer (que pode ter valores) é zerado.</summary>
    private sealed class GoogleResponse : IDisposable
    {
        private static readonly byte[] EmptyObject = "{}"u8.ToArray();
        private readonly byte[] _buffer;
        private readonly JsonDocument _document;

        internal GoogleResponse(byte[] buffer)
        {
            _buffer = buffer;
            try
            {
                _document = JsonDocument.Parse(buffer.Length > 0 ? buffer : EmptyObject, new JsonDocumentOptions { MaxDepth = 32 });
                if (_document.RootElement.ValueKind != JsonValueKind.Object)
                {
                    _document.Dispose();
                    throw new JsonException("Resposta do Google não é um objeto JSON.");
                }
            }
            catch (JsonException)
            {
                CryptographicOperations.ZeroMemory(buffer);   // a resposta fora do formato também pode conter valores
                throw;
            }
        }

        public JsonElement Root => _document.RootElement;

        public void Dispose()
        {
            _document.Dispose();
            CryptographicOperations.ZeroMemory(_buffer);
        }
    }
}
