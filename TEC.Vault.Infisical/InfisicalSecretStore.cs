using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Infisical.Internal;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.Infisical;

/// <summary>
/// Segredos no Infisical pela API REST v4 (provedor <c>Infisical</c>): leitura, gravação e exclusão em uma pasta de um
/// ambiente de um projeto. Thread-safe; uma instância por aplicação.
/// </summary>
/// <remarks>
/// <para><b>Nomes</b>: o Infisical diferencia maiúsculas; o TEC.Vault não. Uma leitura, gravação ou exclusão que não encontra o
/// nome exato procura um único nome igual sem diferenciar maiúsculas na pasta e usa esse (dois nomes que só diferem em
/// maiúsculas tornam a operação <see cref="VaultErrors.Conflict"/>).</para>
/// <para><b>Versões</b>: inteiros sequenciais por segredo. <see cref="ListSecretVersionsAsync"/> devolve de 1 até a atual (a API não
/// lista o histórico; versões apagadas pela retenção do Infisical retornam <see cref="VaultErrors.NotFound"/> na leitura). Só a atual
/// tem datas.</para>
/// <para><b>Tags</b> são gravadas como <c>secretMetadata</c> (chave até 255, valor até 1.020 caracteres). Não há tipo de
/// conteúdo, habilitar/desabilitar nem validade: pedir esses campos retorna <see cref="VaultErrors.InvalidInput"/>.</para>
/// <para>Com política de aprovação no ambiente, a escrita fica pendente no Infisical e a operação retorna
/// <see cref="VaultErrors.NotSupported"/> (a aplicação não deve assumir que o valor mudou).</para>
/// </remarks>
public sealed partial class InfisicalSecretStore : VaultHttpProviderBase, ISecretStore, IVaultHealthProbe, IDisposable
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "Infisical";

    /// <summary>Tamanho máximo de um valor: 1 MB.</summary>
    public const int MaxSecretValueBytes = 1024 * 1024;

    private const int MaxListedVersions = 100;
    private const string NameRule = "use de 1 a 255 caracteres: letras, números, hífen, sublinhado e ponto, começando por letra, número ou sublinhado.";

    private static readonly VaultProviderRules Rules = new(NamePattern(), NameRule)
    {
        VersionPattern = VersionPatternRegex(),
        MaxSecretValueBytes = MaxSecretValueBytes,
        MaxTags = 50,
        MaxTagKeyLength = 255,
        MaxTagValueLength = 1020,
        MaxBackupBytes = 1
    };

    private readonly InfisicalOptions _options;
    private readonly string _secretPath;
    private readonly VaultHttpClient _login;
    private readonly VaultTokenSource _tokens;
    private readonly VaultHttpClient _http;
    private readonly TimeProvider _time;

    /// <summary>Cria o store. As opções são validadas aqui (falha na inicialização, não na primeira requisição).</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public InfisicalSecretStore(InfisicalOptions options, ILogger<InfisicalSecretStore>? logger = null)
        : base(Provider, logger ?? (ILogger)NullLogger.Instance)
    {
        ArgumentNullException.ThrowIfNull(options);
        var (site, path) = options.Validate();
        _options = options;
        _secretPath = path;
        _time = options.TimeProvider ?? TimeProvider.System;

        var credential = options.Credential();
        _login = new VaultHttpClient(site, options.Http);
        _tokens = new VaultTokenSource(ct => LoginAsync(credential, ct), _time);
        _http = new VaultHttpClient(site, options.Http, _tokens);
    }

    [GeneratedRegex(@"^[0-9a-zA-Z_][0-9a-zA-Z._-]{0,254}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"^[1-9][0-9]{0,9}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VersionPatternRegex();

    // ---------- Leitura ----------

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            var secret = await FindAsync(name, version, withValue: true, ct).ConfigureAwait(false);
            if (secret.Error is not null)
                return secret.Error;
            if (secret.Value is null)
                return VaultErrors.NotFound();
            if (secret.Value.SecretValueHidden || secret.Value.SecretValue is null)
                return VaultErrors.AccessDenied();   // identidade sem permissão de ver valores
            return Result<VaultSecret>.Success(new VaultSecret(ToProperties(secret.Value), secret.Value.SecretValue));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.exists", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var secret = await FindAsync(name, null, withValue: false, ct).ConfigureAwait(false);
            return secret.Error is not null ? secret.Error : Result<bool>.Success(secret.Value is not null);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.list", null, null, isWrite: false, async ct =>
            (await ListAsync(ct).ConfigureAwait(false)).Select(ToProperties).ToList(), cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var secret = await FindAsync(name, null, withValue: false, ct).ConfigureAwait(false);
            if (secret.Error is not null)
                return secret.Error;
            if (secret.Value is null)
                return VaultErrors.NotFound();

            var current = ToProperties(secret.Value);
            var first = Math.Max(1, secret.Value.Version - MaxListedVersions + 1);
            var versions = new List<SecretProperties>();
            for (var v = first; v < secret.Value.Version; v++)
            {
                versions.Add(current with
                {
                    Version = v.ToString(CultureInfo.InvariantCulture),
                    CreatedOn = null,
                    UpdatedOn = null,
                    Tags = CopyTags(null)
                });
            }

            versions.Add(current);
            return Result<IReadOnlyList<SecretProperties>>.Success(versions);
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Lista a pasta configurada sem ler valores.</remarks>
    public async Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default)
    {
        var result = await ListSecretsAsync(cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? Result.Success() : result.ToFailure();
    }

    // ---------- Escrita ----------

    /// <inheritdoc />
    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SecretWriteOptions();
        var inputError = Rules.SetSecret(name, value, options, _time.GetUtcNow()) ?? Unsupported(options);

        return ExecuteAsync("secret.set", name, inputError, isWrite: true, async ct =>
        {
            var existing = await FindAsync(name, null, withValue: false, ct).ConfigureAwait(false);
            if (existing.Error is not null)
                return existing.Error;

            var body = Write(value, options.Tags);
            if (existing.Value is { } current)
                return await SendWriteAsync(HttpMethod.Patch, current.SecretKey, body, idempotent: true, ct).ConfigureAwait(false);

            var created = await SendWriteAsync(HttpMethod.Post, name, body, idempotent: false, ct).ConfigureAwait(false);
            if (created.IsSuccess || created.Error!.Code != VaultErrors.RejectedCode)
                return created;

            // Criado em paralelo por outra instância entre a busca e o POST (o Infisical responde 400): grava nova versão
            var again = await FindAsync(name, null, withValue: false, ct).ConfigureAwait(false);
            return again.Value is { } raced
                ? await SendWriteAsync(HttpMethod.Patch, raced.SecretKey, body, idempotent: true, ct).ConfigureAwait(false)
                : created;
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>Só <see cref="SecretPropertiesUpdate.Tags"/> é suportado, e só na versão atual (o Infisical cria uma nova versão).</remarks>
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateSecret(name, version, update, _time.GetUtcNow()) ??
            (update.Enabled is not null || update.ExpiresOn is not null || update.NotBefore is not null || update.ContentType is not null
                ? VaultErrors.InvalidInput("update", "O Infisical só permite alterar as tags (habilitado, validade e tipo de conteúdo não existem).")
                : null);

        return ExecuteAsync("secret.update", name, inputError, isWrite: true, async ct =>
        {
            var existing = await FindAsync(name, null, withValue: false, ct).ConfigureAwait(false);
            if (existing.Error is not null)
                return existing.Error;
            if (existing.Value is not { } current)
                return VaultErrors.NotFound();
            if (version is not null && version != current.Version.ToString(CultureInfo.InvariantCulture))
                return VaultErrors.InvalidInput("version", "O Infisical só altera a versão atual.");
            if (update.Tags is null)
                return Result<SecretProperties>.Success(ToProperties(current));

            return await SendWriteAsync(HttpMethod.Patch, current.SecretKey, Write(null, update.Tags), idempotent: true, ct).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>Exclui todas as versões. O Infisical não tem lixeira: a exclusão não é recuperável pela API.</remarks>
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var existing = await FindAsync(name, null, withValue: false, ct).ConfigureAwait(false);
            if (existing.Error is not null)
                return existing.Error;
            if (existing.Value is not { } current)
                return VaultErrors.NotFound();

            var result = await SendWriteAsync(HttpMethod.Delete, current.SecretKey, Write(null, null), idempotent: true, ct).ConfigureAwait(false);
            return result.IsSuccess
                ? Result<DeletedVaultItem>.Success(new DeletedVaultItem(current.SecretKey, _time.GetUtcNow(), ScheduledPurgeDate: null))
                : result.ToFailure<DeletedVaultItem>();
        }, cancellationToken);

    /// <inheritdoc />
    public void Dispose()
    {
        _http.Dispose();
        _login.Dispose();
        _tokens.Dispose();
    }

    // ---------- HTTP ----------

    private async Task<VaultToken> LoginAsync(VaultCredentialInput credential, CancellationToken cancellationToken)
    {
        string secret;
        try
        {
            secret = credential.Read();
        }
        catch (InvalidOperationException exception)
        {
            throw new VaultLoginException(exception.Message, exception);
        }

        if (_options.Authentication == InfisicalAuthentication.AccessToken)
            return new VaultToken(secret, ExpiresOn: null);   // token pronto: renovado só por quem o gerou

        var (path, bytes) = _options.Authentication == InfisicalAuthentication.Kubernetes
            ? ("api/v1/auth/kubernetes-auth/login", System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                new KubernetesAuthLogin { IdentityId = _options.IdentityId!, Jwt = secret, OrganizationSlug = _options.OrganizationSlug },
                InfisicalJsonContext.Default.KubernetesAuthLogin))
            : ("api/v1/auth/universal-auth/login", System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                new UniversalAuthLogin { ClientId = _options.ClientId!, ClientSecret = secret },
                InfisicalJsonContext.Default.UniversalAuthLogin));
        try
        {
            using var response = await _login.SendAsync(() => new HttpRequestMessage(HttpMethod.Post, path)
            {
                Content = new ByteArrayContent(bytes) { Headers = { ContentType = new("application/json") } }
            }, idempotent: true, cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                throw new VaultLoginException($"o Infisical recusou o login ({(int)response.StatusCode})");

            var login = await _login.ReadJsonAsync(response, InfisicalJsonContext.Default.InfisicalLoginResponse, cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(login.AccessToken))
                throw new VaultLoginException("o Infisical não devolveu token");
            DateTimeOffset? expires = login.ExpiresIn > 0 ? _time.GetUtcNow().AddSeconds(login.ExpiresIn) : null;
            return new VaultToken(login.AccessToken, expires);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>Busca pelo nome exato e, sem ele, por um único nome igual sem diferenciar maiúsculas.</summary>
    private async Task<(InfisicalSecret? Value, Error? Error)> FindAsync(string name, string? version, bool withValue, CancellationToken ct)
    {
        var exact = await GetAsync(name, version, withValue, ct).ConfigureAwait(false);
        if (exact is not null)
            return (exact, null);

        var matches = (await ListAsync(ct).ConfigureAwait(false))
            .Where(s => !string.Equals(s.SecretKey, name, StringComparison.Ordinal) &&
                        string.Equals(s.SecretKey, name, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return matches.Count switch
        {
            0 => (null, null),
            1 => (await GetAsync(matches[0].SecretKey, version, withValue, ct).ConfigureAwait(false), null),
            _ => (null, VaultErrors.Conflict())
        };
    }

    private async Task<InfisicalSecret?> GetAsync(string key, string? version, bool withValue, CancellationToken ct)
    {
        var query = Query(("projectId", _options.ProjectId), ("environment", _options.Environment), ("secretPath", _secretPath),
            ("version", version), ("type", "shared"), ("viewSecretValue", Bool(withValue)),
            ("expandSecretReferences", Bool(_options.ExpandSecretReferences)), ("includeImports", Bool(_options.IncludeImports)));

        using var response = await _http.SendAsync(() => new HttpRequestMessage(HttpMethod.Get, $"api/v4/secrets/{VaultEndpoint.Segment(key)}?{query}"),
            idempotent: true, ct).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
            return null;
        VaultHttpClient.EnsureSuccess(response);

        var envelope = await _http.ReadJsonAsync(response, InfisicalJsonContext.Default.InfisicalSecretEnvelope, ct).ConfigureAwait(false);
        return envelope.Secret ?? throw new System.Text.Json.JsonException("Resposta sem secret.");
    }

    private async Task<List<InfisicalSecret>> ListAsync(CancellationToken ct)
    {
        var query = Query(("projectId", _options.ProjectId), ("environment", _options.Environment), ("secretPath", _secretPath),
            ("viewSecretValue", "false"), ("expandSecretReferences", "false"), ("recursive", "false"),
            ("includeImports", Bool(_options.IncludeImports)));

        using var response = await _http.SendAsync(() => new HttpRequestMessage(HttpMethod.Get, $"api/v4/secrets?{query}"), idempotent: true, ct)
            .ConfigureAwait(false);
        VaultHttpClient.EnsureSuccess(response);
        var list = await _http.ReadJsonAsync(response, InfisicalJsonContext.Default.InfisicalSecretList, ct).ConfigureAwait(false);
        return list.Secrets;
    }

    private async Task<Result<SecretProperties>> SendWriteAsync(HttpMethod method, string key, InfisicalWrite body, bool idempotent, CancellationToken ct)
    {
        var json = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(body, InfisicalJsonContext.Default.InfisicalWrite);
        try
        {
            using var response = await _http.SendAsync(() => new HttpRequestMessage(method, $"api/v4/secrets/{VaultEndpoint.Segment(key)}")
            {
                Content = new ByteArrayContent(json) { Headers = { ContentType = new("application/json") } }
            }, idempotent, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return MapStatus(response.StatusCode).Error;

            var envelope = await _http.ReadJsonAsync(response, InfisicalJsonContext.Default.InfisicalSecretEnvelope, ct).ConfigureAwait(false);
            if (envelope.Secret is null)
                return VaultErrors.NotSupported();   // política de aprovação: escrita pendente
            envelope.Secret.SecretValue = null;
            return Result<SecretProperties>.Success(ToProperties(envelope.Secret));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(json);
        }
    }

    private InfisicalWrite Write(string? value, IReadOnlyDictionary<string, string>? tags) => new()
    {
        ProjectId = _options.ProjectId!,
        Environment = _options.Environment!,
        SecretPath = _secretPath,
        SecretValue = value,
        SecretMetadata = tags?.Select(t => new InfisicalMetadata { Key = t.Key, Value = t.Value }).ToList()
    };

    private static Error? Unsupported(SecretWriteOptions options) =>
        options.ContentType is not null || !options.Enabled || options.ExpiresOn is not null || options.NotBefore is not null
            ? VaultErrors.InvalidInput("options", "O Infisical não tem tipo de conteúdo, habilitar/desabilitar nem validade: informe só valor e tags.")
            : null;

    private SecretProperties ToProperties(InfisicalSecret secret) => new()
    {
        Name = secret.SecretKey,
        Version = secret.Version.ToString(CultureInfo.InvariantCulture),
        Id = $"{_options.Environment}:{secret.SecretPath ?? _secretPath}/{secret.SecretKey}",
        Enabled = true,
        CreatedOn = secret.CreatedAt,
        UpdatedOn = secret.UpdatedAt,
        // Metadados criptografados não viram tags; entradas malformadas (chave nula ou repetida) não derrubam a leitura
        Tags = CopyTags(secret.SecretMetadata?
            .Where(m => m is not null && m.IsEncrypted != true)
            .Select(m => new KeyValuePair<string, string>(m.Key, m.Value ?? string.Empty)))
    };

    private static string Bool(bool value) => value ? "true" : "false";

    private static string Query(params (string Key, string? Value)[] values)
    {
        var builder = new StringBuilder();
        foreach (var (key, value) in values)
        {
            if (value is null)
                continue;
            if (builder.Length > 0)
                builder.Append('&');
            builder.Append(key).Append('=').Append(Uri.EscapeDataString(value));
        }

        return builder.ToString();
    }
}

