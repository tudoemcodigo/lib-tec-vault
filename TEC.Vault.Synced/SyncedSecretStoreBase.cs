using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Providers;
using TEC.Vault.Secrets;
using TEC.Vault.Synced.Internal;
using TEC.Core.Common.Results;

namespace TEC.Vault.Synced;

/// <summary>
/// Base dos leitores de segredos sincronizados por um agente externo (diretório, variáveis de ambiente, arquivo). Só leitura:
/// quem grava é o agente (External Secrets, Vault Agent, CSI driver, <c>infisical run</c>, <c>bws run</c>...).
/// Não pode ser derivada fora deste pacote.
/// </summary>
/// <remarks>
/// <para>O valor é lido da fonte a cada chamada: a rotação feita pelo agente vale na hora. Para evitar E/S a cada leitura,
/// ative o cache do núcleo (<c>EnableSecretCache</c> ou <c>Vault:Cache:Duration</c>).</para>
/// <para><see cref="VaultItemProperties.Version"/> é um HMAC-SHA256 do valor com chave aleatória por instância (32 hexadecimais):
/// muda quando o valor muda (o que permite a recarga incremental da fonte de <c>IConfiguration</c>), mas não permite verificar
/// um palpite do valor, e não se repete entre processos. Só a versão atual existe: outra versão retorna
/// <see cref="VaultErrors.NotFound"/>.</para>
/// <para>Não há habilitar/desabilitar, validade, tags nem tipo de conteúdo: os itens são sempre habilitados e sem metadados.</para>
/// </remarks>
public abstract partial class SyncedSecretStoreBase : VaultProviderBase, ISecretReader, IVaultHealthProbe
{
    /// <summary>Tamanho máximo de um valor (padrão dos arquivos): 64 KB.</summary>
    public const int DefaultMaxValueBytes = 64 * 1024;

    /// <summary>Limite superior configurável do tamanho de um valor: 1 MB.</summary>
    public const int MaxValueBytesLimit = 1024 * 1024;

    internal const string NameRule = "use de 1 a 255 caracteres: letras, números, hífen, sublinhado e ponto, começando por letra ou número.";

    private readonly byte[] _versionKey = RandomNumberGenerator.GetBytes(32);

    private protected SyncedSecretStoreBase(string providerName, int maxValueBytes, ILogger? logger)
        : base(providerName, logger ?? NullLogger.Instance)
    {
        Rules = new VaultProviderRules(NamePattern(), NameRule)
        {
            MaxSecretValueBytes = maxValueBytes,
            MaxTags = 0,
            MaxTagKeyLength = 1,
            MaxTagValueLength = 1,
            MaxBackupBytes = 1
        };
    }

    // \z e não $: $ aceitaria uma quebra de linha no final do nome. Sem barra: o nome nunca vira caminho
    [GeneratedRegex(@"^[0-9a-zA-Z][0-9a-zA-Z._-]{0,254}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    /// <summary>Indica se o nome é aceito pelo provedor (os itens da fonte com nome fora da regra são ignorados).</summary>
    internal static bool IsValidName(string name) => NamePattern().IsMatch(name);

    private protected VaultProviderRules Rules { get; }

    /// <summary>Itens atuais da fonte (nome, valor e data de atualização), sem duplicados por nome (sem diferenciar maiúsculas).</summary>
    private protected abstract IReadOnlyList<SyncedEntry> ReadAll(CancellationToken cancellationToken);

    /// <summary>Um item pelo nome (sem diferenciar maiúsculas), ou <c>null</c>. Padrão: procura em <see cref="ReadAll"/>.</summary>
    private protected virtual SyncedEntry? ReadOne(string name, CancellationToken cancellationToken) =>
        ReadAll(cancellationToken).FirstOrDefault(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Descrição da origem do item para <see cref="VaultItemProperties.Id"/> (sem valores).</summary>
    private protected abstract string? DescribeSource(SyncedEntry entry);

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultSecret>("secret.get", name, Rules.Item(name, version), isWrite: false, ct =>
        {
            var entry = ReadOne(name, ct);
            if (entry is null)
                return Task.FromResult<Result<VaultSecret>>(VaultErrors.NotFound());

            var properties = Properties(entry);
            if (version is not null && !string.Equals(version, properties.Version, StringComparison.OrdinalIgnoreCase))
                return Task.FromResult<Result<VaultSecret>>(VaultErrors.NotFound());

            return Task.FromResult<Result<VaultSecret>>(new VaultSecret(properties, entry.Value));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<bool>("secret.exists", name, Rules.Name(name), isWrite: false,
            ct => Task.FromResult<Result<bool>>(ReadOne(name, ct) is not null), cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.list", null, null, isWrite: false,
            ct => Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(ReadAll(ct).Select(Properties).ToList()), cancellationToken);

    /// <inheritdoc />
    /// <remarks>Só existe a versão atual: a lista tem um item.</remarks>
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.versions", name, Rules.Name(name), isWrite: false, ct =>
        {
            var entry = ReadOne(name, ct);
            return Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(entry is null
                ? VaultErrors.NotFound()
                : new[] { Properties(entry) });
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Lista a fonte: falha se ela não existir ou não puder ser lida.</remarks>
    public async Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default)
    {
        var result = await ListSecretsAsync(cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? Result.Success() : result.ToFailure();
    }

    /// <inheritdoc />
    protected override VaultFailure? MapException(Exception exception) => exception switch
    {
        SyncedFormatException format => new VaultFailure(VaultErrors.ProviderFailure(), format.Message),
        DirectoryNotFoundException or FileNotFoundException => new VaultFailure(VaultErrors.Unavailable(), "fonte de segredos ausente"),
        UnauthorizedAccessException => new VaultFailure(VaultErrors.AccessDenied(), "sem permissão de leitura na fonte"),
        IOException io => new VaultFailure(VaultErrors.Unavailable(), "E/S: " + io.GetType().Name),
        _ => null
    };

    private SecretProperties Properties(SyncedEntry entry) => new()
    {
        Name = entry.Name,
        Version = VersionOf(entry.Value),
        Id = DescribeSource(entry),
        Enabled = true,
        UpdatedOn = entry.UpdatedOn
    };

    private string VersionOf(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            return Convert.ToHexString(HMACSHA256.HashData(_versionKey, bytes).AsSpan(0, 16)).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
