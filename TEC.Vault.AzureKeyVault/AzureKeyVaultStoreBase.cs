using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Providers;

using TEC.Vault.AzureKeyVault.Internal;

namespace TEC.Vault.AzureKeyVault;

/// <summary>
/// Base dos stores do Azure Key Vault: regras de entrada do Key Vault e conversão de exceções do SDK.
/// Não pode ser derivada fora deste pacote.
/// </summary>
public abstract partial class AzureKeyVaultStoreBase : VaultProviderBase
{
    /// <summary>Nome do provedor (<see cref="VaultProviderBase.ProviderName"/>).</summary>
    public const string Provider = "AzureKeyVault";

    /// <summary>Limite de valor de segredo do Key Vault: 25 KB.</summary>
    internal const int MaxSecretValueBytes = 25 * 1024;

    internal const int MaxTags = 15;
    internal const int MaxTagKeyLength = 256;
    internal const int MaxTagValueLength = 256;
    internal const int MaxBackupBytes = 10 * 1024 * 1024;

    internal const string NameRule = "use de 1 a 127 caracteres: letras, números e hífen.";

    private protected AzureKeyVaultStoreBase(AzureKeyVaultClients clients, ILogger? logger)
        : base(Provider, logger ?? NullLogger.Instance, clients?.CircuitBreaker)
    {
        ArgumentNullException.ThrowIfNull(clients);
        Clients = clients;
    }

    private protected AzureKeyVaultClients Clients { get; }

    // \z e não $: $ aceitaria uma quebra de linha no final do nome (que iria para a URL da requisição)
    [GeneratedRegex(@"^[0-9a-zA-Z-]{1,127}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    internal static partial Regex NamePattern();

    /// <summary>Regras de entrada do Key Vault: os limites acima + as validações comuns a todos os provedores.</summary>
    internal static VaultProviderRules Rules { get; } = new(NamePattern(), NameRule)
    {
        MaxSecretValueBytes = MaxSecretValueBytes,
        MaxTags = MaxTags,
        MaxTagKeyLength = MaxTagKeyLength,
        MaxTagValueLength = MaxTagValueLength,
        MaxBackupBytes = MaxBackupBytes
    };

    /// <summary>Cancelamento com o limite de <see cref="AzureKeyVaultOptions.OperationTimeout"/> para operações longas.</summary>
    private protected CancellationTokenSource WithOperationTimeout(CancellationToken cancellationToken)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(Clients.OperationTimeout);
        return cts;
    }

    private protected static void ReplaceTags(IDictionary<string, string> target, IReadOnlyDictionary<string, string>? tags)
    {
        if (tags is null)
            return;
        target.Clear();
        foreach (var (key, value) in tags)
            target[key] = value;
    }

    private protected static DeletedVaultItem ToDeleted(string name, DateTimeOffset? deletedOn, DateTimeOffset? purgeDate) =>
        new(name, deletedOn, purgeDate);

    /// <summary>
    /// Valor de <see cref="VaultItemProperties.ManagedBy"/> para itens que o Key Vault cria e gerencia junto com um certificado
    /// (o segredo com o conteúdo e a chave): <c>managed = true</c> no SDK.
    /// </summary>
    internal const string ManagedByCertificate = "certificate";

    private protected static string? ToManagedBy(bool managed) => managed ? ManagedByCertificate : null;

    /// <summary>
    /// 403 de item desabilitado: <c>error.code</c> "Forbidden" com <c>innererror.code</c> "SecretDisabled"/"KeyDisabled"/
    /// "CertificateDisabled" (mesma classificação de <see cref="Map"/>, que nunca usa o texto da mensagem).
    /// </summary>
    private protected static bool IsDisabledFailure(RequestFailedException exception) =>
        exception.Status == 403 && Map(exception) is { } failure && failure.Error.Code == VaultErrors.DisabledCode;

    /// <inheritdoc />
    protected override VaultFailure? MapException(Exception exception) => Map(exception);

    internal static VaultFailure? Map(Exception exception) => exception switch
    {
        AuthenticationFailedException or CredentialUnavailableException =>
            new VaultFailure(VaultErrors.AuthenticationFailed(), exception.GetType().Name),
        RequestFailedException failed => MapRequestFailed(failed),
        OperationCanceledException or TimeoutException => new VaultFailure(VaultErrors.Unavailable(), "timeout"),
        NotSupportedException => new VaultFailure(VaultErrors.NotSupported(), "tipo não suportado"),
        // Falha de transporte que o SDK não converte em RequestFailedException (ex.: conexão cortada ao ler a resposta);
        // com MaxRetries = 0 ela chega aqui sozinha, sem AggregateException
        IOException or HttpRequestException or SocketException => new VaultFailure(VaultErrors.Unavailable(), $"rede ({exception.GetType().Name})"),
        // Política de retry do Azure.Core: quando todas as tentativas falham por exceção (rede, DNS, timeout), ela lança
        // AggregateException ("Retry failed after N tries") com uma exceção por tentativa. Vale a última; se ela não for
        // conhecida, tentativas esgotadas são, de todo modo, cofre indisponível (e não falha não classificada)
        AggregateException { InnerExceptions.Count: > 0 } aggregate =>
            Map(aggregate.InnerExceptions[^1])
            ?? new VaultFailure(VaultErrors.Unavailable(), $"tentativas esgotadas ({aggregate.InnerExceptions[^1].GetType().Name})"),
        _ => null
    };

    private static VaultFailure MapRequestFailed(RequestFailedException exception)
    {
        // Só status e códigos de erro vão para o log: a mensagem completa traz corpo e cabeçalhos da resposta
        string? innerCode = exception.Status == 403 ? InnerErrorCode(exception) : null;
        string code = SafeCode(exception.ErrorCode) ?? "-";
        string detail = innerCode is null ? $"{exception.Status} {code}" : $"{exception.Status} {code} {innerCode}";

        var error = exception.Status switch
        {
            400 => VaultErrors.Rejected(),
            401 => VaultErrors.AuthenticationFailed(),
            403 when IsDisabled(exception.ErrorCode) || IsDisabled(innerCode) => VaultErrors.Disabled(),
            403 => VaultErrors.AccessDenied(),
            404 => VaultErrors.NotFound(),
            409 => VaultErrors.Conflict(),
            429 => VaultErrors.Throttled(),
            0 or >= 500 => VaultErrors.Unavailable(),
            _ => VaultErrors.ProviderFailure()
        };
        return new VaultFailure(error, detail);
    }

    /// <summary>
    /// Códigos estruturados (<c>error.innererror.code</c>) que o Key Vault devolve, com HTTP 403, para itens desabilitados.
    /// A classificação nunca usa o texto da mensagem: um 403 de firewall ("Public network access is disabled...",
    /// <c>ForbiddenByConnection</c>/<c>ForbiddenByFirewall</c>) é falha de acesso/infraestrutura, não item desabilitado.
    /// </summary>
    internal static readonly string[] DisabledCodes = ["SecretDisabled", "KeyDisabled", "CertificateDisabled"];

    private static bool IsDisabled(string? code) =>
        code is not null && DisabledCodes.Contains(code, StringComparer.OrdinalIgnoreCase);

    private const int MaxErrorBodyBytes = 64 * 1024;
    private const int MaxCodeLength = 64;

    /// <summary>Marcador que vai para o log no lugar de um código de erro fora do formato esperado.</summary>
    internal const string InvalidCodeMarker = "codigo-invalido";

    /// <summary>
    /// Código de erro do provedor pronto para o log: o próprio código se for um identificador ASCII curto (letras, dígitos,
    /// <c>_</c>, <c>-</c>, <c>.</c>; até 64 caracteres); <see cref="InvalidCodeMarker"/> se não for (o corpo da resposta é
    /// controlado por quem responde: nada dele vai para o log sem essa conferência); <c>null</c> se ausente.
    /// </summary>
    internal static string? SafeCode(string? code)
    {
        if (string.IsNullOrEmpty(code))
            return null;
        return code.Length <= MaxCodeLength && code.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.')
            ? code
            : InvalidCodeMarker;
    }

    /// <summary>
    /// Lê <c>error.innererror.code</c> do corpo JSON da resposta (o SDK só expõe <c>error.code</c>, que é "Forbidden").
    /// Retorna <c>null</c> se ausente ou malformado, e <see cref="InvalidCodeMarker"/> se estiver fora do formato de um código
    /// (<see cref="SafeCode"/>: nada do corpo vai além disso para o log).
    /// </summary>
    internal static string? InnerErrorCode(RequestFailedException exception)
    {
        try
        {
            var content = exception.GetRawResponse()?.Content;
            if (content is null || content.ToMemory().Length is 0 or > MaxErrorBodyBytes)
                return null;

            using var json = JsonDocument.Parse(content.ToMemory());
            var element = json.RootElement;
            string? code = null;

            // A cadeia de innererror pode ter mais de um nível; o código mais interno é o mais específico
            if (element.ValueKind == JsonValueKind.Object && element.TryGetProperty("error", out var error))
            {
                var current = error;
                for (int depth = 0; depth < 5 && current.ValueKind == JsonValueKind.Object
                    && current.TryGetProperty("innererror", out var inner) && inner.ValueKind == JsonValueKind.Object; depth++)
                {
                    if (inner.TryGetProperty("code", out var innerCode) && innerCode.ValueKind == JsonValueKind.String)
                        code = innerCode.GetString();
                    current = inner;
                }
            }

            return SafeCode(code);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
