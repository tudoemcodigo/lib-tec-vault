using System.Diagnostics;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.AwsSecretsManager.Internal;

/// <summary>
/// Credencial da AWS (chave de acesso, segredo e token de sessão). <see cref="ToString"/> e o depurador não mostram o segredo
/// nem o token.
/// </summary>
/// <remarks>
/// Guardada em <see cref="VaultTokenSource"/> (cache, renovação antes de expirar, login único em concorrência, intervalo de falha)
/// como um texto opaco (<see cref="Encode"/>), que nunca sai do processo: só a assinatura usa as partes.
/// </remarks>
[DebuggerDisplay("{ToString(),nq}")]
internal sealed class AwsCredentials
{
    private const char Separator = '\n';
    private const int MaxSessionTokenLength = 64 * 1024;

    private AwsCredentials(string accessKeyId, string secretAccessKey, string? sessionToken)
    {
        AccessKeyId = accessKeyId;
        SecretAccessKey = secretAccessKey;
        SessionToken = sessionToken;
    }

    public string AccessKeyId { get; }

    public string SecretAccessKey { get; }

    public string? SessionToken { get; }

    /// <summary>Confere o formato (nada vai para cabeçalho sem ser conferido). A mensagem nunca traz os valores.</summary>
    /// <exception cref="VaultLoginException">Parte ausente ou fora do formato.</exception>
    internal static AwsCredentials Create(string? accessKeyId, string? secretAccessKey, string? sessionToken, string source)
    {
        accessKeyId = accessKeyId?.Trim();
        secretAccessKey = secretAccessKey?.Trim();
        sessionToken = string.IsNullOrWhiteSpace(sessionToken) ? null : sessionToken.Trim();

        // Chave de acesso: 16 a 128 letras e dígitos (vai no cabeçalho Authorization)
        if (string.IsNullOrEmpty(accessKeyId) || accessKeyId.Length is < 16 or > 128 || !accessKeyId.All(char.IsAsciiLetterOrDigit))
            throw new VaultLoginException($"credencial da AWS sem chave de acesso válida ({source})");
        if (string.IsNullOrEmpty(secretAccessKey) || secretAccessKey.Length > 1024 || secretAccessKey.Contains(Separator, StringComparison.Ordinal))
            throw new VaultLoginException($"credencial da AWS sem segredo de acesso válido ({source})");
        // Token de sessão: ASCII visível (vai no cabeçalho x-amz-security-token; sem quebra de linha)
        if (sessionToken is not null && (sessionToken.Length > MaxSessionTokenLength || !sessionToken.All(c => c is > ' ' and <= '~')))
            throw new VaultLoginException($"credencial da AWS com token de sessão fora do formato ({source})");

        return new AwsCredentials(accessKeyId, secretAccessKey, sessionToken);
    }

    /// <summary>Texto opaco guardado pela <see cref="VaultTokenSource"/>.</summary>
    internal string Encode() => string.Join(Separator, AccessKeyId, SecretAccessKey, SessionToken ?? string.Empty);

    /// <summary>Volta do texto de <see cref="Encode"/>.</summary>
    internal static AwsCredentials Decode(string token)
    {
        var parts = token.Split(Separator);
        if (parts.Length != 3)
            throw new VaultLoginException("credencial da AWS em cache fora do formato");
        return new AwsCredentials(parts[0], parts[1], parts[2].Length == 0 ? null : parts[2]);
    }

    /// <inheritdoc />
    public override string ToString() =>
        $"AwsCredentials {{ AccessKeyId = {AccessKeyId}, SecretAccessKey = ***, SessionToken = {(SessionToken is null ? "-" : "***")} }}";
}
