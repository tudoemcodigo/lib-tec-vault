using System.Text;
using System.Text.RegularExpressions;
using TEC.Vault.Common;
using TEC.Core.Common.Results;

namespace TEC.Vault.Providers;

/// <summary>
/// Validações de entrada reutilizáveis pelos provedores. Retornam o primeiro <see cref="Error"/> encontrado ou <c>null</c>.
/// </summary>
/// <remarks>
/// Validar antes de chamar o provedor evita requisições inúteis e fecha a porta para injeção em caminhos/URLs
/// (ex.: nome "../outro-segredo" ou com "?"), mesmo que o SDK já escape os valores. As mensagens nunca repetem o valor recebido.
/// </remarks>
public static partial class VaultInputRules
{
    /// <summary>Tamanho máximo do tipo de conteúdo de um segredo (<c>ContentType</c>).</summary>
    public const int MaxContentTypeLength = 255;

    /// <summary>
    /// Versão com 32 caracteres hexadecimais (formato do Azure Key Vault, também usado pelo provedor em memória).
    /// Termina em <c>\z</c>: <c>$</c> aceitaria uma quebra de linha no final.
    /// </summary>
    [GeneratedRegex(@"^[0-9a-fA-F]{32}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    public static partial Regex HexVersionPattern();

    /// <summary>Valida um nome obrigatório contra o padrão do provedor.</summary>
    /// <remarks>Padrão que estoura o tempo limite (entrada hostil contra regex de terceiros) também recusa o nome, sem exceção.</remarks>
    public static Error? Name(string? name, Regex pattern, string rule, string field = "name")
    {
        ArgumentNullException.ThrowIfNull(pattern);
        if (string.IsNullOrEmpty(name))
            return VaultErrors.InvalidInput(field, "O nome é obrigatório.");
        return Matches(pattern, name) ? null : VaultErrors.InvalidInput(field, $"Nome inválido: {rule}");
    }

    /// <summary>Valida uma versão opcional contra o padrão do provedor.</summary>
    public static Error? Version(string? version, Regex pattern, string field = "version")
    {
        ArgumentNullException.ThrowIfNull(pattern);
        return version is null || Matches(pattern, version) ? null : VaultErrors.InvalidInput(field, "Versão em formato inválido.");
    }

    // Tempo limite do regex (padrão de um provedor de terceiros com retrocesso) = entrada recusada: a validação nunca lança
    private static bool Matches(Regex pattern, string value)
    {
        try
        {
            return pattern.IsMatch(value);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>Valida uma versão obrigatória contra o padrão do provedor.</summary>
    public static Error? RequiredVersion(string? version, Regex pattern, string field = "version") =>
        string.IsNullOrEmpty(version) ? VaultErrors.InvalidInput(field, "A versão é obrigatória.") : Version(version, pattern, field);

    /// <summary>Valida um valor de segredo: não vazio e até <paramref name="maxBytes"/> bytes em UTF-8.</summary>
    public static Error? SecretValue(string? value, int maxBytes, string field = "value")
    {
        if (string.IsNullOrEmpty(value))
            return VaultErrors.InvalidInput(field, "O valor do segredo é obrigatório.");
        return Encoding.UTF8.GetByteCount(value) <= maxBytes
            ? null
            : VaultErrors.InvalidInput(field, $"O valor do segredo excede o limite de {maxBytes} bytes.");
    }

    /// <summary>Valida um conteúdo binário obrigatório e seu tamanho máximo.</summary>
    public static Error? Bytes(byte[]? value, int maxBytes, string field)
    {
        if (value is null || value.Length == 0)
            return VaultErrors.InvalidInput(field, "O conteúdo é obrigatório.");
        return value.Length <= maxBytes ? null : VaultErrors.InvalidInput(field, $"O conteúdo excede o limite de {maxBytes} bytes.");
    }

    /// <summary>Valida um texto opcional: tamanho máximo e ausência de caracteres de controle.</summary>
    public static Error? OptionalText(string? value, int maxLength, string field)
    {
        if (value is null)
            return null;
        if (value.Length > maxLength)
            return VaultErrors.InvalidInput(field, $"O texto excede {maxLength} caracteres.");
        return value.Any(char.IsControl) ? VaultErrors.InvalidInput(field, "O texto contém caracteres de controle.") : null;
    }

    /// <summary>Valida as tags: quantidade, tamanho de chave/valor e ausência de caracteres de controle.</summary>
    public static Error? Tags(IReadOnlyDictionary<string, string>? tags, int maxCount, int maxKeyLength, int maxValueLength, string field = "tags")
    {
        if (tags is null)
            return null;
        if (tags.Count > maxCount)
            return VaultErrors.InvalidInput(field, $"Máximo de {maxCount} tags.");

        foreach (var (key, value) in tags)
        {
            if (string.IsNullOrWhiteSpace(key) || key.Length > maxKeyLength || key.Any(char.IsControl))
                return VaultErrors.InvalidInput(field, $"Chave de tag inválida (obrigatória, até {maxKeyLength} caracteres, sem caracteres de controle).");
            if (value is null || value.Length > maxValueLength || value.Any(char.IsControl))
                return VaultErrors.InvalidInput(field, $"Valor de tag inválido (até {maxValueLength} caracteres, sem caracteres de controle).");
        }

        return null;
    }

    /// <summary>
    /// Valida o período de validade: início antes do fim e, em gravações, expiração no futuro
    /// (gravar algo já expirado é quase sempre engano e gera item inutilizável).
    /// </summary>
    public static Error? Validity(DateTimeOffset? notBefore, DateTimeOffset? expiresOn, DateTimeOffset now, bool requireFutureExpiration)
    {
        if (notBefore is not null && expiresOn is not null && notBefore >= expiresOn)
            return VaultErrors.InvalidInput("notBefore", "O início da validade deve ser anterior à expiração.");
        if (requireFutureExpiration && expiresOn is not null && expiresOn <= now)
            return VaultErrors.InvalidInput("expiresOn", "A expiração deve estar no futuro.");
        return null;
    }

    /// <summary>Retorna o primeiro erro não nulo.</summary>
    public static Error? First(params ReadOnlySpan<Error?> errors)
    {
        foreach (var error in errors)
        {
            if (error is not null)
                return error;
        }

        return null;
    }
}
