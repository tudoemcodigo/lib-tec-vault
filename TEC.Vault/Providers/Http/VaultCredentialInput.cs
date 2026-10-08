using TEC.Core.IO;

namespace TEC.Vault.Providers.Http;

/// <summary>
/// Credencial de login lida de arquivo ou de variável de ambiente, nunca de texto na configuração (uso pelos provedores).
/// Exemplos: token da service account do Kubernetes, JWT federado, secret_id do AppRole, client secret.
/// </summary>
/// <remarks>
/// Lida a cada login (não no início): tokens projetados pelo Kubernetes e credenciais rotacionadas são renovados no arquivo
/// sem reiniciar a aplicação.
/// </remarks>
public sealed class VaultCredentialInput
{
    /// <summary>Tamanho máximo do arquivo de credencial: 64 KB.</summary>
    public const int MaxFileBytes = 64 * 1024;

    private readonly string? _file;
    private readonly string? _variable;
    private readonly Func<string>? _value;

    private VaultCredentialInput(string? file, string? variable, Func<string>? value, string description)
    {
        _file = file;
        _variable = variable;
        _value = value;
        Description = description;
    }

    /// <summary>Descrição para mensagens (ex.: "HashiCorpVaultOptions.Auth.SecretIdFile").</summary>
    public string Description { get; }

    /// <summary>Credencial em arquivo.</summary>
    public static VaultCredentialInput FromFile(string path, string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        return new VaultCredentialInput(path, null, null, description);
    }

    /// <summary>Credencial em variável de ambiente.</summary>
    public static VaultCredentialInput FromVariable(string name, string description)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return new VaultCredentialInput(null, name, null, description);
    }

    /// <summary>Credencial obtida por código (ex.: de outro cofre). A função é chamada a cada login.</summary>
    public static VaultCredentialInput FromValue(Func<string> value, string description)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new VaultCredentialInput(null, null, value, description);
    }

    /// <summary>
    /// Cria a partir das opções "arquivo" e "variável": exatamente uma deve estar preenchida (ou nenhuma, se
    /// <paramref name="defaultFile"/> for informado).
    /// </summary>
    /// <exception cref="InvalidOperationException">Nenhuma ou as duas informadas.</exception>
    public static VaultCredentialInput Create(string? file, string? variable, string fileOption, string variableOption, string? defaultFile = null)
    {
        var hasFile = !string.IsNullOrWhiteSpace(file);
        var hasVariable = !string.IsNullOrWhiteSpace(variable);
        if (hasFile && hasVariable)
            throw new InvalidOperationException($"Informe só um de {fileOption} e {variableOption}.");
        if (hasFile)
            return FromFile(file!, fileOption);
        if (hasVariable)
            return FromVariable(variable!, variableOption);
        if (defaultFile is not null)
            return FromFile(defaultFile, fileOption);
        throw new InvalidOperationException($"Informe {fileOption} ou {variableOption}.");
    }

    /// <summary>Lê o valor atual (sem espaços e quebras de linha nas pontas).</summary>
    /// <exception cref="InvalidOperationException">Arquivo ausente, grande demais ou vazio; variável ausente ou vazia. A mensagem não traz o valor.</exception>
    public string Read()
    {
        string? value;
        if (_value is not null)
            value = _value();
        else if (_variable is not null)
            value = Environment.GetEnvironmentVariable(_variable);
        else
            value = ReadFile(_file!);

        value = value?.Trim();
        return string.IsNullOrEmpty(value)
            ? throw new InvalidOperationException($"Credencial de login vazia ou ausente ({Description}).")
            : value;
    }

    private string ReadFile(string path)
    {
        try
        {
            // Leitura limitada mesmo sem tamanho conhecido (pipe, arquivo especial), UTF-8 estrito, sem BOM, buffers zerados
            return BoundedFileReader.TryReadUtf8(path, MaxFileBytes, out string? content) ? content : throw TooLarge();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            throw new InvalidOperationException($"Não foi possível ler o arquivo de credencial ({Description}): {exception.GetType().Name}.", exception);
        }
    }

    private InvalidOperationException TooLarge() =>
        new($"Arquivo de credencial acima de {MaxFileBytes / 1024} KB ({Description}).");
}
