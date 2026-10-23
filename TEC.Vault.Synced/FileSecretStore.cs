using Microsoft.Extensions.Logging;
using TEC.Vault.Synced.Internal;

namespace TEC.Vault.Synced;

/// <summary>Formato do arquivo do provedor <c>SecretsFile</c>.</summary>
public enum SecretsFileFormat
{
    /// <summary>Pela extensão: <c>.json</c> → <see cref="Json"/>; <c>.env</c> → <see cref="DotEnv"/>; outra extensão é erro.</summary>
    Auto = 0,

    /// <summary>Objeto JSON; objetos aninhados viram nomes com <c>--</c>.</summary>
    Json = 1,

    /// <summary>Linhas <c>CHAVE=valor</c> (formato .env).</summary>
    DotEnv = 2
}

/// <summary>Configuração do provedor <c>SecretsFile</c>.</summary>
public sealed class SecretsFileOptions
{
    /// <summary>Caminho do arquivo (ex.: <c>/vault/secrets/app.json</c>, gerado por um template do Vault Agent). Obrigatório.</summary>
    public string? Path { get; set; }

    /// <summary>Formato. Padrão: <see cref="SecretsFileFormat.Auto"/> (pela extensão).</summary>
    public SecretsFileFormat Format { get; set; }

    /// <summary>Tamanho máximo do arquivo (1 byte a 16 MB). Padrão: 1 MB.</summary>
    public int MaxFileBytes { get; set; } = 1024 * 1024;

    /// <summary>Quantidade máxima de segredos no arquivo (1 a 10.000). Padrão: 1.000.</summary>
    public int MaxItems { get; set; } = 1000;

    internal (string Path, SecretsFileFormat Format) Validate()
    {
        if (string.IsNullOrWhiteSpace(Path))
            throw new InvalidOperationException("SecretsFileOptions.Path é obrigatório.");
        if (MaxFileBytes is < 1 or > 16 * 1024 * 1024)
            throw new InvalidOperationException("SecretsFileOptions.MaxFileBytes deve estar entre 1 byte e 16 MB.");
        if (MaxItems is < 1 or > 10_000)
            throw new InvalidOperationException("SecretsFileOptions.MaxItems deve estar entre 1 e 10.000.");

        var format = Format;
        if (format == SecretsFileFormat.Auto)
        {
            format = System.IO.Path.GetExtension(Path).ToLowerInvariant() switch
            {
                ".json" => SecretsFileFormat.Json,
                ".env" => SecretsFileFormat.DotEnv,
                _ when System.IO.Path.GetFileName(Path).Equals(".env", StringComparison.OrdinalIgnoreCase) => SecretsFileFormat.DotEnv,
                _ => throw new InvalidOperationException("SecretsFileOptions.Format: informe Json ou DotEnv (a extensão do arquivo não é .json nem .env).")
            };
        }
        else if (!Enum.IsDefined(format))
            throw new InvalidOperationException("SecretsFileOptions.Format inválido.");

        return (System.IO.Path.GetFullPath(Path), format);
    }
}

/// <summary>
/// Segredos em um único arquivo JSON ou .env (provedor <c>SecretsFile</c>). Formato de templates do Vault Agent / Infisical Agent
/// e de exports (<c>infisical export</c>, <c>bws secret list</c> convertido).
/// </summary>
/// <remarks>
/// <para>O arquivo é relido só quando muda (tamanho ou data de modificação); a leitura de um segredo não reabre o arquivo.</para>
/// <para>Nomes repetidos (sem diferenciar maiúsculas) e nomes fora da regra do provedor fazem a leitura falhar: num arquivo único,
/// um nome inválido é erro de geração do arquivo, e ignorá-lo esconderia o problema.</para>
/// </remarks>
public sealed class FileSecretStore : SyncedSecretStoreBase
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "SecretsFile";

    private readonly SecretsFileOptions _options;
    private readonly string _path;
    private readonly SecretsFileFormat _format;
    private readonly Lock _sync = new();
    private (long Length, DateTime WriteTime, IReadOnlyList<SyncedEntry> Entries)? _cache;

    /// <summary>Cria o leitor. As opções são validadas aqui.</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public FileSecretStore(SecretsFileOptions options, ILogger<FileSecretStore>? logger = null)
        : base(Provider, MaxValueBytesLimit, logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        (_path, _format) = options.Validate();
        _options = options;
    }

    private protected override IReadOnlyList<SyncedEntry> ReadAll(CancellationToken cancellationToken)
    {
        var info = new FileInfo(_path);
        if (!info.Exists)
            throw new FileNotFoundException("Arquivo de segredos ausente.");

        lock (_sync)
        {
            if (_cache is { } cached && cached.Length == info.Length && cached.WriteTime == info.LastWriteTimeUtc)
                return cached.Entries;
        }

        var content = SyncedText.ReadFile(_path, _options.MaxFileBytes, out var updatedOn)
            ?? throw new SyncedFormatException("arquivo de segredos acima de MaxFileBytes");
        var pairs = _format == SecretsFileFormat.Json ? SecretFileParsers.ParseJson(content) : SecretFileParsers.ParseDotEnv(content);

        if (pairs.Count > _options.MaxItems)
            throw new SyncedFormatException($"o arquivo tem mais de {_options.MaxItems} segredos (MaxItems)");

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<SyncedEntry>(pairs.Count);
        foreach (var (name, value) in pairs)
        {
            if (!IsValidName(name))
                throw new SyncedFormatException($"nome fora da regra do provedor no arquivo de segredos (item {entries.Count + 1})");
            if (!names.Add(name))
                throw new SyncedFormatException($"nome repetido sem diferenciar maiúsculas: {name}");
            if (System.Text.Encoding.UTF8.GetByteCount(value) > MaxValueBytesLimit)
                throw new SyncedFormatException($"valor acima de 1 MB: {name}");
            entries.Add(new SyncedEntry(name, value, updatedOn));
        }

        lock (_sync)
            _cache = (info.Length, info.LastWriteTimeUtc, entries);
        return entries;
    }

    private protected override string? DescribeSource(SyncedEntry entry) => "file:" + System.IO.Path.GetFileName(_path) + "#" + entry.Name;
}
