using Microsoft.Extensions.Logging;
using TEC.Vault.Synced.Internal;

namespace TEC.Vault.Synced;

/// <summary>Configuração do provedor <c>Directory</c>: um arquivo por segredo.</summary>
public sealed class DirectorySecretsOptions
{
    /// <summary>
    /// Pasta com os arquivos (ex.: <c>/mnt/secrets</c>, o volume de um Secret do Kubernetes ou do CSI driver). Obrigatório.
    /// O nome do arquivo é o nome do segredo e o conteúdo é o valor.
    /// </summary>
    public string? Path { get; set; }

    /// <summary>Tamanho máximo de cada arquivo (1 byte a 1 MB). Padrão: 64 KB. Arquivo maior faz a leitura falhar (não é truncado).</summary>
    public int MaxFileBytes { get; set; } = SyncedSecretStoreBase.DefaultMaxValueBytes;

    /// <summary>Quantidade máxima de arquivos (1 a 10.000). Padrão: 1.000. Acima disso a listagem falha.</summary>
    public int MaxItems { get; set; } = 1000;

    /// <summary>Remove quebras de linha do final do valor (o <c>echo</c> e vários agentes gravam com "\n"). Padrão: <c>true</c>.</summary>
    public bool TrimTrailingNewline { get; set; } = true;

    internal string Validate()
    {
        if (string.IsNullOrWhiteSpace(Path))
            throw new InvalidOperationException("DirectorySecretsOptions.Path é obrigatório.");
        if (MaxFileBytes is < 1 or > SyncedSecretStoreBase.MaxValueBytesLimit)
            throw new InvalidOperationException("DirectorySecretsOptions.MaxFileBytes deve estar entre 1 byte e 1 MB.");
        if (MaxItems is < 1 or > 10_000)
            throw new InvalidOperationException("DirectorySecretsOptions.MaxItems deve estar entre 1 e 10.000.");
        return System.IO.Path.GetFullPath(Path);
    }
}

/// <summary>
/// Segredos em arquivos de uma pasta, um arquivo por segredo (provedor <c>Directory</c>). Formato do volume de Secret do
/// Kubernetes, do Secrets Store CSI driver, do External Secrets Operator e dos templates do Vault Agent / Infisical Agent.
/// </summary>
/// <remarks>
/// <para>Só os arquivos diretamente na pasta são lidos: subpastas e entradas cujo nome começa com <c>.</c> são ignoradas (isso
/// pula as pastas internas <c>..data</c> e <c>..2026_...</c> do Kubernetes; os links <c>nome → ..data/nome</c> são lidos).
/// Arquivos com nome fora da regra do provedor também são ignorados.</para>
/// <para>Um link simbólico só é seguido se o destino final ficar dentro da pasta: um link para fora (ex.: <c>/etc/passwd</c>) é
/// ignorado e registrado em log. O nome pedido nunca vira caminho: a pasta é listada e o arquivo é escolhido pelo nome.</para>
/// <para>Nomes iguais sem diferenciar maiúsculas (possível em Linux) fazem a leitura falhar, em vez de escolher um deles.</para>
/// </remarks>
public sealed class DirectorySecretStore : SyncedSecretStoreBase
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "Directory";

    private readonly DirectorySecretsOptions _options;
    private readonly string _root;
    private readonly ILogger? _logger;

    /// <summary>Cria o leitor. As opções são validadas aqui.</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public DirectorySecretStore(DirectorySecretsOptions options, ILogger<DirectorySecretStore>? logger = null)
        : base(Provider, Checked(options).MaxFileBytes, logger)
    {
        _options = options;
        _root = RealPath(options.Validate());
        _logger = logger;
    }

    /// <summary>
    /// Caminho real da pasta (se ela própria for um link simbólico, o destino): os links dos segredos são conferidos contra ele.
    /// </summary>
    private static string RealPath(string path)
    {
        var directory = new DirectoryInfo(path);
        return directory.LinkTarget is not null && directory.ResolveLinkTarget(returnFinalTarget: true) is { } target
            ? System.IO.Path.GetFullPath(target.FullName)
            : path;
    }

    private static DirectorySecretsOptions Checked(DirectorySecretsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        return options;
    }

    private protected override IReadOnlyList<SyncedEntry> ReadAll(CancellationToken cancellationToken) =>
        Files(cancellationToken).Select(f => Read(f.Name, f.Path)).ToList();

    private protected override SyncedEntry? ReadOne(string name, CancellationToken cancellationToken)
    {
        var file = Files(cancellationToken).FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase));
        return file.Path is null ? null : Read(file.Name, file.Path);
    }

    private protected override string? DescribeSource(SyncedEntry entry) => entry.Source;

    /// <summary>Arquivos válidos da pasta: nome → caminho final (links já resolvidos e confinados à pasta).</summary>
    private List<(string Name, string Path)> Files(CancellationToken cancellationToken)
    {
        var root = new DirectoryInfo(_root);
        var rootPrefix = _root.EndsWith(System.IO.Path.DirectorySeparatorChar) ? _root : _root + System.IO.Path.DirectorySeparatorChar;
        var files = new List<(string Name, string Path)>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in root.EnumerateFileSystemInfos("*", new EnumerationOptions { RecurseSubdirectories = false, AttributesToSkip = 0 }))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.Name.StartsWith('.') || entry is DirectoryInfo || !IsValidName(entry.Name))
                continue;

            var path = entry.FullName;
            if (entry.LinkTarget is not null)
            {
                var target = entry.ResolveLinkTarget(returnFinalTarget: true);
                if (target is null || !target.Exists || target is DirectoryInfo)
                    continue;
                path = System.IO.Path.GetFullPath(target.FullName);
                if (!path.StartsWith(rootPrefix, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                {
                    if (_logger is not null)
                        SyncedLog.LinkOutsideFolderIgnored(_logger, entry.Name);
                    continue;
                }
            }

            if (!names.Add(entry.Name))
                throw new SyncedFormatException($"nomes de arquivo repetidos sem diferenciar maiúsculas: {entry.Name}");
            if (files.Count == _options.MaxItems)
                throw new SyncedFormatException($"a pasta tem mais de {_options.MaxItems} segredos (MaxItems)");
            files.Add((entry.Name, path));
        }

        return files;
    }

    private SyncedEntry Read(string name, string path)
    {
        var value = SyncedText.ReadFile(path, _options.MaxFileBytes, out var updatedOn)
            ?? throw new SyncedFormatException($"arquivo acima de MaxFileBytes: {name}");
        if (_options.TrimTrailingNewline)
            value = SyncedText.TrimTrailingNewlines(value);
        return new SyncedEntry(name, value, updatedOn, "file:" + name);
    }
}
