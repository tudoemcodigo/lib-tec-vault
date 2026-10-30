using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
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

    /// <summary>Quantidade máxima de arquivos (1 a 10.000). Padrão: 1.000. Acima disso a listagem falha com <c>VaultErrors.TooManyItems</c>.</summary>
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
/// <para><b>Leitura de um segredo</b>: o arquivo com o nome exato é aberto direto, sem listar a pasta (o nome pedido já passou pela
/// regra do provedor: sem barra, sem <c>.</c> e <c>..</c>). Só quando o nome exato não existe a pasta é listada, para achar um
/// único arquivo com o mesmo nome sem diferenciar maiúsculas; dois arquivos assim fazem a leitura falhar, em vez de escolher um.</para>
/// <para><b>Links simbólicos</b>: o destino final (todos os links resolvidos) precisa ficar dentro da pasta; um link para fora (ex.:
/// <c>/etc/passwd</c>) é ignorado e registrado em log. Para que o link não seja trocado entre a conferência e a leitura, o arquivo é
/// aberto pelo destino já conferido e o handle aberto é verificado de novo: no Linux, pelo caminho real do handle
/// (<c>/proc/self/fd</c>); nos demais sistemas, resolvendo o link outra vez depois da abertura. O conteúdo é lido desse handle.</para>
/// </remarks>
public sealed class DirectorySecretStore : SyncedSecretStoreBase
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "Directory";

    /// <summary>Máximo de links simbólicos seguidos ao resolver um caminho (o mesmo limite do Linux).</summary>
    private const int MaxLinks = 40;

    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows() || OperatingSystem.IsMacOS() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    private readonly DirectorySecretsOptions _options;
    private readonly string _root;
    private readonly string _rootPrefix;
    private readonly ILogger? _logger;

    /// <summary>Cria o leitor. As opções são validadas aqui.</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public DirectorySecretStore(DirectorySecretsOptions options, ILogger<DirectorySecretStore>? logger = null)
        : base(Provider, Checked(options).MaxFileBytes, logger)
    {
        _options = options;
        var configured = options.Validate();
        _root = RealPath(configured) ?? configured;
        _rootPrefix = _root.EndsWith(System.IO.Path.DirectorySeparatorChar) ? _root : _root + System.IO.Path.DirectorySeparatorChar;
        _logger = logger;
    }

    /// <inheritdoc />
    /// <remarks>
    /// O nome exato tem precedência (num Linux, <c>Db</c> e <c>DB</c> podem ser arquivos diferentes): o cache trata grafias
    /// diferentes como itens diferentes.
    /// </remarks>
    public override StringComparer NameComparer => StringComparer.Ordinal;

    private static DirectorySecretsOptions Checked(DirectorySecretsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        return options;
    }

    private protected override IReadOnlyList<SyncedEntry> ReadAll(CancellationToken cancellationToken)
    {
        var entries = new List<SyncedEntry>();
        foreach (var (name, path) in Files(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Read(name, path) is { } entry)
                entries.Add(entry);
        }

        return entries;
    }

    private protected override SyncedEntry? ReadOne(string name, CancellationToken cancellationToken)
    {
        // O nome exato, se existir, decide sem listar a pasta
        var exact = System.IO.Path.Join(_root, name);
        if (Exists(exact))
            return Read(name, exact);

        var file = Files(cancellationToken).FirstOrDefault(f => string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase));
        return file.Path is null ? null : Read(file.Name, file.Path);
    }

    private protected override string? DescribeSource(SyncedEntry entry) => entry.Source;

    /// <summary>Entradas válidas da pasta (nome → caminho da entrada, que pode ser um link), sem nomes repetidos.</summary>
    private List<(string Name, string Path)> Files(CancellationToken cancellationToken)
    {
        var root = new DirectoryInfo(_root);
        var files = new List<(string Name, string Path)>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in root.EnumerateFileSystemInfos("*", new EnumerationOptions { RecurseSubdirectories = false, AttributesToSkip = 0 }))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry.Name.StartsWith('.') || entry is DirectoryInfo || !IsValidName(entry.Name))
                continue;

            if (!names.Add(entry.Name))
                throw new SyncedFormatException($"nomes de arquivo repetidos sem diferenciar maiúsculas: {entry.Name}");
            EnsureListLimit(files.Count + 1, _options.MaxItems);
            files.Add((entry.Name, entry.FullName));
        }

        return files;
    }

    /// <summary>
    /// Lê o arquivo da entrada: resolve o destino final, confere que ele está dentro da pasta, abre o destino, confere o handle
    /// aberto e lê dele. <c>null</c>: entrada ignorada (destino fora da pasta, pasta, link quebrado ou arquivo removido no meio).
    /// </summary>
    private SyncedEntry? Read(string name, string entryPath)
    {
        var target = RealPath(entryPath);
        if (target is null || !IsInsideRoot(target))
        {
            if (_logger is not null)
                SyncedLog.LinkOutsideFolderIgnored(_logger, name);
            return null;
        }

        SafeFileHandle handle;
        try
        {
            if (Directory.Exists(target))
                return null;
            handle = File.OpenHandle(target, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;   // removido entre a listagem e a abertura (ex.: troca do ..data pelo Kubernetes)
        }

        using (handle)
        {
            if (!OpenedTargetMatches(handle, entryPath, target))
            {
                if (_logger is not null)
                    SyncedLog.LinkChangedWhileOpeningIgnored(_logger, name);
                return null;
            }

            // A data vem antes da leitura: o FileStream da leitura fecha o handle ao terminar
            var updatedOn = File.GetLastWriteTimeUtc(handle);
            var value = SyncedText.ReadHandle(handle, _options.MaxFileBytes, name)
                ?? throw new SyncedFormatException($"arquivo acima de MaxFileBytes: {name}");
            if (_options.TrimTrailingNewline)
                value = SyncedText.TrimTrailingNewlines(value);
            return new SyncedEntry(name, value, updatedOn, "file:" + name);
        }
    }

    private bool IsInsideRoot(string path) => path.StartsWith(_rootPrefix, PathComparison);

    /// <summary>
    /// Confere o arquivo realmente aberto. No Linux, o caminho real do handle (<c>/proc/self/fd/N</c>) precisa ser o destino
    /// conferido; sem o <c>/proc</c> (e nos demais sistemas), o link é resolvido de novo e precisa levar ao mesmo destino.
    /// </summary>
    private bool OpenedTargetMatches(SafeFileHandle handle, string entryPath, string target)
    {
        if (OperatingSystem.IsLinux() && OpenedPath(handle) is { } opened)
            return string.Equals(opened, target, StringComparison.Ordinal) && IsInsideRoot(opened);

        return RealPath(entryPath) is { } again && string.Equals(again, target, PathComparison);
    }

    /// <summary>Caminho real de um handle aberto, pelo <c>/proc/self/fd</c> do Linux; <c>null</c> se não der para ler.</summary>
    private static string? OpenedPath(SafeFileHandle handle)
    {
        try
        {
            return new FileInfo($"/proc/self/fd/{handle.DangerousGetHandle().ToInt64().ToString(System.Globalization.CultureInfo.InvariantCulture)}").LinkTarget;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool Exists(string path)
    {
        try
        {
            var info = new FileInfo(path);
            return info.Exists || info.LinkTarget is not null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Caminho real (como o <c>realpath</c> do sistema): cada componente que é link simbólico é trocado pelo destino, inclusive
    /// destinos relativos e links dentro do destino. <c>null</c> se passar de <see cref="MaxLinks"/> links (laço).
    /// </summary>
    internal static string? RealPath(string path)
    {
        var full = System.IO.Path.GetFullPath(path);
        var resolved = System.IO.Path.GetPathRoot(full)!;
        var pending = new List<string>(Split(full[resolved.Length..]));
        var links = 0;
        var i = 0;

        while (i < pending.Count)
        {
            var part = pending[i++];
            if (part is "" or ".")
                continue;
            if (part == "..")
            {
                resolved = System.IO.Path.GetDirectoryName(resolved) ?? resolved;
                continue;
            }

            var candidate = System.IO.Path.Join(resolved, part);
            string? target;
            try
            {
                target = new FileInfo(candidate).LinkTarget;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                target = null;
            }

            if (target is null)
            {
                resolved = candidate;
                continue;
            }

            if (++links > MaxLinks)
                return null;

            if (target.StartsWith(@"\\?\", StringComparison.Ordinal) && !target.StartsWith(@"\\?\UNC\", StringComparison.Ordinal))
                target = target[4..];   // destino de link do Windows no formato estendido
            var rest = pending.GetRange(i, pending.Count - i);
            if (System.IO.Path.IsPathRooted(target))
            {
                var absolute = System.IO.Path.GetFullPath(target);
                resolved = System.IO.Path.GetPathRoot(absolute)!;
                pending = [.. Split(absolute[resolved.Length..]), .. rest];
            }
            else
            {
                pending = [.. Split(target), .. rest];   // relativo à pasta do link (resolved)
            }

            i = 0;
        }

        return resolved;
    }

    private static string[] Split(string path) =>
        path.Split([System.IO.Path.DirectorySeparatorChar, System.IO.Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries);
}
