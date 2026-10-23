using System.Collections;
using Microsoft.Extensions.Logging;
using TEC.Vault.Synced.Internal;

namespace TEC.Vault.Synced;

/// <summary>Configuração do provedor <c>EnvironmentVariables</c>.</summary>
public sealed class EnvironmentSecretsOptions
{
    /// <summary>
    /// Prefixo das variáveis que são segredos (ex.: <c>TECVAULT_</c>). <b>Obrigatório</b>: sem prefixo, qualquer variável do
    /// processo (<c>PATH</c>, <c>HOME</c>...) seria exposta como segredo. O prefixo é removido do nome.
    /// </summary>
    public string? Prefix { get; set; }

    /// <summary>Quantidade máxima de variáveis com o prefixo (1 a 10.000). Padrão: 1.000.</summary>
    public int MaxItems { get; set; } = 1000;

    /// <summary>Tamanho máximo de cada valor (1 byte a 1 MB). Padrão: 64 KB.</summary>
    public int MaxValueBytes { get; set; } = SyncedSecretStoreBase.DefaultMaxValueBytes;

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(Prefix) || Prefix.Length < 2)
            throw new InvalidOperationException("EnvironmentSecretsOptions.Prefix é obrigatório (ao menos 2 caracteres, ex.: TECVAULT_).");
        if (!Prefix.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'))
            throw new InvalidOperationException("EnvironmentSecretsOptions.Prefix aceita só letras, números e sublinhado.");
        if (MaxItems is < 1 or > 10_000)
            throw new InvalidOperationException("EnvironmentSecretsOptions.MaxItems deve estar entre 1 e 10.000.");
        if (MaxValueBytes is < 1 or > SyncedSecretStoreBase.MaxValueBytesLimit)
            throw new InvalidOperationException("EnvironmentSecretsOptions.MaxValueBytes deve estar entre 1 byte e 1 MB.");
    }
}

/// <summary>
/// Segredos em variáveis de ambiente com prefixo (provedor <c>EnvironmentVariables</c>). Formato do <c>infisical run</c>,
/// <c>bws run</c>, <c>op run</c>, <c>envFrom</c> do Kubernetes e afins.
/// </summary>
/// <remarks>
/// <para>Nome do segredo = nome da variável sem o prefixo, com <c>__</c> trocado por <c>--</c> (separador de seção do
/// <c>IConfiguration</c>): <c>TECVAULT_ConnectionStrings__Db</c> → <c>ConnectionStrings--Db</c>. A busca não diferencia maiúsculas.</para>
/// <para>Variáveis de ambiente são herdadas por processos filhos e aparecem em dumps do processo: prefira o provedor
/// <c>Directory</c> quando o agente puder gravar arquivos.</para>
/// </remarks>
public sealed class EnvironmentSecretStore : SyncedSecretStoreBase
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "EnvironmentVariables";

    private readonly EnvironmentSecretsOptions _options;
    private readonly Func<IDictionary> _read;

    /// <summary>Cria o leitor. As opções são validadas aqui.</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public EnvironmentSecretStore(EnvironmentSecretsOptions options, ILogger<EnvironmentSecretStore>? logger = null)
        : this(options, Environment.GetEnvironmentVariables, logger)
    {
    }

    /// <summary>Leitura das variáveis injetável (os testes não alteram o ambiente do processo).</summary>
    internal EnvironmentSecretStore(EnvironmentSecretsOptions options, Func<IDictionary> read, ILogger<EnvironmentSecretStore>? logger = null)
        : base(Provider, Checked(options).MaxValueBytes, logger)
    {
        _options = options;
        _read = read;
    }

    private static EnvironmentSecretsOptions Checked(EnvironmentSecretsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        return options;
    }

    private protected override IReadOnlyList<SyncedEntry> ReadAll(CancellationToken cancellationToken)
    {
        var prefix = _options.Prefix!;
        var entries = new List<SyncedEntry>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (DictionaryEntry variable in _read())
        {
            if (variable.Key is not string key || variable.Value is not string value ||
                key.Length <= prefix.Length || !key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                continue;

            var name = key[prefix.Length..].Replace("__", "--", StringComparison.Ordinal);
            if (!IsValidName(name))
                continue;
            if (!names.Add(name))
                throw new SyncedFormatException($"variáveis repetidas sem diferenciar maiúsculas: {name}");
            if (entries.Count == _options.MaxItems)
                throw new SyncedFormatException($"há mais de {_options.MaxItems} variáveis com o prefixo (MaxItems)");
            if (System.Text.Encoding.UTF8.GetByteCount(value) > _options.MaxValueBytes)
                throw new SyncedFormatException($"variável acima de MaxValueBytes: {name}");

            entries.Add(new SyncedEntry(name, value, UpdatedOn: null));
        }

        return entries;
    }

    private protected override string? DescribeSource(SyncedEntry entry) => "env:" + entry.Name;
}
