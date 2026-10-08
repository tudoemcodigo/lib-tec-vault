using System.Globalization;
using Microsoft.Extensions.Configuration;

namespace TEC.Vault.DependencyInjection;

/// <summary>
/// Leitura estrita de uma seção de configuração do cofre (uso pelos provedores no registro por configuração).
/// </summary>
/// <remarks>
/// <para>Compatível com Native AOT: cada valor é lido e convertido explicitamente, sem binder por reflexão.</para>
/// <para>Falha fechada: valor inválido ou chave desconhecida (<see cref="EnsureNoUnknownKeys"/>) lança
/// <see cref="InvalidOperationException"/> na inicialização, com o caminho da chave. <b>O valor nunca aparece na mensagem</b>
/// (uma chave digitada errado pode conter um segredo colado por engano).</para>
/// <para>As chaves são comparadas sem diferenciar maiúsculas de minúsculas, como no <see cref="IConfiguration"/>.</para>
/// </remarks>
public sealed class VaultSettings
{
    private readonly IConfiguration _section;
    private readonly HashSet<string> _known = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, VaultSettings> _children = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ignored = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Cria o leitor sobre <paramref name="section"/>.</summary>
    /// <param name="section">Seção (ou a raiz) da configuração.</param>
    /// <param name="path">Caminho exibido nas mensagens de erro. <c>null</c>: o <c>Path</c> da seção, se houver.</param>
    public VaultSettings(IConfiguration section, string? path = null)
    {
        ArgumentNullException.ThrowIfNull(section);
        _section = section;
        Path = path ?? (section as IConfigurationSection)?.Path ?? "";
    }

    /// <summary>Caminho da seção (ex.: <c>Vault:HashiCorpVault</c>).</summary>
    public string Path { get; }

    /// <summary>Indica se a seção tem algum valor (ela mesma ou filhas).</summary>
    public bool Exists() => _section.GetChildren().Any() || (_section as IConfigurationSection)?.Value is not null;

    /// <summary>Texto da chave. Vazio ou só espaços = <c>null</c>.</summary>
    public string? GetString(string key)
    {
        var value = Read(key);
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }

    /// <summary>Texto obrigatório.</summary>
    /// <exception cref="InvalidOperationException">Chave ausente ou vazia.</exception>
    public string GetRequiredString(string key) =>
        GetString(key) ?? throw new InvalidOperationException($"Configuração obrigatória ausente: {Full(key)}.");

    /// <summary>Booleano (<c>true</c>/<c>false</c>).</summary>
    public bool? GetBoolean(string key) => Parse<bool>(key, "true ou false",
        static text => bool.TryParse(text, out var value) ? value : null);

    /// <summary>Inteiro dentro de [<paramref name="min"/>, <paramref name="max"/>].</summary>
    public int? GetInt32(string key, int min = int.MinValue, int max = int.MaxValue) => Parse(key, $"inteiro entre {min} e {max}",
        text => int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value >= min && value <= max
            ? value
            : (int?)null);

    /// <summary>Intervalo no formato <c>[d.]hh:mm:ss</c>, maior que zero.</summary>
    public TimeSpan? GetTimeSpan(string key) => Parse(key, "intervalo [d.]hh:mm:ss maior que zero",
        static text => TimeSpan.TryParse(text, CultureInfo.InvariantCulture, out var value) && value > TimeSpan.Zero
            ? value
            : (TimeSpan?)null);

    /// <summary>Endereço absoluto.</summary>
    public Uri? GetUri(string key)
    {
        var text = GetString(key);
        if (text is null)
            return null;

        return Uri.TryCreate(text, UriKind.Absolute, out var value)
            ? value
            : throw new InvalidOperationException($"Configuração inválida em {Full(key)}: esperado endereço absoluto.");
    }

    /// <summary>Valor de enum pelo nome (sem diferenciar maiúsculas). Números não são aceitos.</summary>
    public TEnum? GetEnum<TEnum>(string key) where TEnum : struct, Enum => Parse<TEnum>(key, $"um de: {string.Join(", ", Enum.GetNames<TEnum>())}",
        static text => !char.IsAsciiDigit(text[0]) && text[0] != '-' && Enum.TryParse<TEnum>(text, ignoreCase: true, out var value) &&
                       Enum.IsDefined(value)
            ? value
            : (TEnum?)null);

    /// <summary>Flags de enum separadas por vírgula (ex.: <c>Secrets, Keys</c>).</summary>
    public TEnum? GetFlags<TEnum>(string key) where TEnum : struct, Enum => Parse<TEnum>(key, $"combinação de: {string.Join(", ", Enum.GetNames<TEnum>())}",
        static text =>
        {
            ulong combined = 0;
            foreach (var part in text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                if (char.IsAsciiDigit(part[0]) || part[0] == '-' || !Enum.TryParse<TEnum>(part, ignoreCase: true, out var value) ||
                    !Enum.IsDefined(value))
                    return (TEnum?)null;
                combined |= Convert.ToUInt64(value, CultureInfo.InvariantCulture);
            }

            return (TEnum?)(TEnum)Enum.ToObject(typeof(TEnum), combined);
        });

    /// <summary>Pares chave → valor das filhas diretas da chave (ex.: tags, segredos iniciais).</summary>
    public IReadOnlyDictionary<string, string> GetDictionary(string key)
    {
        _known.Add(key);
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var child in _section.GetSection(key).GetChildren())
        {
            if (child.GetChildren().Any())
                throw new InvalidOperationException($"Configuração inválida em {Full(key)}:{child.Key}: esperado um valor de texto.");
            result[child.Key] = child.Value ?? "";
        }

        return result;
    }

    /// <summary>Subseção, com a mesma verificação de chaves desconhecidas (feita pelo <see cref="EnsureNoUnknownKeys"/> do pai).</summary>
    public VaultSettings GetSection(string key)
    {
        _known.Add(key);
        if (!_children.TryGetValue(key, out var child))
        {
            child = new VaultSettings(_section.GetSection(key), Full(key));
            _children[key] = child;
        }

        return child;
    }

    /// <summary>Nomes das subseções e chaves diretas presentes.</summary>
    public IEnumerable<string> Keys => _section.GetChildren().Select(c => c.Key);

    /// <summary>
    /// Marca a chave como conhecida sem validar o conteúdo (ex.: a seção de um provedor registrado que a configuração não
    /// selecionou).
    /// </summary>
    public void Ignore(string key)
    {
        _known.Add(key);
        _ignored.Add(key);
    }

    /// <summary>
    /// Recusa uma chave que traria um segredo em texto na configuração (ex.: <c>ClientSecret</c>). Use para obrigar a leitura
    /// por arquivo ou variável de ambiente.
    /// </summary>
    /// <param name="key">Chave proibida.</param>
    /// <param name="alternatives">Chaves aceitas no lugar (para a mensagem).</param>
    /// <exception cref="InvalidOperationException">A chave está presente.</exception>
    public void RejectInlineSecret(string key, params string[] alternatives)
    {
        _known.Add(key);
        if (_section.GetSection(key).Value is not null || _section.GetSection(key).GetChildren().Any())
        {
            throw new InvalidOperationException(
                $"{Full(key)}: segredos não são aceitos em texto na configuração. Use {string.Join(" ou ", alternatives.Select(Full))}.");
        }
    }

    /// <summary>Recusa uma chave que só pode ser definida em código (ex.: liberações de segurança).</summary>
    /// <exception cref="InvalidOperationException">A chave está presente.</exception>
    public void RejectKey(string key, string reason)
    {
        _known.Add(key);
        if (_section.GetSection(key).Value is not null || _section.GetSection(key).GetChildren().Any())
            throw new InvalidOperationException($"{Full(key)}: {reason}");
    }

    /// <summary>
    /// Confere que toda chave presente foi lida (inclusive nas subseções obtidas por <see cref="GetSection"/>).
    /// </summary>
    /// <exception cref="InvalidOperationException">Há chaves desconhecidas (provável erro de digitação).</exception>
    public void EnsureNoUnknownKeys()
    {
        var unknown = new List<string>();
        Collect(unknown);
        if (unknown.Count > 0)
        {
            throw new InvalidOperationException(
                $"Configuração do cofre com chaves desconhecidas: {string.Join(", ", unknown)}. Confira a grafia na documentação do provedor; numa seção de provedor, confira também se ele foi adicionado no AddTecVault (providers.AddXxx()).");
        }
    }

    private void Collect(List<string> unknown)
    {
        foreach (var child in _section.GetChildren())
        {
            if (!_known.Contains(child.Key))
                unknown.Add(Full(child.Key));
        }

        foreach (var (key, child) in _children)
        {
            if (!_ignored.Contains(key))
                child.Collect(unknown);
        }
    }

    private string? Read(string key)
    {
        _known.Add(key);
        var section = _section.GetSection(key);
        if (section.GetChildren().Any())
            throw new InvalidOperationException($"Configuração inválida em {Full(key)}: esperado um valor, encontrada uma seção.");
        return section.Value;
    }

    private T? Parse<T>(string key, string expected, Func<string, T?> parse) where T : struct
    {
        var text = GetString(key);
        if (text is null)
            return null;

        return parse(text) ?? throw new InvalidOperationException($"Configuração inválida em {Full(key)}: esperado {expected}.");
    }

    private string Full(string key) => Path.Length == 0 ? key : $"{Path}:{key}";
}
