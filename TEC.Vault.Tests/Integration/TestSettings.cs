using Microsoft.Extensions.Configuration;

namespace TEC.Vault.Tests.Integration;

/// <summary>
/// Configuração dos testes de integração, com a mesma convenção em todos os componentes TEC (o arquivo é repetido em cada
/// projeto de testes: não há projeto compartilhado entre os repositórios).
/// </summary>
/// <remarks>
/// <para>Vale a primeira fonte com valor, nesta ordem:</para>
/// <list type="number">
/// <item><description>variável de ambiente <c>TEC_TESTES_*</c> (definida pelo CI ou por <c>.github/scripts/integration-setup.sh</c>);</description></item>
/// <item><description><c>dotnet user-secrets</c> com o id <see cref="UserSecretsId"/> (o mesmo em todos os projetos de teste),
/// seção <see cref="Section"/>;</description></item>
/// <item><description>arquivo <c>appsettings.Local.json</c> da saída do projeto (ignorado pelo git), seção <see cref="Section"/>.</description></item>
/// </list>
/// <para>Nenhuma chave tem valor padrão apontando para recurso real: sem o serviço configurado, o teste de integração se pula
/// com o motivo (nunca falha nem passa em silêncio). Não há variável liga/desliga: a seleção é pela categoria
/// <c>Integracao</c>.</para>
/// </remarks>
internal static class TestSettings
{
    /// <summary>Id do <c>dotnet user-secrets</c> compartilhado por todos os projetos de teste dos componentes TEC.</summary>
    public const string UserSecretsId = "tudoemcodigo-tec-testes";

    /// <summary>Seção das chaves no user-secrets e no <c>appsettings.Local.json</c>.</summary>
    public const string Section = "TecTestes";

    /// <summary>URI do Key Vault exclusivo de testes (compartilhada por todos os componentes).</summary>
    public const string VaultUriVariable = "TEC_TESTES_VAULT_URI";

    /// <summary>Tenant do Entra ID do Key Vault de testes (compartilhada por todos os componentes).</summary>
    public const string TenantIdVariable = "TEC_TESTES_TENANT_ID";

    private static readonly IConfiguration? UserSecrets = Load(builder => builder.AddUserSecrets(UserSecretsId));

    private static readonly IConfiguration? LocalFile = Load(builder => builder
        .SetBasePath(AppContext.BaseDirectory)
        .AddJsonFile("appsettings.Local.json", optional: true));

    /// <summary>
    /// Primeiro valor encontrado: a variável de ambiente, depois a chave <c>TecTestes:{key}</c> no user-secrets e por fim no
    /// <c>appsettings.Local.json</c>.
    /// </summary>
    public static string? Read(string variable, string key)
    {
        if (Environment.GetEnvironmentVariable(variable) is { Length: > 0 } value)
            return value.Trim();

        foreach (var source in new[] { UserSecrets, LocalFile })
        {
            if (source?[$"{Section}:{key}"] is { } configured && !string.IsNullOrWhiteSpace(configured))
                return configured.Trim();
        }

        return null;
    }

    /// <summary>Tenant do Entra ID (opcional).</summary>
    public static string? TenantId() => Read(TenantIdVariable, "TenantId");

    /// <summary>URI do Key Vault de testes, ou <c>null</c> com o motivo em <paramref name="reason"/>.</summary>
    public static Uri? VaultUri(out string reason)
    {
        string? value = Read(VaultUriVariable, "VaultUri");
        if (value is null)
        {
            reason = $"Key Vault de testes não configurado: defina {VaultUriVariable}, ou execute " +
                     $"'dotnet user-secrets set {Section}:VaultUri https://<cofre>.vault.azure.net/ --id {UserSecretsId}'.";
            return null;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            reason = "A URI do Key Vault de testes configurada não é uma URL https válida.";
            return null;
        }

        reason = string.Empty;
        return uri;
    }

    private static IConfiguration? Load(Action<IConfigurationBuilder> configure)
    {
        try
        {
            var builder = new ConfigurationBuilder();
            configure(builder);
            return builder.Build();
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException or IOException or InvalidDataException)
        {
            // Sem pasta de perfil (user-secrets) ou arquivo inválido: a fonte é ignorada, as demais continuam valendo
            return null;
        }
    }
}
