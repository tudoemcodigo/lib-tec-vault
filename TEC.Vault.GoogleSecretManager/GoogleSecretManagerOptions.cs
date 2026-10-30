using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.GoogleSecretManager;

/// <summary>Configuração do provedor Google Cloud Secret Manager.</summary>
/// <remarks>
/// <para>Credencial, na ordem (vale a primeira configurada; o token fica em cache e é renovado antes de expirar):</para>
/// <list type="number">
/// <item><description><b>Token estático</b>: <see cref="AccessToken"/> (só em código) ou a variável de <see cref="AccessTokenVariable"/>,
/// relida quando o Google recusa o token (401).</description></item>
/// <item><description><b>Service Account JSON</b>: a variável de <see cref="CredentialsJsonVariable"/> ou o arquivo de
/// <see cref="CredentialsJsonFile"/> (padrão: <c>GOOGLE_APPLICATION_CREDENTIALS</c>), lido com teto a cada renovação. O provedor
/// assina um JWT RS256 e o troca por um token no <c>token_uri</c> do JSON, que precisa ser HTTPS e de um host de
/// <see cref="AllowedTokenHosts"/>.</description></item>
/// <item><description><b>Metadata Server</b> do Google (Compute Engine, GKE, Cloud Run), se <see cref="UseMetadataServer"/>.</description></item>
/// </list>
/// </remarks>
public sealed partial class GoogleSecretManagerOptions
{
    /// <summary>Endereço padrão da troca do JWT por token.</summary>
    public const string DefaultTokenUri = "https://oauth2.googleapis.com/token";

    /// <summary>ID (ou número) do projeto. Padrão: <c>GOOGLE_CLOUD_PROJECT</c> ou <c>GCP_PROJECT</c>. Obrigatório.</summary>
    public string? ProjectId { get; set; }

    /// <summary>Endereço da API. Padrão: <c>https://secretmanager.googleapis.com/</c>. Sempre HTTPS, só o servidor (HTTP só em localhost no ambiente Development).</summary>
    public Uri Endpoint { get; set; } = new("https://secretmanager.googleapis.com/");

    /// <summary>Token OAuth2 estático, só em código (testes, CI); recusado na configuração (use <see cref="AccessTokenVariable"/>).</summary>
    public string? AccessToken { get; set; }

    /// <summary>Variável de ambiente com um token OAuth2 estático.</summary>
    public string? AccessTokenVariable { get; set; }

    /// <summary>Arquivo da Service Account (JSON). Padrão: <c>GOOGLE_APPLICATION_CREDENTIALS</c>. Configurado e ausente, a inicialização falha.</summary>
    public string? CredentialsJsonFile { get; set; }

    /// <summary>Variável de ambiente com o conteúdo do JSON da Service Account.</summary>
    public string? CredentialsJsonVariable { get; set; }

    /// <summary>Usa o Metadata Server do Google quando não há outra credencial. Padrão: <c>true</c>.</summary>
    public bool UseMetadataServer { get; set; } = true;

    /// <summary>
    /// Hosts aceitos no <c>token_uri</c> do JSON da Service Account (o JWT assinado só vai para eles, sempre em HTTPS). Padrão:
    /// <c>oauth2.googleapis.com</c>. Arquivos antigos com <c>accounts.google.com</c> pedem esse host aqui.
    /// </summary>
    public ICollection<string> AllowedTokenHosts { get; } = new List<string> { "oauth2.googleapis.com" };

    /// <summary>
    /// Máximo de itens de uma listagem, de 1 a 1.000.000. Padrão: 10.000. Acima do limite a operação falha com
    /// <c>VaultErrors.TooManyItems</c> (nunca devolve uma lista cortada).
    /// </summary>
    public int MaxListItems { get; set; } = 10_000;

    /// <summary>Transporte HTTP (tentativas, tempo limite, teto de resposta, handler, circuit breaker).</summary>
    public VaultHttpSettings Http { get; } = new();

    /// <summary>Ambiente da aplicação (libera HTTP em localhost só em Development). <c>null</c>: o do container ou as variáveis de ambiente.</summary>
    public IHostEnvironment? HostEnvironment { get; set; }

    /// <summary>Relógio (JWT, expiração do token e circuito). Padrão: <see cref="System.TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; set; }

    /// <summary>Leitura das variáveis de ambiente (testes; o padrão lê as do processo).</summary>
    internal Func<string, string?> ReadVariable { get; set; } = Environment.GetEnvironmentVariable;

    // ID do projeto (minúsculas, dígitos, hífen; com "domínio:" nos projetos antigos) ou número: vai para o caminho da URL
    [GeneratedRegex(@"^[a-z0-9][a-z0-9.:-]{0,127}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex ProjectIdPattern();

    /// <summary>Confere as opções e decide a fonte da credencial (na inicialização).</summary>
    /// <exception cref="InvalidOperationException">Opção inválida ou nenhuma credencial.</exception>
    internal Resolved Validate()
    {
        var projectId = Text(ProjectId) ?? Text(ReadVariable("GOOGLE_CLOUD_PROJECT")) ?? Text(ReadVariable("GCP_PROJECT"));
        if (projectId is null || !ProjectIdPattern().IsMatch(projectId))
            throw new InvalidOperationException("GoogleSecretManagerOptions.ProjectId é obrigatório (ou GOOGLE_CLOUD_PROJECT): letras minúsculas, dígitos e hífen.");

        var endpoint = VaultEndpoint.Validate(Endpoint, "GoogleSecretManagerOptions.Endpoint", HostEnvironment);
        Http.Validate("GoogleSecretManagerOptions.Http");
        if (MaxListItems is < 1 or > 1_000_000)
            throw new InvalidOperationException("GoogleSecretManagerOptions.MaxListItems deve estar entre 1 e 1.000.000.");
        if (AllowedTokenHosts.Count == 0 || AllowedTokenHosts.Any(h => string.IsNullOrWhiteSpace(h) || Uri.CheckHostName(h) != UriHostNameType.Dns))
            throw new InvalidOperationException("GoogleSecretManagerOptions.AllowedTokenHosts deve ter ao menos um nome de host válido.");

        if (Text(AccessToken) is not null || Text(AccessTokenVariable) is not null)
            return new Resolved(endpoint, projectId, GoogleCredentialKind.StaticToken);
        if (Text(CredentialsJsonVariable) is not null)
            return new Resolved(endpoint, projectId, GoogleCredentialKind.ServiceAccount);
        if ((Text(CredentialsJsonFile) ?? Text(ReadVariable("GOOGLE_APPLICATION_CREDENTIALS"))) is { } file)
        {
            // Configurado e ausente: falha aqui, sem cair em outra identidade (Metadata Server) sem aviso
            if (!File.Exists(file))
                throw new InvalidOperationException("O arquivo de credenciais do Google (CredentialsJsonFile ou GOOGLE_APPLICATION_CREDENTIALS) não existe.");
            return new Resolved(endpoint, projectId, GoogleCredentialKind.ServiceAccount) { CredentialsJsonFile = file };
        }

        if (UseMetadataServer)
            return new Resolved(endpoint, projectId, GoogleCredentialKind.MetadataServer);
        throw new InvalidOperationException(
            "Nenhuma credencial do Google: configure AccessTokenVariable, CredentialsJsonVariable, CredentialsJsonFile " +
            "(ou GOOGLE_APPLICATION_CREDENTIALS) ou UseMetadataServer.");
    }

    private static string? Text(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>Opções conferidas: endereço, projeto e a fonte da credencial.</summary>
    internal sealed record Resolved(Uri Endpoint, string ProjectId, GoogleCredentialKind Credentials)
    {
        public string? CredentialsJsonFile { get; init; }
    }
}

/// <summary>Fonte da credencial do Google escolhida na inicialização.</summary>
internal enum GoogleCredentialKind
{
    StaticToken,
    ServiceAccount,
    MetadataServer
}
