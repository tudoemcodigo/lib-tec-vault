using Microsoft.Extensions.Hosting;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.Infisical;

/// <summary>Como a aplicação se autentica no Infisical (identidade de máquina).</summary>
public enum InfisicalAuthentication
{
    /// <summary>
    /// Universal Auth: <see cref="InfisicalOptions.ClientId"/> e o client secret lido de arquivo
    /// (<see cref="InfisicalOptions.ClientSecretFile"/>) ou variável de ambiente (<see cref="InfisicalOptions.ClientSecretVariable"/>).
    /// </summary>
    UniversalAuth = 0,

    /// <summary>
    /// Kubernetes Auth: token da service account do pod (<see cref="InfisicalOptions.ServiceAccountTokenFile"/>) trocado por um
    /// token do Infisical, sem segredo guardado pela aplicação. Recomendado no Kubernetes.
    /// </summary>
    Kubernetes = 1,

    /// <summary>
    /// Token de acesso pronto, lido de arquivo (<see cref="InfisicalOptions.AccessTokenFile"/>) ou variável
    /// (<see cref="InfisicalOptions.AccessTokenVariable"/>). Para CI e ferramentas; o token não é renovado pela biblioteca.
    /// </summary>
    AccessToken = 2
}

/// <summary>Configuração do provedor Infisical.</summary>
public sealed class InfisicalOptions
{
    /// <summary>Caminho padrão do token da service account no pod.</summary>
    public const string DefaultServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    /// <summary>
    /// Endereço do Infisical. Padrão: <c>https://app.infisical.com</c> (nuvem US). Use <c>https://eu.infisical.com</c> para a nuvem
    /// europeia ou o endereço da instância self-hosted. Sempre HTTPS (HTTP só em localhost no ambiente Development).
    /// </summary>
    public Uri SiteUrl { get; set; } = new("https://app.infisical.com/");

    /// <summary>ID do projeto. Obrigatório.</summary>
    public string? ProjectId { get; set; }

    /// <summary>Slug do ambiente (ex.: <c>prod</c>, <c>dev</c>). Obrigatório.</summary>
    public string? Environment { get; set; }

    /// <summary>Pasta dos segredos no projeto. Padrão: <c>/</c>. Ex.: <c>/minha-api</c>.</summary>
    public string SecretPath { get; set; } = "/";

    /// <summary>Modo de autenticação. Padrão: <see cref="InfisicalAuthentication.UniversalAuth"/>.</summary>
    public InfisicalAuthentication Authentication { get; set; } = InfisicalAuthentication.UniversalAuth;

    /// <summary>Client ID da identidade (Universal Auth).</summary>
    public string? ClientId { get; set; }

    /// <summary>Arquivo com o client secret (Universal Auth). Ex.: um Secret do Kubernetes montado.</summary>
    public string? ClientSecretFile { get; set; }

    /// <summary>Variável de ambiente com o client secret (Universal Auth).</summary>
    public string? ClientSecretVariable { get; set; }

    /// <summary>ID da identidade de máquina (Kubernetes Auth).</summary>
    public string? IdentityId { get; set; }

    /// <summary>Arquivo do token da service account (Kubernetes Auth). Padrão: <see cref="DefaultServiceAccountTokenFile"/>.</summary>
    public string? ServiceAccountTokenFile { get; set; }

    /// <summary>Organização do login (opcional; Kubernetes Auth).</summary>
    public string? OrganizationSlug { get; set; }

    /// <summary>Arquivo com o token de acesso (<see cref="InfisicalAuthentication.AccessToken"/>).</summary>
    public string? AccessTokenFile { get; set; }

    /// <summary>Variável de ambiente com o token de acesso (<see cref="InfisicalAuthentication.AccessToken"/>).</summary>
    public string? AccessTokenVariable { get; set; }

    /// <summary>
    /// Expande referências <c>${...}</c> no valor ao ler. Padrão: <c>false</c> (o valor lido é exatamente o gravado; com
    /// expansão, gravar e ler o mesmo segredo poderia dar valores diferentes).
    /// </summary>
    public bool ExpandSecretReferences { get; set; }

    /// <summary>Inclui segredos importados de outras pastas na leitura e na listagem. Padrão: <c>false</c>.</summary>
    public bool IncludeImports { get; set; }

    /// <summary>Transporte HTTP (tentativas, tempo limite, handler).</summary>
    public VaultHttpSettings Http { get; } = new();

    /// <summary>Ambiente da aplicação (libera HTTP em localhost só em Development). <c>null</c>: o do container ou as variáveis de ambiente.</summary>
    public IHostEnvironment? HostEnvironment { get; set; }

    /// <summary>Relógio (expiração do token). Padrão: <see cref="System.TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; set; }

    internal (Uri SiteUrl, string SecretPath) Validate()
    {
        var site = VaultEndpoint.Validate(SiteUrl, "InfisicalOptions.SiteUrl", HostEnvironment);
        if (string.IsNullOrWhiteSpace(ProjectId) || !ProjectId.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
            throw new InvalidOperationException("InfisicalOptions.ProjectId é obrigatório (letras, números e hífen).");
        if (string.IsNullOrWhiteSpace(Environment) || !Environment.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new InvalidOperationException("InfisicalOptions.Environment é obrigatório (slug do ambiente: letras, números, hífen e sublinhado).");

        var path = string.IsNullOrWhiteSpace(SecretPath) ? "/" : SecretPath.Trim();
        if (!path.StartsWith('/') || path.Contains("//", StringComparison.Ordinal) ||
            path.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(p => p is "." or ".." || !p.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')))
            throw new InvalidOperationException("InfisicalOptions.SecretPath deve começar com / e ter só letras, números, hífen, sublinhado e ponto (ex.: /minha-api).");
        if (path.Length > 1)
            path = path.TrimEnd('/');

        switch (Authentication)
        {
            case InfisicalAuthentication.UniversalAuth:
                if (string.IsNullOrWhiteSpace(ClientId))
                    throw new InvalidOperationException("InfisicalOptions.ClientId é obrigatório no Universal Auth.");
                break;
            case InfisicalAuthentication.Kubernetes:
                if (string.IsNullOrWhiteSpace(IdentityId))
                    throw new InvalidOperationException("InfisicalOptions.IdentityId é obrigatório no Kubernetes Auth.");
                break;
            case InfisicalAuthentication.AccessToken:
                break;
            default:
                throw new InvalidOperationException("InfisicalOptions.Authentication inválido.");
        }

        Credential();   // valida arquivo/variável
        Http.Validate("InfisicalOptions.Http");
        return (site, path);
    }

    internal VaultCredentialInput Credential() => Authentication switch
    {
        InfisicalAuthentication.UniversalAuth => VaultCredentialInput.Create(ClientSecretFile, ClientSecretVariable,
            "InfisicalOptions.ClientSecretFile", "InfisicalOptions.ClientSecretVariable"),
        InfisicalAuthentication.Kubernetes => VaultCredentialInput.Create(ServiceAccountTokenFile, null,
            "InfisicalOptions.ServiceAccountTokenFile", "-", DefaultServiceAccountTokenFile),
        _ => VaultCredentialInput.Create(AccessTokenFile, AccessTokenVariable,
            "InfisicalOptions.AccessTokenFile", "InfisicalOptions.AccessTokenVariable")
    };
}
