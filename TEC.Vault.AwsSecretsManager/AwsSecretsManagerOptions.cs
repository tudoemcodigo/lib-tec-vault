using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.AwsSecretsManager;

/// <summary>Configuração do provedor AWS Secrets Manager.</summary>
/// <remarks>
/// <para>Credenciais, na ordem (vale a primeira fonte configurada; as temporárias são renovadas antes de expirar):</para>
/// <list type="number">
/// <item><description><b>Web identity (IRSA no EKS)</b>: <see cref="RoleArn"/> e <see cref="WebIdentityTokenFile"/> (padrão:
/// <c>AWS_ROLE_ARN</c> e <c>AWS_WEB_IDENTITY_TOKEN_FILE</c>), trocados no STS por <c>AssumeRoleWithWebIdentity</c>. O arquivo do
/// token é relido a cada renovação.</description></item>
/// <item><description><b>Container (ECS e EKS Pod Identity)</b>: <c>AWS_CONTAINER_CREDENTIALS_RELATIVE_URI</c> ou
/// <c>AWS_CONTAINER_CREDENTIALS_FULL_URI</c>, com <c>AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE</c> ou
/// <c>AWS_CONTAINER_AUTHORIZATION_TOKEN</c>. Desligue com <see cref="UseContainerCredentials"/>.</description></item>
/// <item><description><b>Serviço de metadados do EC2 (IMDSv2)</b>, se <see cref="UseInstanceMetadata"/> e
/// <c>AWS_EC2_METADATA_DISABLED</c> não for <c>true</c>.</description></item>
/// <item><description><b>Chaves estáticas</b>, último recurso: <see cref="AccessKeyId"/>/<see cref="SecretAccessKey"/>/
/// <see cref="SessionToken"/> em código ou as variáveis <see cref="AccessKeyIdVariable"/>, <see cref="SecretAccessKeyVariable"/> e
/// <see cref="SessionTokenVariable"/> (lidas a cada login). Com o IMDS ligado, ele é tentado antes; se não responder na primeira
/// vez, o processo passa a usar as chaves estáticas.</description></item>
/// </list>
/// </remarks>
public sealed partial class AwsSecretsManagerOptions
{
    /// <summary>Região da AWS (ex.: <c>us-east-1</c>, <c>sa-east-1</c>). Padrão: <c>AWS_REGION</c>, <c>AWS_DEFAULT_REGION</c> ou <c>us-east-1</c>.</summary>
    public string Region { get; set; } = Environment.GetEnvironmentVariable("AWS_REGION")
        ?? Environment.GetEnvironmentVariable("AWS_DEFAULT_REGION")
        ?? "us-east-1";

    /// <summary>
    /// Endereço da API (VPC endpoint, LocalStack). Padrão: <c>https://secretsmanager.{Region}.amazonaws.com/</c>
    /// (<c>amazonaws.com.cn</c> nas regiões da China). Sempre HTTPS, só o servidor (HTTP só em localhost no ambiente Development).
    /// </summary>
    public Uri? Endpoint { get; set; }

    /// <summary>Endereço do STS para o web identity. Padrão: <c>https://sts.{Region}.amazonaws.com/</c>. Mesmas regras de <see cref="Endpoint"/>.</summary>
    public Uri? StsEndpoint { get; set; }

    /// <summary>ARN do papel assumido com web identity (IRSA). Padrão: <c>AWS_ROLE_ARN</c>.</summary>
    public string? RoleArn { get; set; }

    /// <summary>Arquivo do token de web identity (IRSA: token projetado da service account). Padrão: <c>AWS_WEB_IDENTITY_TOKEN_FILE</c>.</summary>
    public string? WebIdentityTokenFile { get; set; }

    /// <summary>Nome da sessão no STS (aparece no CloudTrail). Padrão: <c>AWS_ROLE_SESSION_NAME</c> ou <c>tec-vault-</c> seguido de um número.</summary>
    public string? RoleSessionName { get; set; }

    /// <summary>Usa as credenciais de container do ECS e do EKS Pod Identity quando as variáveis existem. Padrão: <c>true</c>.</summary>
    public bool UseContainerCredentials { get; set; } = true;

    /// <summary>Usa o serviço de metadados do EC2 (IMDSv2). Padrão: <c>true</c> (a variável <c>AWS_EC2_METADATA_DISABLED=true</c> desliga).</summary>
    public bool UseInstanceMetadata { get; set; } = true;

    /// <summary>Chave de acesso estática, só em código (último recurso). Na configuração, use <see cref="AccessKeyIdVariable"/>.</summary>
    public string? AccessKeyId { get; set; }

    /// <summary>Segredo de acesso estático, só em código; recusado na configuração (use <see cref="SecretAccessKeyVariable"/>).</summary>
    public string? SecretAccessKey { get; set; }

    /// <summary>Token de sessão estático, só em código; recusado na configuração (use <see cref="SessionTokenVariable"/>).</summary>
    public string? SessionToken { get; set; }

    /// <summary>Variável de ambiente com a chave de acesso (padrão: <c>AWS_ACCESS_KEY_ID</c>).</summary>
    public string? AccessKeyIdVariable { get; set; } = "AWS_ACCESS_KEY_ID";

    /// <summary>Variável de ambiente com o segredo de acesso (padrão: <c>AWS_SECRET_ACCESS_KEY</c>).</summary>
    public string? SecretAccessKeyVariable { get; set; } = "AWS_SECRET_ACCESS_KEY";

    /// <summary>Variável de ambiente com o token de sessão (padrão: <c>AWS_SESSION_TOKEN</c>).</summary>
    public string? SessionTokenVariable { get; set; } = "AWS_SESSION_TOKEN";

    /// <summary>
    /// Máximo de itens de uma listagem, de 1 a 1.000.000. Padrão: 10.000. Acima do limite a operação falha com
    /// <c>VaultErrors.TooManyItems</c> (nunca devolve uma lista cortada).
    /// </summary>
    public int MaxListItems { get; set; } = 10_000;

    /// <summary>Transporte HTTP (tentativas, tempo limite, teto de resposta, handler, circuit breaker).</summary>
    public VaultHttpSettings Http { get; } = new();

    /// <summary>Ambiente da aplicação (libera HTTP em localhost só em Development). <c>null</c>: o do container ou as variáveis de ambiente.</summary>
    public IHostEnvironment? HostEnvironment { get; set; }

    /// <summary>Relógio (assinatura, expiração das credenciais e circuito). Padrão: <see cref="System.TimeProvider.System"/>.</summary>
    public TimeProvider? TimeProvider { get; set; }

    /// <summary>Leitura das variáveis de ambiente (testes; o padrão lê as do processo).</summary>
    internal Func<string, string?> ReadVariable { get; set; } = Environment.GetEnvironmentVariable;

    // Região: só letras minúsculas, dígitos e hífen (vai para o nome do host e para o escopo da assinatura)
    [GeneratedRegex(@"^[a-z0-9]+(-[a-z0-9]+)*\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex RegionPattern();

    [GeneratedRegex(@"^arn:[a-z0-9-]+:iam::[0-9]{12}:role/[\w+=,.@/-]{1,512}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex RoleArnPattern();

    [GeneratedRegex(@"^[\w+=,.@-]{2,64}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    internal static partial Regex RoleSessionNamePattern();

    /// <summary>Confere as opções e decide a fonte das credenciais (na inicialização).</summary>
    /// <exception cref="InvalidOperationException">Opção inválida ou nenhuma fonte de credenciais.</exception>
    internal Resolved Validate()
    {
        if (string.IsNullOrWhiteSpace(Region) || Region.Length > 32 || !RegionPattern().IsMatch(Region))
            throw new InvalidOperationException("AwsSecretsManagerOptions.Region é obrigatória: letras minúsculas, dígitos e hífen (ex.: us-east-1).");

        var suffix = Region.StartsWith("cn-", StringComparison.Ordinal) ? "amazonaws.com.cn" : "amazonaws.com";
        var endpoint = VaultEndpoint.Validate(Endpoint ?? new Uri($"https://secretsmanager.{Region}.{suffix}/"), "AwsSecretsManagerOptions.Endpoint", HostEnvironment);
        Http.Validate("AwsSecretsManagerOptions.Http");
        if (MaxListItems is < 1 or > 1_000_000)
            throw new InvalidOperationException("AwsSecretsManagerOptions.MaxListItems deve estar entre 1 e 1.000.000.");

        // 1. Web identity (IRSA)
        var roleArn = Text(RoleArn) ?? Text(ReadVariable("AWS_ROLE_ARN"));
        var tokenFile = Text(WebIdentityTokenFile) ?? Text(ReadVariable("AWS_WEB_IDENTITY_TOKEN_FILE"));
        if (roleArn is not null || tokenFile is not null)
        {
            if (roleArn is null || tokenFile is null)
                throw new InvalidOperationException("Web identity: informe AwsSecretsManagerOptions.RoleArn e WebIdentityTokenFile juntos (ou AWS_ROLE_ARN e AWS_WEB_IDENTITY_TOKEN_FILE).");
            if (roleArn.Length > 2048 || !RoleArnPattern().IsMatch(roleArn))
                throw new InvalidOperationException("AwsSecretsManagerOptions.RoleArn deve ser o ARN de um papel do IAM (arn:aws:iam::123456789012:role/nome).");

            var session = Text(RoleSessionName) ?? Text(ReadVariable("AWS_ROLE_SESSION_NAME"))
                ?? "tec-vault-" + (TimeProvider ?? System.TimeProvider.System).GetUtcNow().ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (!RoleSessionNamePattern().IsMatch(session))
                throw new InvalidOperationException("AwsSecretsManagerOptions.RoleSessionName deve ter de 2 a 64 caracteres: letras, dígitos e +=,.@_-.");

            var sts = VaultEndpoint.Validate(StsEndpoint ?? new Uri($"https://sts.{Region}.{suffix}/"), "AwsSecretsManagerOptions.StsEndpoint", HostEnvironment);
            return new Resolved(endpoint, AwsCredentialKind.WebIdentity) { StsEndpoint = sts, RoleArn = roleArn, WebIdentityTokenFile = tokenFile, RoleSessionName = session };
        }

        // 2. Container (ECS, EKS Pod Identity)
        if (UseContainerCredentials && ContainerUri() is { } container)
            return new Resolved(endpoint, AwsCredentialKind.Container) { ContainerUri = container };

        // 3. IMDSv2 (com as chaves estáticas como alternativa se ele não responder) e 4. chaves estáticas
        var metadataDisabled = string.Equals(Text(ReadVariable("AWS_EC2_METADATA_DISABLED")), "true", StringComparison.OrdinalIgnoreCase);
        if (UseInstanceMetadata && !metadataDisabled)
            return new Resolved(endpoint, AwsCredentialKind.InstanceMetadata);

        var accessKeyId = Text(AccessKeyId) ?? Variable(AccessKeyIdVariable);
        var secretAccessKey = Text(SecretAccessKey) ?? Variable(SecretAccessKeyVariable);
        if (accessKeyId is null && secretAccessKey is null)
        {
            throw new InvalidOperationException(
                "Nenhuma fonte de credenciais da AWS: configure web identity (RoleArn e WebIdentityTokenFile), credenciais de container, o " +
                "serviço de metadados do EC2 (UseInstanceMetadata) ou chaves estáticas (AccessKeyIdVariable e SecretAccessKeyVariable).");
        }

        if (accessKeyId is null || secretAccessKey is null)
            throw new InvalidOperationException("Chaves estáticas da AWS incompletas: informe a chave de acesso e o segredo de acesso (código ou variáveis).");
        return new Resolved(endpoint, AwsCredentialKind.Static);
    }

    private string? Variable(string? name) => Text(name) is { } variable ? Text(ReadVariable(variable)) : null;

    /// <summary>
    /// Endereço das credenciais de container: <c>AWS_CONTAINER_CREDENTIALS_RELATIVE_URI</c> (sempre em 169.254.170.2) ou
    /// <c>AWS_CONTAINER_CREDENTIALS_FULL_URI</c>, que só aceita HTTPS ou HTTP para loopback e para os endereços do agente do ECS e
    /// do EKS Pod Identity (as mesmas regras dos SDKs da AWS). <c>null</c>: sem as variáveis.
    /// </summary>
    private Uri? ContainerUri()
    {
        if (Text(ReadVariable("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) is { } relative)
        {
            var host = new Uri("http://169.254.170.2/");
            if (!relative.StartsWith('/') || relative.StartsWith("//", StringComparison.Ordinal) || relative.Contains('\\', StringComparison.Ordinal) ||
                !Uri.TryCreate(host, relative, out var uri) || uri.Host != host.Host || uri.Port != 80 || uri.Scheme != Uri.UriSchemeHttp)
                throw new InvalidOperationException("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI inválida: esperado um caminho relativo (ex.: /v2/credentials/...).");
            return uri;
        }

        if (Text(ReadVariable("AWS_CONTAINER_CREDENTIALS_FULL_URI")) is not { } full)
            return null;

        if (!Uri.TryCreate(full, UriKind.Absolute, out var address) || !string.IsNullOrEmpty(address.UserInfo) || !string.IsNullOrEmpty(address.Fragment))
            throw new InvalidOperationException("AWS_CONTAINER_CREDENTIALS_FULL_URI inválida: esperado um endereço absoluto sem usuário nem fragmento.");
        var allowedHttp = address.IsLoopback || address.Host is "169.254.170.2" or "169.254.170.23" or "[fd00:ec2::23]";
        if (address.Scheme != Uri.UriSchemeHttps && !(address.Scheme == Uri.UriSchemeHttp && allowedHttp))
            throw new InvalidOperationException("AWS_CONTAINER_CREDENTIALS_FULL_URI deve usar HTTPS (HTTP só para loopback, 169.254.170.2, 169.254.170.23 ou fd00:ec2::23).");
        return address;
    }

    private static string? Text(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>Opções conferidas: endereço da API e a fonte das credenciais escolhida.</summary>
    internal sealed record Resolved(Uri Endpoint, AwsCredentialKind Credentials)
    {
        public Uri? StsEndpoint { get; init; }

        public string? RoleArn { get; init; }

        public string? WebIdentityTokenFile { get; init; }

        public string? RoleSessionName { get; init; }

        public Uri? ContainerUri { get; init; }
    }
}

/// <summary>Fonte das credenciais da AWS escolhida na inicialização.</summary>
internal enum AwsCredentialKind
{
    WebIdentity,
    Container,
    InstanceMetadata,
    Static
}
