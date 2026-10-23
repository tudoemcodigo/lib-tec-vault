using TEC.Vault.Providers.Http;

namespace TEC.Vault.AwsSecretsManager;

/// <summary>Opções de configuração para o provedor AWS Secrets Manager.</summary>
public sealed class AwsSecretsManagerOptions
{
    /// <summary>Região da AWS (ex.: "us-east-1", "sa-east-1"). Padrão: lê variável AWS_REGION ou us-east-1.</summary>
    public string Region { get; set; } = Environment.GetEnvironmentVariable("AWS_REGION")
        ?? Environment.GetEnvironmentVariable("AWS_DEFAULT_REGION")
        ?? "us-east-1";

    /// <summary>Endpoint customizado da AWS (opcional, para LocalStack, emuladores ou VPC Endpoints privados).</summary>
    public Uri? Endpoint { get; set; }

    /// <summary>AWS Access Key ID.</summary>
    public string? AccessKeyId { get; set; }

    /// <summary>AWS Secret Access Key.</summary>
    public string? SecretAccessKey { get; set; }

    /// <summary>AWS Session Token (para credenciais temporárias ou STS / IRSA).</summary>
    public string? SessionToken { get; set; }

    /// <summary>Variável de ambiente com a chave de acesso (padrão: AWS_ACCESS_KEY_ID).</summary>
    public string? AccessKeyIdVariable { get; set; } = "AWS_ACCESS_KEY_ID";

    /// <summary>Variável de ambiente com o segredo de acesso (padrão: AWS_SECRET_ACCESS_KEY).</summary>
    public string? SecretAccessKeyVariable { get; set; } = "AWS_SECRET_ACCESS_KEY";

    /// <summary>Variável de ambiente com o token de sessão (padrão: AWS_SESSION_TOKEN).</summary>
    public string? SessionTokenVariable { get; set; } = "AWS_SESSION_TOKEN";

    /// <summary>Máximo de itens por listagem (1 a 10.000). Padrão: 1.000.</summary>
    public int MaxListItems { get; set; } = 1000;

    /// <summary>Configurações de transporte HTTP e resiliência.</summary>
    public VaultHttpSettings Http { get; } = new();

    /// <summary>Relógio injetável (para testes e carimbos de tempo).</summary>
    public TimeProvider? TimeProvider { get; set; }

    internal (string AccessKey, string SecretKey, string? SessionToken, Uri EndpointUri) Resolve()
    {
        if (string.IsNullOrWhiteSpace(Region))
            throw new InvalidOperationException("AwsSecretsManagerOptions.Region é obrigatória (ex.: us-east-1).");

        var accessKey = AccessKeyId ?? (AccessKeyIdVariable is not null ? Environment.GetEnvironmentVariable(AccessKeyIdVariable) : null);
        var secretKey = SecretAccessKey ?? (SecretAccessKeyVariable is not null ? Environment.GetEnvironmentVariable(SecretAccessKeyVariable) : null);
        var sessionToken = SessionToken ?? (SessionTokenVariable is not null ? Environment.GetEnvironmentVariable(SessionTokenVariable) : null);

        if (string.IsNullOrWhiteSpace(accessKey))
            throw new InvalidOperationException("AWS Access Key ID não foi configurada. Defina AwsSecretsManagerOptions.AccessKeyId ou a variável AWS_ACCESS_KEY_ID.");

        if (string.IsNullOrWhiteSpace(secretKey))
            throw new InvalidOperationException("AWS Secret Access Key não foi configurada. Defina AwsSecretsManagerOptions.SecretAccessKey ou a variável AWS_SECRET_ACCESS_KEY.");

        var endpoint = Endpoint ?? new Uri($"https://secretsmanager.{Region}.amazonaws.com/");

        return (accessKey, secretKey, sessionToken, endpoint);
    }
}
