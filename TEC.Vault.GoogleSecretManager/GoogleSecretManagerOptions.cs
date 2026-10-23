using TEC.Vault.Providers.Http;

namespace TEC.Vault.GoogleSecretManager;

/// <summary>Opções de configuração para o provedor Google Cloud Secret Manager.</summary>
public sealed class GoogleSecretManagerOptions
{
    /// <summary>ID do projeto no Google Cloud (ex.: "meu-projeto-prod"). Padrão: lido de GOOGLE_CLOUD_PROJECT ou GCP_PROJECT.</summary>
    public string? ProjectId { get; set; } = Environment.GetEnvironmentVariable("GOOGLE_CLOUD_PROJECT")
        ?? Environment.GetEnvironmentVariable("GCP_PROJECT");

    /// <summary>Endpoint base da API REST do Secret Manager. Padrão: https://secretmanager.googleapis.com/.</summary>
    public Uri Endpoint { get; set; } = new("https://secretmanager.googleapis.com/");

    /// <summary>Token de acesso OAuth2 Bearer estático (para testes ou CI).</summary>
    public string? AccessToken { get; set; }

    /// <summary>Variável de ambiente com o token de acesso OAuth2.</summary>
    public string? AccessTokenVariable { get; set; }

    /// <summary>Caminho do arquivo de credenciais da Service Account em formato JSON.</summary>
    public string? CredentialsJsonFile { get; set; } = Environment.GetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS");

    /// <summary>Conteúdo ou variável com o JSON da Service Account.</summary>
    public string? CredentialsJsonVariable { get; set; }

    /// <summary>Utiliza o servidor de metadados do Google (Compute Engine, Cloud Run, GKE) para obter tokens automaticamente.</summary>
    public bool UseMetadataServer { get; set; } = true;

    /// <summary>Teto máximo de itens retornados em listagens (1 a 10.000). Padrão: 1.000.</summary>
    public int MaxListItems { get; set; } = 1000;

    /// <summary>Configurações de transporte HTTP e resiliência.</summary>
    public VaultHttpSettings Http { get; } = new();

    /// <summary>Relógio injetável.</summary>
    public TimeProvider? TimeProvider { get; set; }

    internal string ResolveProjectId()
    {
        if (string.IsNullOrWhiteSpace(ProjectId))
            throw new InvalidOperationException("GoogleSecretManagerOptions.ProjectId é obrigatório. Defina ProjectId ou a variável GOOGLE_CLOUD_PROJECT.");

        return ProjectId;
    }
}
