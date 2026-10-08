using Azure.Core;
using Microsoft.Extensions.Hosting;
using TEC.Vault.DependencyInjection;

namespace TEC.Vault.AzureKeyVault;

/// <summary>Como a aplicação se autentica no Key Vault. Nenhum modo exige segredo em código ou configuração.</summary>
public enum AzureKeyVaultAuthentication
{
    /// <summary>
    /// Managed Identity (App Service, Functions, Container Apps, VMs, AKS com identidade de pod). Padrão e recomendado em produção.
    /// Para identidade atribuída pelo usuário, informe <see cref="AzureKeyVaultOptions.ManagedIdentityClientId"/>.
    /// </summary>
    ManagedIdentity = 0,

    /// <summary>
    /// Workload Identity federada (AKS, GitHub Actions/OIDC): token do provedor de identidade trocado por token do Entra ID,
    /// sem segredo. Lê AZURE_TENANT_ID, AZURE_CLIENT_ID e AZURE_FEDERATED_TOKEN_FILE do ambiente.
    /// </summary>
    WorkloadIdentity = 1,

    /// <summary>
    /// Credenciais do desenvolvedor: Azure CLI (<c>az login</c>), Azure Developer CLI (<c>azd auth login</c>) e Visual Studio,
    /// nessa ordem. <b>Somente para desenvolvimento</b>: use
    /// <c>builder.Environment.IsDevelopment() ? Developer : ManagedIdentity</c>.
    /// </summary>
    /// <remarks>
    /// Falha fechada: só é aceito quando o ambiente é <c>Development</c> (<see cref="AzureKeyVaultOptions.HostEnvironment"/>, o
    /// <c>IHostEnvironment</c> do container ou, sem ele, <c>ASPNETCORE_ENVIRONMENT</c>/<c>DOTNET_ENVIRONMENT</c>),
    /// ou com <see cref="AzureKeyVaultOptions.AllowDeveloperCredentialsOutsideDevelopment"/>. Assim um servidor com
    /// <c>az login</c> de um administrador nunca passa a usar essa identidade por engano de configuração.
    /// </remarks>
    Developer = 2
}

/// <summary>Configuração do provedor Azure Key Vault.</summary>
public sealed class AzureKeyVaultOptions
{
    /// <summary>Endereço do cofre (ex.: <c>https://kv-minha-app.vault.azure.net/</c>). Obrigatório.</summary>
    /// <remarks>
    /// Validado na inicialização: HTTPS, domínio oficial do Key Vault (nuvem pública, China ou governo dos EUA), sem caminho,
    /// porta, usuário ou query. Isso impede que um valor de configuração adulterado envie o token de acesso da aplicação para
    /// outro servidor.
    /// </remarks>
    public Uri? VaultUri { get; set; }

    /// <summary>Modo de autenticação. Padrão: <see cref="AzureKeyVaultAuthentication.ManagedIdentity"/>.</summary>
    public AzureKeyVaultAuthentication Authentication { get; set; } = AzureKeyVaultAuthentication.ManagedIdentity;

    /// <summary>
    /// Permite <see cref="AzureKeyVaultAuthentication.Developer"/> fora do ambiente Development (ex.: pipeline de CI com
    /// <c>azure/login</c> via OIDC, ferramentas de linha de comando). Padrão: <c>false</c>.
    /// </summary>
    public bool AllowDeveloperCredentialsOutsideDevelopment { get; set; }

    /// <summary>Client ID da Managed Identity atribuída pelo usuário. <c>null</c> = identidade atribuída pelo sistema.</summary>
    public string? ManagedIdentityClientId { get; set; }

    /// <summary>
    /// Tenant do Entra ID. Recomendado em <see cref="AzureKeyVaultAuthentication.Developer"/>: impede que o login de outro tenant
    /// da mesma conta seja usado por engano.
    /// </summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// Credencial própria (ex.: <c>ClientCertificateCredential</c> fora do Azure). Tem precedência sobre <see cref="Authentication"/>.
    /// Evite <c>ClientSecretCredential</c>: é um segredo para proteger o cofre de segredos.
    /// </summary>
    public TokenCredential? Credential { get; set; }

    /// <summary>Tentativas extras em falhas transitórias (backoff exponencial). Padrão: 3.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Timeout de cada tentativa de rede. Padrão: 30 segundos.</summary>
    public TimeSpan NetworkTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Tempo máximo de espera por operações longas (exclusão, recuperação, emissão de certificado). Padrão: 5 minutos.</summary>
    public TimeSpan OperationTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Máximo de itens de uma listagem (segredos, chaves, certificados, versões e itens excluídos), de 1 a 1.000.000. Padrão: 10.000.
    /// Acima disso a listagem para de paginar e retorna <c>VaultErrors.TooManyItems</c>: protege a aplicação (memória, chamadas e
    /// throttling) de um cofre inflado.
    /// </summary>
    public int MaxListItems { get; set; } = 10_000;

    /// <summary>Menor valor aceito em <see cref="CryptographyClientLifetime"/>: 1 minuto.</summary>
    public static readonly TimeSpan MinCryptographyClientLifetime = TimeSpan.FromMinutes(1);

    /// <summary>Maior valor aceito em <see cref="CryptographyClientLifetime"/>: 24 horas.</summary>
    public static readonly TimeSpan MaxCryptographyClientLifetime = TimeSpan.FromHours(24);

    /// <summary>
    /// Tempo máximo de vida de cada cliente de criptografia reaproveitado (um por chave + versão). Padrão: 10 minutos
    /// (de 1 minuto a 24 horas).
    /// </summary>
    /// <remarks>
    /// O SDK do Azure busca a chave pública na primeira operação do cliente e, a partir daí, faz <b>localmente</b> as operações
    /// que só precisam dela (criptografar, wrap e verificar assinatura), sem consultar o cofre. Uma chave desabilitada,
    /// expirada ou excluída no cofre continuaria sendo usada nessas operações enquanto o cliente existisse. Ao fim deste
    /// tempo o cliente é recriado e o estado da chave é lido de novo: é o prazo máximo para a revogação valer em
    /// criptografar/wrap/verificar. Descriptografar, unwrap e assinar são sempre executados no cofre (revogação imediata).
    /// </remarks>
    public TimeSpan CryptographyClientLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Stores registrados por <c>UseAzureKeyVault</c>. Padrão: <see cref="VaultStores.All"/>. Registre só os que a aplicação usa:
    /// o health check verifica cada store registrado, então uma aplicação que só usa chaves (<see cref="VaultStores.Keys"/>) não
    /// precisa de permissão de segredos para ficar saudável. Ignorado em <see cref="AzureKeyVaultStores"/>.
    /// </summary>
    public VaultStores Stores { get; set; } = VaultStores.All;

    /// <summary>
    /// Ambiente da aplicação, usado para liberar <see cref="AzureKeyVaultAuthentication.Developer"/> só em Development.
    /// <c>null</c> (padrão): <c>UseAzureKeyVault</c> usa o <see cref="IHostEnvironment"/> registrado no container (o
    /// <c>WebApplicationBuilder</c>/<c>HostApplicationBuilder</c> registra) e, sem ele, as variáveis
    /// <c>ASPNETCORE_ENVIRONMENT</c>/<c>DOTNET_ENVIRONMENT</c>.
    /// </summary>
    public IHostEnvironment? HostEnvironment { get; set; }

    /// <summary>Transporte HTTP substituto, somente para testes automatizados (respostas simuladas, sem rede).</summary>
    internal Azure.Core.Pipeline.HttpPipelineTransport? Transport { get; set; }

    /// <summary>
    /// Relógio (validação de datas de expiração na gravação e vida dos clientes de criptografia). Padrão:
    /// <see cref="System.TimeProvider.System"/>.
    /// </summary>
    public TimeProvider? TimeProvider { get; set; }
}
