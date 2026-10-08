using System.Text.RegularExpressions;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Providers;

namespace TEC.Vault.AzureKeyVault.Internal;

/// <summary>Clientes do SDK (thread-safe, um por aplicação), criados a partir de opções já validadas.</summary>
internal sealed partial class AzureKeyVaultClients
{
    /// <summary>
    /// Domínios oficiais do Key Vault. O SDK também confere se o desafio de autenticação pertence ao mesmo domínio
    /// (DisableChallengeResourceVerification = false), mas validar aqui falha já na inicialização.
    /// </summary>
    internal static readonly string[] AllowedHostSuffixes = [".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net"];

    public AzureKeyVaultClients(AzureKeyVaultOptions options)
    {
        Validate(options);

        VaultUri = new Uri(options.VaultUri!.GetLeftPart(UriPartial.Authority) + "/");
        OperationTimeout = options.OperationTimeout;
        MaxListItems = options.MaxListItems;
        CryptographyClientLifetime = options.CryptographyClientLifetime;
        Time = options.TimeProvider ?? TimeProvider.System;
        var credential = CreateCredential(options);

        Secrets = new SecretClient(VaultUri, credential, Configure(new SecretClientOptions(), options));
        Keys = new KeyClient(VaultUri, credential, Configure(new KeyClientOptions(), options));
        Certificates = new CertificateClient(VaultUri, credential, Configure(new CertificateClientOptions(), options));
    }

    public Uri VaultUri { get; }

    public TimeSpan OperationTimeout { get; }

    public int MaxListItems { get; }

    public TimeSpan CryptographyClientLifetime { get; }

    public TimeProvider Time { get; }

    public SecretClient Secrets { get; }

    public KeyClient Keys { get; }

    public CertificateClient Certificates { get; }

    internal static void Validate(AzureKeyVaultOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var uri = options.VaultUri ?? throw new InvalidOperationException("Informe AzureKeyVaultOptions.VaultUri.");
        bool validUri = uri.IsAbsoluteUri
            && uri.Scheme == Uri.UriSchemeHttps
            && uri.IsDefaultPort
            && string.IsNullOrEmpty(uri.UserInfo)
            && string.IsNullOrEmpty(uri.Query)
            && string.IsNullOrEmpty(uri.Fragment)
            && uri.AbsolutePath == "/"
            && AllowedHostSuffixes.Any(s => uri.Host.EndsWith(s, StringComparison.OrdinalIgnoreCase)
                && VaultNameRegex().IsMatch(uri.Host[..^s.Length]));

        if (!validUri)
        {
            throw new InvalidOperationException(
                "AzureKeyVaultOptions.VaultUri inválido: use https://<nome-do-cofre>.vault.azure.net/ (ou o domínio da nuvem soberana), " +
                "sem caminho, porta, usuário ou query.");
        }

        if (options.MaxListItems is < 1 or > 1_000_000)
            throw new InvalidOperationException("AzureKeyVaultOptions.MaxListItems deve estar entre 1 e 1.000.000.");
        if (options.MaxRetries is < 0 or > 10)
            throw new InvalidOperationException("AzureKeyVaultOptions.MaxRetries deve estar entre 0 e 10.");
        if (options.NetworkTimeout <= TimeSpan.Zero || options.NetworkTimeout > TimeSpan.FromMinutes(5))
            throw new InvalidOperationException("AzureKeyVaultOptions.NetworkTimeout deve ser maior que zero e no máximo 5 minutos.");
        if (options.OperationTimeout <= TimeSpan.Zero || options.OperationTimeout > TimeSpan.FromMinutes(30))
            throw new InvalidOperationException("AzureKeyVaultOptions.OperationTimeout deve ser maior que zero e no máximo 30 minutos.");
        if (options.CryptographyClientLifetime < AzureKeyVaultOptions.MinCryptographyClientLifetime
            || options.CryptographyClientLifetime > AzureKeyVaultOptions.MaxCryptographyClientLifetime)
        {
            throw new InvalidOperationException("AzureKeyVaultOptions.CryptographyClientLifetime deve estar entre 1 minuto e 24 horas.");
        }
        if (!Enum.IsDefined(options.Authentication))
            throw new InvalidOperationException("AzureKeyVaultOptions.Authentication inválido.");
        if (options.Credential is null && options.Authentication == AzureKeyVaultAuthentication.Developer
            && !options.AllowDeveloperCredentialsOutsideDevelopment && !VaultEnvironment.IsDevelopment(options.HostEnvironment))
        {
            throw new InvalidOperationException(
                "AzureKeyVaultAuthentication.Developer só é permitido no ambiente Development (IHostEnvironment ou " +
                "ASPNETCORE_ENVIRONMENT/DOTNET_ENVIRONMENT). Em produção use ManagedIdentity ou WorkloadIdentity " +
                "(ou AllowDeveloperCredentialsOutsideDevelopment para CI/ferramentas).");
        }

        VaultBuilder.EnsureValidStores(options.Stores, "AzureKeyVaultOptions.Stores");

        if (options.TenantId is not null && !Guid.TryParse(options.TenantId, out _))
            throw new InvalidOperationException("AzureKeyVaultOptions.TenantId deve ser um GUID.");
        if (options.ManagedIdentityClientId is not null && !Guid.TryParse(options.ManagedIdentityClientId, out _))
            throw new InvalidOperationException("AzureKeyVaultOptions.ManagedIdentityClientId deve ser um GUID.");
    }

    internal static TokenCredential CreateCredential(AzureKeyVaultOptions options)
    {
        if (options.Credential is not null)
            return options.Credential;

        return options.Authentication switch
        {
            AzureKeyVaultAuthentication.ManagedIdentity => options.ManagedIdentityClientId is null
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(options.ManagedIdentityClientId)),

            AzureKeyVaultAuthentication.WorkloadIdentity => new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions
            {
                TenantId = options.TenantId ?? Environment.GetEnvironmentVariable("AZURE_TENANT_ID")
            }),

            // Sem AdditionallyAllowedTenants: o token é pedido somente para o tenant informado (ou o padrão do login)
            AzureKeyVaultAuthentication.Developer => new ChainedTokenCredential(
                new AzureCliCredential(new AzureCliCredentialOptions { TenantId = options.TenantId }),
                new AzureDeveloperCliCredential(new AzureDeveloperCliCredentialOptions { TenantId = options.TenantId }),
                new VisualStudioCredential(new VisualStudioCredentialOptions { TenantId = options.TenantId })),

            _ => throw new InvalidOperationException("AzureKeyVaultOptions.Authentication inválido.")
        };
    }

    private static T Configure<T>(T clientOptions, AzureKeyVaultOptions options) where T : ClientOptions
    {
        clientOptions.Retry.Mode = RetryMode.Exponential;
        clientOptions.Retry.MaxRetries = options.MaxRetries;
        clientOptions.Retry.NetworkTimeout = options.NetworkTimeout;

        // Nunca registrar corpo de requisição/resposta nos logs do SDK (conteriam valores de segredos)
        clientOptions.Diagnostics.IsLoggingContentEnabled = false;

        // Sem spans do SDK: eles levam o endereço do cofre e o nome/versão do item (url.full, az.namespace...) para o
        // backend de rastreamento. A Activity do próprio TEC.Vault já cobre cada operação, sem nome de item
        clientOptions.Diagnostics.IsDistributedTracingEnabled = false;

        if (options.Transport is not null)
        {
            clientOptions.Transport = options.Transport;
            clientOptions.Retry.Delay = TimeSpan.FromMilliseconds(1);
        }

        switch (clientOptions)
        {
            case SecretClientOptions s: s.DisableChallengeResourceVerification = false; break;
            case KeyClientOptions k: k.DisableChallengeResourceVerification = false; break;
            case CertificateClientOptions c: c.DisableChallengeResourceVerification = false; break;
        }

        return clientOptions;
    }

    // \z e não $: $ aceitaria uma quebra de linha no final
    [GeneratedRegex(@"^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VaultNameRegex();
}
