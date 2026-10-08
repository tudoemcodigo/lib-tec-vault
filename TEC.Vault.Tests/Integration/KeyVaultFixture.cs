using Azure.Core;
using Azure.Identity;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Common;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests.Integration;

/// <summary>
/// Acesso ao Key Vault real de testes. Autentica com as credenciais do desenvolvedor (<c>az login</c>, azd ou Visual Studio);
/// sem cofre configurado ou sem credencial, os testes de integração são pulados, não falham.
/// </summary>
/// <remarks>
/// Configuração (ver <see cref="TestSettings"/>: variável <c>TEC_TESTES_*</c>, <c>dotnet user-secrets</c> ou
/// <c>appsettings.Local.json</c>, seção <c>TecTestes</c>): URI do cofre exclusivo de testes em <c>TEC_TESTES_VAULT_URI</c> /
/// <c>TecTestes:VaultUri</c> (obrigatória, sem valor padrão: sem ela os testes se pulam com o motivo) e tenant em
/// <c>TEC_TESTES_TENANT_ID</c> / <c>TecTestes:TenantId</c> (opcional).
/// Permissões necessárias da identidade: Key Vault Secrets Officer, Crypto Officer e Certificates Officer (ou Administrator).
/// Cada teste cria itens com prefixo <c>tec-teste-</c> e os exclui (e remove definitivamente, se permitido) ao final.
/// Execuções interrompidas deixam sobras: antes do primeiro teste, itens com esse prefixo criados (ou excluídos) há mais de
/// <see cref="LeftoverAge"/> são excluídos e removidos definitivamente. Itens mais novos podem ser de outra execução em andamento.
/// </remarks>
internal static class KeyVaultFixture
{
    public const string TestPrefix = "tec-teste-";

    /// <summary>Idade mínima de uma sobra (evita apagar itens de outra execução simultânea).</summary>
    public static readonly TimeSpan LeftoverAge = TimeSpan.FromHours(1);

    private const int MaxLeftoversPerKind = 50;

    /// <summary>URI do cofre de testes (<c>null</c> se não configurada) e, nesse caso, o motivo para pular os testes.</summary>
    private static readonly (Uri? Uri, string Reason) Vault = ReadVault();

    /// <summary>URI do cofre de testes, ou <c>null</c> se não configurada.</summary>
    public static Uri? VaultUri => Vault.Uri;

    private static readonly string? TenantId = TestSettings.TenantId();

    private static (Uri?, string) ReadVault()
    {
        var uri = TestSettings.VaultUri(out string reason);
        return (uri, reason);
    }

    private static readonly Lazy<Task<string?>> Unavailable = new(CheckAsync);

    public static void Configure(AzureKeyVaultOptions options)
    {
        options.VaultUri = VaultUri ?? throw new InvalidOperationException(Vault.Reason);
        options.Authentication = AzureKeyVaultAuthentication.Developer;
        options.AllowDeveloperCredentialsOutsideDevelopment = true;
        options.TenantId = TenantId;
    }

    public static AzureKeyVaultSecretStore Secrets() => AzureKeyVaultStores.CreateSecretStore(Configure);

    public static AzureKeyVaultKeyStore Keys() => AzureKeyVaultStores.CreateKeyStore(Configure);

    public static AzureKeyVaultCertificateStore Certificates() => AzureKeyVaultStores.CreateCertificateStore(Configure);

    public static string NewName(string kind) => $"{TestPrefix}{kind}-{Guid.NewGuid():N}"[..40];

    /// <summary>Pula o teste se o cofre não estiver configurado ou acessível com as credenciais do desenvolvedor.</summary>
    public static async Task RequireAsync()
    {
        var reason = await Unavailable.Value;
        Skip.When(reason is not null, reason ?? string.Empty);
    }

    private static async Task<string?> CheckAsync()
    {
        if (VaultUri is null)
            return Vault.Reason;

        try
        {
            var options = new AzureKeyVaultOptions();
            Configure(options);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var credential = new ChainedTokenCredential(
                new AzureCliCredential(new AzureCliCredentialOptions { TenantId = TenantId }),
                new AzureDeveloperCliCredential(new AzureDeveloperCliCredentialOptions { TenantId = TenantId }),
                new VisualStudioCredential(new VisualStudioCredentialOptions { TenantId = TenantId }));
            await credential.GetTokenAsync(new TokenRequestContext(["https://vault.azure.net/.default"]), timeout.Token);
        }
        catch (Exception ex) when (ex is AuthenticationFailedException or CredentialUnavailableException or OperationCanceledException)
        {
            return "Sem credencial de desenvolvedor para o Key Vault (execute 'az login').";
        }

        await CleanupLeftoversAsync();
        return null;
    }

    /// <summary>
    /// Exclui e remove definitivamente sobras de execuções anteriores (prefixo <see cref="TestPrefix"/>, mais velhas que
    /// <see cref="LeftoverAge"/>). Nunca falha: a limpeza é melhor esforço e não pode impedir os testes.
    /// </summary>
    private static async Task CleanupLeftoversAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var ct = timeout.Token;
            var limit = DateTimeOffset.UtcNow - LeftoverAge;
            static bool IsLeftover(string name) => name.StartsWith(TestPrefix, StringComparison.OrdinalIgnoreCase);

            // Falha ao listar = nada a limpar daquele tipo
            static IReadOnlyList<T> Items<T>(Result<IReadOnlyList<T>> listed) => listed.IsSuccess ? listed.Value : [];

            // Certificados primeiro: excluir o certificado exclui também a chave e o segredo gerenciados
            var certificates = Certificates();
            foreach (var item in Items(await certificates.ListCertificatesAsync(ct))
                .Where(c => IsLeftover(c.Name) && c.CreatedOn < limit).Take(MaxLeftoversPerKind))
            {
                await certificates.DeleteCertificateAsync(item.Name, ct);
                await certificates.PurgeDeletedCertificateAsync(item.Name, ct);
            }

            var keys = Keys();
            foreach (var item in Items(await keys.ListKeysAsync(ct))
                .Where(k => IsLeftover(k.Name) && !k.IsManaged && k.CreatedOn < limit).Take(MaxLeftoversPerKind))
            {
                await keys.DeleteKeyAsync(item.Name, ct);
                await keys.PurgeDeletedKeyAsync(item.Name, ct);
            }

            var secrets = Secrets();
            foreach (var item in Items(await secrets.ListSecretsAsync(ct))
                .Where(s => IsLeftover(s.Name) && !s.IsManaged && s.CreatedOn < limit).Take(MaxLeftoversPerKind))
            {
                await secrets.DeleteSecretAsync(item.Name, ct);
                await secrets.PurgeDeletedSecretAsync(item.Name, ct);
            }

            // Itens já excluídos (ex.: exclusão feita, purge interrompido) também ocupam o nome até o purge
            foreach (var item in Items(await certificates.ListDeletedCertificatesAsync(ct)).Where(d => IsLeftover(d.Name) && d.DeletedOn < limit).Take(MaxLeftoversPerKind))
                await certificates.PurgeDeletedCertificateAsync(item.Name, ct);
            foreach (var item in Items(await keys.ListDeletedKeysAsync(ct)).Where(d => IsLeftover(d.Name) && d.DeletedOn < limit).Take(MaxLeftoversPerKind))
                await keys.PurgeDeletedKeyAsync(item.Name, ct);
            foreach (var item in Items(await secrets.ListDeletedSecretsAsync(ct)).Where(d => IsLeftover(d.Name) && d.DeletedOn < limit).Take(MaxLeftoversPerKind))
                await secrets.PurgeDeletedSecretAsync(item.Name, ct);
        }
        catch (OperationCanceledException)
        {
            // Limpeza demorou demais: continua com os testes
        }
    }
}
