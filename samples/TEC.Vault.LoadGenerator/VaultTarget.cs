using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Caching;
using TEC.Vault.InMemory;
using TEC.Vault.Keys;

namespace TEC.Vault.LoadGenerator;

/// <summary>Provedor alvo da carga.</summary>
public enum VaultBackend
{
    /// <summary><c>TEC.Vault.InMemory</c>: custo do componente sem SDK nem rede.</summary>
    InMemory,

    /// <summary>Provedor Azure com o SDK real sobre <see cref="SimulatedKeyVault"/> (sem rede).</summary>
    Simulated,

    /// <summary>Key Vault de testes real (<c>TEC_TESTES_VAULT_URI</c>); nunca use um cofre de produção.</summary>
    Azure
}

/// <summary>
/// Stores prontos para a carga, com os itens semeados (segredos e uma chave RSA). Com <see cref="VaultBackend.Azure"/>, os itens
/// criados usam o prefixo <c>tec-teste-carga-</c> e são excluídos e removidos definitivamente em <see cref="DisposeAsync"/>.
/// </summary>
public sealed class VaultTarget : IAsyncDisposable
{
    /// <summary>Prefixo dos itens no cofre real (a limpeza de sobras dos testes de integração também os remove: <c>tec-teste-</c>).</summary>
    public const string AzurePrefix = "tec-teste-carga-";

    private readonly List<string> _createdSecrets = [];
    private CachingSecretReader? _cache;

    private VaultTarget(VaultBackend backend, ISecretStore secrets, IKeyStore keys, SimulatedKeyVault? simulated, string prefix)
    {
        Backend = backend;
        Secrets = secrets;
        Keys = keys;
        Crypto = (IKeyCryptography)keys;
        Simulated = simulated;
        Prefix = prefix;
    }

    /// <summary>Provedor alvo.</summary>
    public VaultBackend Backend { get; }

    /// <summary>Store de segredos (escritas e leituras sem cache).</summary>
    public ISecretStore Secrets { get; }

    /// <summary>Leitor usado nos cenários de leitura: o cache, quando ligado, senão o próprio store.</summary>
    public ISecretReader Reader => (ISecretReader?)_cache ?? Secrets;

    /// <summary>Cache de segredos, quando ligado por <see cref="EnableCache"/>.</summary>
    internal CachingSecretReader? Cache => _cache;

    /// <summary>Store de chaves.</summary>
    public IKeyStore Keys { get; }

    /// <summary>Criptografia no cofre (mesma instância de <see cref="Keys"/>).</summary>
    public IKeyCryptography Crypto { get; }

    /// <summary>Cofre simulado (só com <see cref="VaultBackend.Simulated"/>): latência, falhas e contadores de requisições.</summary>
    public SimulatedKeyVault? Simulated { get; }

    /// <summary>Prefixo dos nomes criados pela carga.</summary>
    public string Prefix { get; }

    /// <summary>Nomes dos segredos semeados.</summary>
    public IReadOnlyList<string> SecretNames { get; private set; } = [];

    /// <summary>Nome da chave RSA semeada.</summary>
    public string KeyName { get; private set; } = string.Empty;

    /// <summary>Versão da chave RSA semeada.</summary>
    public string KeyVersion { get; private set; } = string.Empty;

    /// <summary>Cria os stores do provedor e semeia <paramref name="secrets"/> segredos e uma chave RSA.</summary>
    /// <param name="backend">Provedor alvo.</param>
    /// <param name="secrets">Quantidade de segredos semeados (leituras sorteiam entre eles).</param>
    /// <param name="vaultUri">Cofre real (obrigatório com <see cref="VaultBackend.Azure"/>).</param>
    /// <param name="tenantId">Tenant do login de desenvolvedor/CI no cofre real (opcional).</param>
    /// <param name="cancellationToken">Cancela a semeadura.</param>
    public static async Task<VaultTarget> CreateAsync(VaultBackend backend, int secrets = 100, Uri? vaultUri = null, string? tenantId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(secrets, 1);
        VaultTarget target;
        switch (backend)
        {
            case VaultBackend.InMemory:
                var memory = new InMemoryVaultOptions { AllowOutsideDevelopment = true };
                target = new VaultTarget(backend, new InMemorySecretStore(memory), new InMemoryKeyStore(memory), null, "carga-");
                break;

            case VaultBackend.Simulated:
                // Host próprio por instância: o SDK guarda o desafio de autenticação em cache estático por host
                var simulated = new SimulatedKeyVault($"https://kv-carga-{Guid.NewGuid():N}"[..32] + ".vault.azure.net/");
                target = new VaultTarget(backend, AzureKeyVaultStores.CreateSecretStore(simulated.Configure),
                    AzureKeyVaultStores.CreateKeyStore(simulated.Configure), simulated, "carga-");
                break;

            case VaultBackend.Azure:
                ArgumentNullException.ThrowIfNull(vaultUri);
                void Configure(AzureKeyVaultOptions o)
                {
                    o.VaultUri = vaultUri;
                    // Mesma credencial dos testes de integração: az login local ou login OIDC do CI (Azure CLI)
                    o.Authentication = AzureKeyVaultAuthentication.Developer;
                    o.AllowDeveloperCredentialsOutsideDevelopment = true;
                    o.TenantId = tenantId;
                }

                string run = Guid.NewGuid().ToString("N")[..8];
                target = new VaultTarget(backend, AzureKeyVaultStores.CreateSecretStore(Configure), AzureKeyVaultStores.CreateKeyStore(Configure),
                    null, $"{AzurePrefix}{run}-");
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(backend));
        }

        try
        {
            await target.SeedAsync(secrets, cancellationToken).ConfigureAwait(false);
            return target;
        }
        catch
        {
            await target.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Liga o cache de segredos (decorator <see cref="CachingSecretReader"/>) para os cenários de leitura.</summary>
    public VaultTarget EnableCache(TimeSpan duration)
    {
        _cache?.Dispose();
        _cache = new CachingSecretReader(Secrets, duration);
        return this;
    }

    /// <summary>Registra um segredo criado pela carga (excluído no fim com o cofre real).</summary>
    internal void TrackCreatedSecret(string name)
    {
        lock (_createdSecrets)
        {
            if (!_createdSecrets.Contains(name, StringComparer.OrdinalIgnoreCase))
                _createdSecrets.Add(name);
        }
    }

    private async Task SeedAsync(int count, CancellationToken cancellationToken)
    {
        var names = Enumerable.Range(0, count).Select(i => $"{Prefix}segredo-{i}").ToArray();
        if (Simulated is not null)
        {
            // Semeadura direta no estado: não entra nos contadores nem na latência
            foreach (string name in names)
                Simulated.AddSecret(name, $"valor-{name}");
            KeyName = $"{Prefix}kek";
            KeyVersion = Simulated.AddRsaKey(KeyName);
        }
        else
        {
            foreach (string name in names)
            {
                var set = await Secrets.SetSecretAsync(name, $"valor-{name}", cancellationToken: cancellationToken).ConfigureAwait(false);
                if (set.IsFailure)
                    throw new InvalidOperationException($"Falha ao semear o segredo: {set.Error!.Code}.");
                TrackCreatedSecret(name);
            }

            KeyName = $"{Prefix}kek";
            var key = await Keys.CreateKeyAsync(KeyName, new CreateKeyOptions { KeyType = VaultKeyType.Rsa, KeySize = 2048 }, cancellationToken)
                .ConfigureAwait(false);
            if (key.IsFailure)
                throw new InvalidOperationException($"Falha ao criar a chave: {key.Error!.Code}.");
            KeyVersion = key.Value.Properties.Version!;
        }

        SecretNames = names;
    }

    /// <summary>Descarta o cache e, no cofre real, exclui e remove definitivamente os itens criados.</summary>
    public async ValueTask DisposeAsync()
    {
        _cache?.Dispose();
        if (Backend != VaultBackend.Azure)
        {
            (Secrets as IDisposable)?.Dispose();
            (Keys as IDisposable)?.Dispose();
            return;
        }

        string[] created;
        lock (_createdSecrets)
            created = [.. _createdSecrets];

        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        foreach (string name in created)
        {
            var deleted = await Secrets.DeleteSecretAsync(name, timeout.Token).ConfigureAwait(false);
            if (deleted.IsSuccess && Secrets is ISecretRecycleBin bin)
                await bin.PurgeDeletedSecretAsync(name, timeout.Token).ConfigureAwait(false);
        }

        if (KeyName.Length > 0)
        {
            var deleted = await Keys.DeleteKeyAsync(KeyName, timeout.Token).ConfigureAwait(false);
            if (deleted.IsSuccess && Keys is IKeyRecycleBin bin)
                await bin.PurgeDeletedKeyAsync(KeyName, timeout.Token).ConfigureAwait(false);
        }
    }
}
