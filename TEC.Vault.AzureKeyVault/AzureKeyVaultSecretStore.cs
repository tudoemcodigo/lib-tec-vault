using Azure;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault.Internal;
using TEC.Vault.Common;
using TEC.Vault.Providers;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;
using AzSecretProperties = Azure.Security.KeyVault.Secrets.SecretProperties;
using SecretProperties = TEC.Vault.Secrets.SecretProperties;

namespace TEC.Vault.AzureKeyVault;

/// <summary>
/// Segredos do Azure Key Vault: leitura, gestão, lixeira (soft delete) e backup. Permissões RBAC: leitura "Key Vault Secrets User";
/// escrita "Key Vault Secrets Officer". Crie com <c>UseAzureKeyVault</c> (DI) ou <see cref="AzureKeyVaultStores"/>.
/// </summary>
public sealed class AzureKeyVaultSecretStore : AzureKeyVaultStoreBase, ISecretStore, ISecretRecycleBin, ISecretBackup, IVaultHealthProbe
{
    internal AzureKeyVaultSecretStore(AzureKeyVaultClients clients, ILogger<AzureKeyVaultSecretStore>? logger = null)
        : base(clients, logger)
    {
    }

    private SecretClient Client => Clients.Secrets;

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultSecret>("secret.get", name, Rules.Item(name, version), isWrite: false,
            async ct =>
            {
                KeyVaultSecret secret = await Client.GetSecretAsync(name, version, ct).ConfigureAwait(false);
                if (secret.Value is null)
                    return VaultErrors.ProviderFailure();

                // Segredo gerenciado = conteúdo de um certificado (PFX/PEM com a chave privada). A leitura é permitida,
                // mas auditada como o download de certificado: é uma chave privada saindo do cofre.
                if (secret.Properties.Managed)
                    AuditSensitiveRead("secret.get", name, ManagedSecretAuditReason);

                return new VaultSecret(ToModel(secret.Properties), secret.Value);
            }, cancellationToken);

    internal const string ManagedSecretAuditReason = "leitura de segredo gerenciado (certificado com chave privada)";

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<bool>("secret.exists", name, Rules.Name(name), isWrite: false, async ct =>
        {
            try
            {
                await foreach (var page in Client.GetPropertiesOfSecretVersionsAsync(name, ct).AsPages(pageSizeHint: 1).ConfigureAwait(false))
                    return page.Values.Count > 0;
                return false;
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                return false;
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SecretWriteOptions();
        var inputError = Rules.SetSecret(name, value, options, Clients.Time.GetUtcNow());

        return ExecuteAsync<SecretProperties>("secret.set", name, inputError, isWrite: true, async ct =>
        {
            var secret = new KeyVaultSecret(name, value);
            secret.Properties.ContentType = options.ContentType;
            secret.Properties.Enabled = options.Enabled;
            secret.Properties.ExpiresOn = options.ExpiresOn;
            secret.Properties.NotBefore = options.NotBefore;
            ReplaceTags(secret.Properties.Tags, options.Tags);

            KeyVaultSecret saved = await Client.SetSecretAsync(secret, ct).ConfigureAwait(false);
            return ToModel(saved.Properties);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateSecret(name, version, update, Clients.Time.GetUtcNow());

        return ExecuteAsync<SecretProperties>("secret.update", name, inputError, isWrite: true, async ct =>
        {
            // Metadados obtidos pela listagem de versões: o valor do segredo não é lido para alterar propriedades
            var versions = new List<AzSecretProperties>();
            await foreach (var properties in Client.GetPropertiesOfSecretVersionsAsync(name, ct).ConfigureAwait(false))
                versions.Add(properties);

            AzSecretProperties? target;
            if (version is not null)
            {
                target = versions.Find(p => string.Equals(p.Version, version, StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                // Versão atual = a mais recente por CreatedOn. CreatedOn tem resolução de 1 segundo: se houver empate, a
                // listagem não diz qual é a atual, e só o GET sem versão responde de forma confiável (lê o valor, que é descartado)
                var newest = VaultVersionRules.Newest(versions, p => p.CreatedOn);
                if (newest.Count > 1)
                {
                    try
                    {
                        KeyVaultSecret current = await Client.GetSecretAsync(name, null, ct).ConfigureAwait(false);
                        target = versions.Find(p => string.Equals(p.Version, current.Properties.Version, StringComparison.OrdinalIgnoreCase));
                    }
                    catch (RequestFailedException ex) when (IsDisabledFailure(ex))
                    {
                        // Versão atual desabilitada (403 com innererror SecretDisabled): desempate determinístico pelos metadados.
                        // Outros 403 (RBAC, firewall, rede privada) seguem como erro: alterar a versão errada por falta de
                        // permissão de leitura seria pior que falhar
                        target = VaultVersionRules.BreakTie(newest, p => p.UpdatedOn, p => p.Version);
                    }
                }
                else
                {
                    target = newest.Count == 1 ? newest[0] : null;
                }
            }

            if (target is null)
                return VaultErrors.NotFound();

            if (update.Enabled is { } enabled) target.Enabled = enabled;
            if (update.ExpiresOn is { } expiresOn) target.ExpiresOn = expiresOn;
            if (update.NotBefore is { } notBefore) target.NotBefore = notBefore;
            if (update.ContentType is { } contentType) target.ContentType = contentType;
            ReplaceTags(target.Tags, update.Tags);

            AzSecretProperties updated = await Client.UpdateSecretPropertiesAsync(target, ct).ConfigureAwait(false);
            return ToModel(updated);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.list", null, null, isWrite: false, async ct =>
        {
            var list = new List<SecretProperties>();
            await foreach (var properties in Client.GetPropertiesOfSecretsAsync(ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToModel(properties));
            }
            return list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var list = new List<SecretProperties>();
            await foreach (var properties in Client.GetPropertiesOfSecretVersionsAsync(name, ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToModel(properties));
            }
            return list.Count == 0 ? VaultErrors.NotFound() : list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<DeletedVaultItem>("secret.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var timeout = WithOperationTimeout(ct);
            var operation = await Client.StartDeleteSecretAsync(name, timeout.Token).ConfigureAwait(false);
            DeletedSecret deleted = await operation.WaitForCompletionAsync(timeout.Token).ConfigureAwait(false);
            return ToDeleted(deleted.Name, deleted.DeletedOn, deleted.ScheduledPurgeDate);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<DeletedVaultItem>>("secret.list-deleted", null, null, isWrite: false, async ct =>
        {
            var list = new List<DeletedVaultItem>();
            await foreach (var deleted in Client.GetDeletedSecretsAsync(ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToDeleted(deleted.Name, deleted.DeletedOn, deleted.ScheduledPurgeDate));
            }
            return list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> RecoverDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<SecretProperties>("secret.recover", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var timeout = WithOperationTimeout(ct);
            var operation = await Client.StartRecoverDeletedSecretAsync(name, timeout.Token).ConfigureAwait(false);
            AzSecretProperties recovered = await operation.WaitForCompletionAsync(timeout.Token).ConfigureAwait(false);
            return ToModel(recovered);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> PurgeDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.purge", name, Rules.Name(name), isWrite: true,
            ct => Client.PurgeDeletedSecretAsync(name, ct), cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> BackupSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<byte[]>("secret.backup", name, Rules.Name(name), isWrite: true, async ct =>
        {
            byte[] backup = await Client.BackupSecretAsync(name, ct).ConfigureAwait(false);
            return backup;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> RestoreSecretBackupAsync(byte[] backup, CancellationToken cancellationToken = default) =>
        ExecuteAsync<SecretProperties>("secret.restore", null, Rules.Backup(backup), isWrite: true, async ct =>
        {
            AzSecretProperties restored = await Client.RestoreSecretBackupAsync(backup, ct).ConfigureAwait(false);
            return ToModel(restored);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.health", null, null, isWrite: false, async ct =>
        {
            // Apenas metadados, uma página de um item: confirma rede, autenticação e permissão sem ler valores
            await foreach (var _ in Client.GetPropertiesOfSecretsAsync(ct).AsPages(pageSizeHint: 1).ConfigureAwait(false))
                break;
        }, cancellationToken);

    internal static SecretProperties ToModel(AzSecretProperties properties) => new()
    {
        Name = properties.Name,
        Version = properties.Version,
        Id = properties.Id?.ToString(),
        Enabled = properties.Enabled ?? false,
        CreatedOn = properties.CreatedOn,
        UpdatedOn = properties.UpdatedOn,
        ExpiresOn = properties.ExpiresOn,
        NotBefore = properties.NotBefore,
        ManagedBy = ToManagedBy(properties.Managed),
        ContentType = properties.ContentType,
        Tags = CopyTags(properties.Tags)
    };
}
