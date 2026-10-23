using System.Diagnostics;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.InMemory.Internal;
using TEC.Vault.Providers;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.InMemory;

/// <summary>
/// Segredos em memória (desenvolvimento e testes): versões, metadados, lixeira e backup, com as mesmas regras de contrato dos
/// provedores reais (ex.: gravar em nome excluído e não removido é conflito; versão atual desabilitada não é lida).
/// </summary>
/// <remarks>Datas de validade são informativas na leitura (como no Azure Key Vault): segredo expirado ainda é lido.</remarks>
public sealed class InMemorySecretStore : InMemoryStoreBase, ISecretStore, ISecretRecycleBin, ISecretBackup, IVaultHealthProbe
{
    /// <summary>Tamanho máximo do valor: 64 KB em UTF-8.</summary>
    public const int MaxSecretValueBytes = 64 * 1024;

    /// <summary>
    /// Versão guardada: metadados + valor. <see cref="ToString"/> e o depurador mascaram o valor (o gerado pelo <c>record</c> o
    /// imprimiria), como em <see cref="VaultSecret"/>.
    /// </summary>
    [DebuggerDisplay("{ToString(),nq}")]
    internal sealed record Version(SecretProperties Properties, string Value)
    {
        public override string ToString() => $"Version {{ Name = {Properties.Name}, Version = {Properties.Version}, Value = *** }}";
    }

    private readonly VersionedItems<Version> _items;

    /// <summary>Cria o store, gravando <see cref="InMemoryVaultOptions.InitialSecrets"/>.</summary>
    /// <param name="options">Opções. <c>null</c> = padrão (só permitido em Development).</param>
    /// <param name="logger">Logger (auditoria).</param>
    /// <exception cref="InvalidOperationException">Fora de Development sem <see cref="InMemoryVaultOptions.AllowOutsideDevelopment"/>.</exception>
    /// <exception cref="ArgumentException">Segredo inicial com nome ou valor inválido.</exception>
    public InMemorySecretStore(InMemoryVaultOptions? options = null, ILogger<InMemorySecretStore>? logger = null)
        : base(options, logger)
    {
        _items = new VersionedItems<Version>(Options.MaxBackups);
        foreach (var (name, value) in Options.InitialSecrets)
        {
            if (VaultInputRules.First(Rules.Name(name), Rules.SecretValue(value)) is { } error)
                throw new ArgumentException($"Segredo inicial inválido: {error.Message}", nameof(options));
            _items.Add(name, NewVersion(name, value, new SecretWriteOptions()));
        }
    }

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        Run<VaultSecret>("secret.get", name, Rules.Item(name, version), isWrite: false, () =>
        {
            lock (_items.Sync)
            {
                var item = _items.Find(name, version, v => v.Properties.Version!);
                if (item is null)
                    return VaultErrors.NotFound();
                if (!item.Properties.Enabled)
                    return VaultErrors.Disabled();
                return new VaultSecret(item.Properties, item.Value);
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        Run<bool>("secret.exists", name, Rules.Name(name), isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.Exists(name);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<SecretProperties>>("secret.list", null, null, isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.Current().Select(v => v.Properties).ToList();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<SecretProperties>>("secret.versions", name, Rules.Name(name), isWrite: false, () =>
        {
            lock (_items.Sync)
            {
                var versions = _items.Versions(name);
                return versions is null ? VaultErrors.NotFound() : versions.Select(v => v.Properties).ToList();
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SecretWriteOptions();
        var inputError = Rules.SetSecret(name, value, options, Time.GetUtcNow());

        return Run<SecretProperties>("secret.set", name, inputError, isWrite: true, () =>
        {
            lock (_items.Sync)
            {
                if (_items.IsDeleted(name))
                    return VaultErrors.Conflict();

                var version = NewVersion(name, value, options);
                _items.Add(name, version);
                return Result<SecretProperties>.Success(version.Properties);
            }
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateSecret(name, version, update, Time.GetUtcNow());

        return Run<SecretProperties>("secret.update", name, inputError, isWrite: true, () =>
        {
            lock (_items.Sync)
            {
                var current = _items.Find(name, version, v => v.Properties.Version!);
                if (current is null)
                    return VaultErrors.NotFound();

                var properties = current.Properties with
                {
                    Enabled = update.Enabled ?? current.Properties.Enabled,
                    ExpiresOn = update.ExpiresOn ?? current.Properties.ExpiresOn,
                    NotBefore = update.NotBefore ?? current.Properties.NotBefore,
                    ContentType = update.ContentType ?? current.Properties.ContentType,
                    Tags = update.Tags is null ? current.Properties.Tags : CopyTags(update.Tags),
                    UpdatedOn = Time.GetUtcNow()
                };
                _items.Replace(name, current, current with { Properties = properties });
                return Result<SecretProperties>.Success(properties);
            }
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        Run<DeletedVaultItem>("secret.delete", name, Rules.Name(name), isWrite: true, () =>
        {
            var now = Time.GetUtcNow();
            lock (_items.Sync)
            {
                return _items.Delete(name, now)
                    ? new DeletedVaultItem(name, now, now + RetentionPeriod)
                    : Result<DeletedVaultItem>.Failure(VaultErrors.NotFound());
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedSecretsAsync(CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<DeletedVaultItem>>("secret.list-deleted", null, null, isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.ListDeleted().Select(d => new DeletedVaultItem(d.Name, d.DeletedOn, d.DeletedOn + RetentionPeriod)).ToList();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> RecoverDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        Run<SecretProperties>("secret.recover", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
            {
                var versions = _items.Recover(name);
                return versions is null ? VaultErrors.NotFound() : Result<SecretProperties>.Success(versions[^1].Properties);
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> PurgeDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        RunVoid("secret.purge", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Purge(name) ? Result.Success() : Result.Failure(VaultErrors.NotFound());
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Em memória o backup é um identificador opaco, válido só nesta instância (não contém o valor).</remarks>
    public Task<Result<byte[]>> BackupSecretAsync(string name, CancellationToken cancellationToken = default) =>
        Run<byte[]>("secret.backup", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Backup(name) is { } token ? token : Result<byte[]>.Failure(VaultErrors.NotFound());
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> RestoreSecretBackupAsync(byte[] backup, CancellationToken cancellationToken = default) =>
        Run<SecretProperties>("secret.restore", null, Rules.Backup(backup), isWrite: true, () =>
        {
            lock (_items.Sync)
            {
                var versions = _items.Restore(backup, out _, out bool conflict);
                if (conflict)
                    return VaultErrors.Conflict();
                return versions is null ? VaultErrors.Rejected() : Result<SecretProperties>.Success(versions[^1].Properties);
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        RunVoid("secret.health", null, null, isWrite: false, Result.Success, cancellationToken);

    private Version NewVersion(string name, string value, SecretWriteOptions options)
    {
        var now = Time.GetUtcNow();
        string version = NewVersion();
        return new Version(new SecretProperties
        {
            Name = name,
            Version = version,
            Id = $"memoria://secrets/{name}/{version}",
            Enabled = options.Enabled,
            CreatedOn = now,
            UpdatedOn = now,
            ExpiresOn = options.ExpiresOn,
            NotBefore = options.NotBefore,
            ContentType = options.ContentType,
            Tags = CopyTags(options.Tags)
        }, value);
    }
}
