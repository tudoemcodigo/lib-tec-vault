using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.HashiCorpVault.Internal;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.HashiCorpVault;

/// <summary>
/// Segredos no KV v2 do HashiCorp Vault: um item por segredo em <c>{Kv.Mount}/data/{Kv.BasePath}/{nome}</c>, com o valor no
/// campo <c>Kv.ValueField</c>. Implementa leitura, gravação e lixeira.
/// </summary>
/// <remarks>
/// <para><b>Versões</b>: as do KV (inteiros). <b>Tags</b>: <c>custom_metadata</c> (valem para o segredo, não por versão).
/// Tipo de conteúdo, habilitar/desabilitar e validade não existem no KV: pedi-los retorna <see cref="VaultErrors.InvalidInput"/>.</para>
/// <para><b>Lixeira</b>: excluir faz a exclusão lógica de todas as versões ativas; recuperar desfaz a exclusão das versões excluídas
/// (inclusive as excluídas antes, individualmente, por outra ferramenta); remover definitivamente apaga os metadados e todas
/// as versões. Enquanto está na lixeira, gravar com o mesmo nome retorna <see cref="VaultErrors.Conflict"/>.</para>
/// <para><b>Nomes</b>: o KV diferencia maiúsculas; o TEC.Vault não (um único nome igual sem diferenciar maiúsculas é usado; dois →
/// <see cref="VaultErrors.Conflict"/>). Itens sem o campo do valor são tratados como formato inesperado (<see cref="VaultErrors.ProviderFailure"/>).</para>
/// <para>A listagem lê os metadados de cada segredo (uma chamada por item, até 8 em paralelo): mantenha uma pasta por aplicação.</para>
/// </remarks>
public sealed class HashiCorpVaultSecretStore : HashiCorpVaultStoreBase, ISecretStore, ISecretRecycleBin, IVaultHealthProbe
{
    private const int MaxParallelMetadata = 8;

    /// <summary>Cria o store com conexão própria. As opções são validadas aqui.</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public HashiCorpVaultSecretStore(HashiCorpVaultOptions options, ILogger<HashiCorpVaultSecretStore>? logger = null)
        : this(new HashiCorpVaultClient(options), ownsClient: true, logger)
    {
    }

    internal HashiCorpVaultSecretStore(HashiCorpVaultClient client, bool ownsClient, ILogger<HashiCorpVaultSecretStore>? logger)
        : base(client, ownsClient, logger)
    {
    }

    private KvFolder Kv => Client.Secrets;

    private string ValueField => Client.Options.Kv.ValueField;

    /// <inheritdoc />
    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is null || (!metadata.Exists && version is null))
                return VaultErrors.NotFound();

            var item = await Kv.ReadAsync(metadata.Name, ParseVersion(version), ct).ConfigureAwait(false);
            if (item is not { } read)
                return VaultErrors.NotFound();
            if (!read.Fields.TryGetValue(ValueField, out var value))
                throw new System.Text.Json.JsonException("Item do KV sem o campo do valor.");

            return Result<VaultSecret>.Success(new VaultSecret(Properties(metadata, read.Version, read.CreatedOn), value));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.exists", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            return ambiguous ? VaultErrors.Conflict() : Result<bool>.Success(metadata is { Exists: true });
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<SecretProperties>>("secret.list", null, null, isWrite: false, async ct =>
            (await AllMetadataAsync(ct).ConfigureAwait(false))
                .Where(m => m.Exists)
                .Select(m => Properties(m, m.CurrentVersion, m.Current?.CreatedOn))
                .ToList(), cancellationToken);

    /// <inheritdoc />
    /// <remarks>Versões excluídas aparecem com <c>Enabled = false</c>; destruídas não aparecem.</remarks>
    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is null || metadata.IsDeleted)
                return VaultErrors.NotFound();

            EnsureListLimit(metadata.Versions.Count(v => !v.Destroyed), Client.Options.MaxListItems);
            return Result<IReadOnlyList<SecretProperties>>.Success(metadata.Versions
                .Where(v => !v.Destroyed)
                .Select(v => Properties(metadata, v.Version, v.CreatedOn) with { Enabled = v.DeletedOn is null })
                .ToList());
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        options ??= new SecretWriteOptions();
        var inputError = Rules.SetSecret(name, value, options, Time.GetUtcNow()) ??
            (options.ContentType is not null || !options.Enabled || options.ExpiresOn is not null || options.NotBefore is not null
                ? VaultErrors.InvalidInput("options", "O KV do Vault não tem tipo de conteúdo, habilitar/desabilitar nem validade: informe só valor e tags.")
                : null);

        return ExecuteAsync("secret.set", name, inputError, isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous || metadata is { IsDeleted: true })
                return VaultErrors.Conflict();

            var target = metadata?.Name ?? name;
            var written = await Kv.WriteAsync(target, new Dictionary<string, string> { [ValueField] = value }, ct).ConfigureAwait(false);
            if (options.Tags is not null)
                await Kv.SetCustomMetadataAsync(target, options.Tags, ct).ConfigureAwait(false);

            var custom = options.Tags is not null ? new Dictionary<string, string>(options.Tags) : metadata?.Custom ?? [];
            return Result<SecretProperties>.Success(new SecretProperties
            {
                Name = target,
                Version = Text(written.Version),
                Id = Kv.Id(target),
                Enabled = true,
                CreatedOn = written.CreatedOn,
                UpdatedOn = written.CreatedOn,
                Tags = custom
            });
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>Só <see cref="SecretPropertiesUpdate.Tags"/> é suportado (vale para o segredo, qualquer que seja a versão).</remarks>
    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateSecret(name, version, update, Time.GetUtcNow()) ??
            (update.Enabled is not null || update.ExpiresOn is not null || update.NotBefore is not null || update.ContentType is not null
                ? VaultErrors.InvalidInput("update", "O KV do Vault só permite alterar as tags.")
                : null);

        return ExecuteAsync("secret.update", name, inputError, isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is not { Exists: true })
                return VaultErrors.NotFound();

            var number = ParseVersion(version) ?? metadata.CurrentVersion;
            if (metadata.Versions.FirstOrDefault(v => v.Version == number) is not { Alive: true } target)
                return VaultErrors.NotFound();

            var custom = metadata.Custom;
            if (update.Tags is not null)
            {
                await Kv.SetCustomMetadataAsync(metadata.Name, update.Tags, ct).ConfigureAwait(false);
                custom = new Dictionary<string, string>(update.Tags);
            }

            return Result<SecretProperties>.Success(Properties(metadata with { Custom = custom }, target.Version, target.CreatedOn));
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is null || metadata.IsDeleted || !metadata.Versions.Any(v => v.Alive))
                return VaultErrors.NotFound();

            await Kv.DeleteVersionsAsync(metadata.Name, metadata.Versions.Where(v => v.Alive).Select(v => v.Version), ct).ConfigureAwait(false);
            return Result<DeletedVaultItem>.Success(new DeletedVaultItem(metadata.Name, Time.GetUtcNow(), ScheduledPurgeDate: null));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedSecretsAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<DeletedVaultItem>>("secret.list-deleted", null, null, isWrite: false, async ct =>
            (await AllMetadataAsync(ct).ConfigureAwait(false))
                .Where(m => m.IsDeleted)
                .Select(m => new DeletedVaultItem(m.Name, m.Versions.Max(v => v.DeletedOn), ScheduledPurgeDate: null))
                .ToList(), cancellationToken);

    /// <inheritdoc />
    public Task<Result<SecretProperties>> RecoverDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("secret.recover", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is not { IsDeleted: true })
                return VaultErrors.NotFound();

            var recovered = metadata.Versions.Where(v => v.DeletedOn is not null && !v.Destroyed).ToList();
            await Kv.UndeleteAsync(metadata.Name, recovered.Select(v => v.Version), ct).ConfigureAwait(false);
            var current = recovered.Max(v => v.Version);
            return Result<SecretProperties>.Success(Properties(metadata, current, recovered.First(v => v.Version == current).CreatedOn));
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Só remove segredos que estão na lixeira. <b>Irreversível.</b></remarks>
    public Task<Result> PurgeDeletedSecretAsync(string name, CancellationToken cancellationToken = default) =>
        RunAsync("secret.purge", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var (metadata, ambiguous) = await Kv.ResolveAsync(name, ct).ConfigureAwait(false);
            if (ambiguous)
                return VaultErrors.Conflict();
            if (metadata is not { IsDeleted: true })
                return VaultErrors.NotFound();

            await Kv.DestroyAsync(metadata.Name, ct).ConfigureAwait(false);
            return Result.Success();
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Lista a pasta dos segredos (exige a permissão <c>list</c> nos metadados do KV).</remarks>
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        RunAsync("secret.health", null, null, isWrite: false, async ct =>
        {
            await Kv.ListAsync(ct).ConfigureAwait(false);
            return Result.Success();
        }, cancellationToken);

    private async Task<List<KvMetadata>> AllMetadataAsync(CancellationToken ct)
    {
        var names = await Kv.ListAsync(ct).ConfigureAwait(false);
        EnsureListLimit(names.Count, Client.Options.MaxListItems);   // antes de ler os metadados de cada item
        var result = new KvMetadata?[names.Count];
        await Parallel.ForEachAsync(Enumerable.Range(0, names.Count),
            new ParallelOptions { MaxDegreeOfParallelism = MaxParallelMetadata, CancellationToken = ct },
            async (i, token) => result[i] = await Kv.MetadataAsync(names[i], token).ConfigureAwait(false)).ConfigureAwait(false);
        return result.Where(m => m is not null).Select(m => m!).ToList();
    }

    private SecretProperties Properties(KvMetadata metadata, int version, DateTimeOffset? createdOn) => new()
    {
        Name = metadata.Name,
        Version = Text(version),
        Id = Kv.Id(metadata.Name),
        Enabled = true,
        CreatedOn = createdOn,
        UpdatedOn = metadata.UpdatedOn ?? createdOn,
        Tags = metadata.Custom
    };
}
