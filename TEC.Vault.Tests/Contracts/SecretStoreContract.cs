using TEC.Vault.Abstractions;
using TEC.Vault.Common;

namespace TEC.Vault.Tests.Contracts;

/// <summary>
/// Contrato de <see cref="ISecretStore"/> (leitura + gravação). Inclui o contrato de leitura: os segredos iniciais são
/// gravados pelo próprio store.
/// </summary>
[InheritsTests]
public abstract class SecretStoreContract : SecretReaderContract
{
    /// <summary>Cria o store vazio.</summary>
    protected abstract Task<ISecretStore> CreateStoreAsync();

    protected sealed override async Task<ISecretReader> CreateReaderAsync(IReadOnlyDictionary<string, string> secrets)
    {
        var store = await CreateStoreAsync();
        foreach (var (name, value) in secrets)
        {
            var set = await store.SetSecretAsync(name, value);
            if (!set.IsSuccess)
                throw new InvalidOperationException($"Falha ao gravar o segredo inicial {name}: {set.Error!.Code}");
        }

        return store;
    }

    protected sealed override async Task<bool> ChangeValueAsync(ISecretReader reader, string name, string value) =>
        (await ((ISecretStore)reader).SetSecretAsync(name, value)).IsSuccess;

    [Test]
    public async Task Writing_again_creates_new_version_and_keeps_previous()
    {
        var store = await CreateStoreAsync();
        var first = await store.SetSecretAsync("rotacao", "v1");
        var second = await store.SetSecretAsync("rotacao", "v2");

        await Assert.That(first.IsSuccess).IsTrue();
        await Assert.That(second.Value.Version).IsNotEqualTo(first.Value.Version);
        await Assert.That((await store.GetSecretAsync("rotacao")).Value.Value).IsEqualTo("v2");
        await Assert.That((await store.GetSecretAsync("rotacao", first.Value.Version)).Value.Value).IsEqualTo("v1");
        await Assert.That((await store.ListSecretVersionsAsync("rotacao")).Value.Count).IsGreaterThanOrEqualTo(2);
    }

    [Test]
    public async Task Delete_removes_secret_from_read_and_listing()
    {
        var store = await CreateStoreAsync();
        await store.SetSecretAsync("temporario", "x");

        var deleted = await store.DeleteSecretAsync("temporario");

        await Assert.That(deleted.IsSuccess).IsTrue();
        await Assert.That((await store.GetSecretAsync("temporario")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.ExistsAsync("temporario")).Value).IsFalse();
        await Assert.That((await store.ListSecretsAsync()).Value.Select(p => p.Name)).DoesNotContain("temporario");
    }

    [Test]
    public async Task Deleting_missing_returns_NotFound()
    {
        var store = await CreateStoreAsync();

        var result = await store.DeleteSecretAsync("nao-existe");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task Empty_value_is_rejected_before_reaching_vault()
    {
        var store = await CreateStoreAsync();

        var result = await store.SetSecretAsync("vazio", "");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
    }
}
