using TEC.Vault.Abstractions;
using TEC.Vault.Common;

namespace TEC.Vault.Tests.Contracts;

/// <summary>
/// Contrato de <see cref="ISecretReader"/> que todo provedor cumpre (o provedor em memória é a referência de comportamento).
/// Cada provedor herda com <c>[InheritsTests]</c> e só informa como criar o leitor com os segredos iniciais.
/// </summary>
public abstract class SecretReaderContract
{
    /// <summary>Segredos com que o leitor é criado.</summary>
    protected static readonly IReadOnlyDictionary<string, string> Seed = new Dictionary<string, string>
    {
        ["db-senha"] = "s3nh@ com espaço e acentuação ç",
        ["api-key"] = "abc123",
        ["ConnectionStrings--Db"] = "Server=local;Password=x"
    };

    /// <summary>Cria o leitor já contendo exatamente <paramref name="secrets"/>.</summary>
    protected abstract Task<ISecretReader> CreateReaderAsync(IReadOnlyDictionary<string, string> secrets);

    /// <summary>
    /// Troca o valor de um segredo existente pela fonte (o agente, o próprio store). <c>false</c>: o provedor de teste não suporta.
    /// </summary>
    protected virtual Task<bool> ChangeValueAsync(ISecretReader reader, string name, string value) => Task.FromResult(false);

    [Test]
    public async Task Reads_a_secret_value()
    {
        var reader = await CreateReaderAsync(Seed);

        var result = await reader.GetSecretAsync("db-senha");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo(Seed["db-senha"]);
        await Assert.That(result.Value.Name).IsEqualTo("db-senha");
        await Assert.That(result.Value.Version).IsNotNull();
        await Assert.That(result.Value.ToString()).DoesNotContain(Seed["db-senha"]);
    }

    [Test]
    public async Task Name_is_case_insensitive()
    {
        var reader = await CreateReaderAsync(Seed);

        var result = await reader.GetSecretAsync("API-KEY");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("abc123");
    }

    [Test]
    public async Task Missing_secret_returns_NotFound()
    {
        var reader = await CreateReaderAsync(Seed);

        var result = await reader.GetSecretAsync("nao-existe");

        await Assert.That(result.IsSuccess).IsFalse();
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    [Arguments("")]
    [Arguments("../etc/passwd")]
    [Arguments("a b")]
    [Arguments("nome\n")]
    public async Task Invalid_name_returns_InvalidInput_without_querying_source(string name)
    {
        var reader = await CreateReaderAsync(Seed);

        var result = await reader.GetSecretAsync(name);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
    }

    [Test]
    public async Task Exists_reports_presence()
    {
        var reader = await CreateReaderAsync(Seed);

        await Assert.That((await reader.ExistsAsync("api-key")).Value).IsTrue();
        await Assert.That((await reader.ExistsAsync("nao-existe")).Value).IsFalse();
    }

    [Test]
    public async Task Lists_secrets_with_version_and_without_values()
    {
        var reader = await CreateReaderAsync(Seed);

        var result = await reader.ListSecretsAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        var names = result.Value.Select(p => p.Name).Order(StringComparer.OrdinalIgnoreCase).ToList();
        await Assert.That(names).IsEquivalentTo(Seed.Keys.Order(StringComparer.OrdinalIgnoreCase).ToList());
        foreach (var properties in result.Value)
        {
            await Assert.That(properties.Version).IsNotNull();
            await Assert.That(properties.Enabled).IsTrue();
            await Assert.That(properties.ToString()).DoesNotContain(Seed[properties.Name]);
        }
    }

    [Test]
    public async Task Listed_version_can_be_read_and_unknown_version_returns_NotFound()
    {
        var reader = await CreateReaderAsync(Seed);
        var current = (await reader.ListSecretVersionsAsync("api-key")).Value.Last(v => v.Enabled);

        var byVersion = await reader.GetSecretAsync("api-key", current.Version);
        var latest = await reader.GetSecretAsync("api-key");

        await Assert.That(byVersion.IsSuccess).IsTrue();
        await Assert.That(byVersion.Value.Value).IsEqualTo("abc123");
        await Assert.That(latest.Value.Version).IsEqualTo(current.Version);
        var unknown = await reader.GetSecretAsync("api-key", UnknownVersion(current.Version!));
        await Assert.That(unknown.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    /// <summary>Uma versão válida no formato do provedor que não existe. Padrão: 32 hexadecimais diferentes.</summary>
    protected virtual string UnknownVersion(string existing) =>
        string.Equals(existing, "0123456789abcdef0123456789abcdef", StringComparison.OrdinalIgnoreCase)
            ? "fedcba9876543210fedcba9876543210"
            : "0123456789abcdef0123456789abcdef";

    [Test]
    public async Task Versions_of_missing_secret_return_NotFound()
    {
        var reader = await CreateReaderAsync(Seed);

        var result = await reader.ListSecretVersionsAsync("nao-existe");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task Version_changes_when_value_changes()
    {
        var reader = await CreateReaderAsync(Seed);
        var before = (await reader.GetSecretAsync("api-key")).Value.Version;

        if (!await ChangeValueAsync(reader, "api-key", "novo-valor"))
            return;

        var after = await reader.GetSecretAsync("api-key");
        await Assert.That(after.Value.Value).IsEqualTo("novo-valor");
        await Assert.That(after.Value.Version).IsNotEqualTo(before);
    }

    [Test]
    public async Task Empty_source_lists_nothing()
    {
        var reader = await CreateReaderAsync(new Dictionary<string, string>());

        var result = await reader.ListSecretsAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value).IsEmpty();
    }

    [Test]
    public async Task Health_probe_responds_healthy()
    {
        var reader = await CreateReaderAsync(Seed);
        if (reader is not IVaultHealthProbe probe)
            return;

        await Assert.That((await probe.CheckAccessAsync()).IsSuccess).IsTrue();
    }
}
