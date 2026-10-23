using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.DependencyInjection;
using TEC.Vault.InMemory;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Regras compartilhadas pelos provedores (uma única implementação para Azure Key Vault e memória).</summary>
public class ProviderRulesTests
{
    [Test]
    public async Task Providers_use_same_rules_with_own_limits()
    {
        var azure = AzureKeyVaultStoreBase.Rules;
        var memory = InMemoryStoreBase.Rules;

        await Assert.That(azure.MaxTags).IsEqualTo(15);
        await Assert.That(memory.MaxTags).IsEqualTo(50);
        await Assert.That(azure.MaxSecretValueBytes).IsEqualTo(25 * 1024);
        await Assert.That(memory.MaxSecretValueBytes).IsEqualTo(InMemorySecretStore.MaxSecretValueBytes);
        await Assert.That(azure.Name("nome_com_underscore")!.Field).IsEqualTo("name");   // só o provedor em memória aceita "_"
        await Assert.That(memory.Name("nome_com_underscore")).IsNull();
        await Assert.That(azure.VersionPattern).IsSameReferenceAs(memory.VersionPattern);
    }

    [Test]
    public async Task Operation_rules_return_first_error_in_field_order()
    {
        var rules = AzureKeyVaultStoreBase.Rules;
        var now = DateTimeOffset.UtcNow;

        await Assert.That(rules.SetSecret("ok", "v", new SecretWriteOptions(), now)).IsNull();
        await Assert.That(rules.SetSecret("a b", "", new SecretWriteOptions(), now)!.Field).IsEqualTo("name");
        await Assert.That(rules.SetSecret("ok", "", new SecretWriteOptions(), now)!.Field).IsEqualTo("value");
        await Assert.That(rules.SetSecret("ok", "v", new SecretWriteOptions { ContentType = new string('x', 256) }, now)!.Field).IsEqualTo("contentType");
        await Assert.That(rules.UpdateSecret("ok", null, new SecretPropertiesUpdate { ExpiresOn = now.AddDays(-1) }, now)).IsNull();
        await Assert.That(rules.CreateKey("ok", new CreateKeyOptions { KeySize = 1024 }, now)!.Field).IsEqualTo("keySize");
        await Assert.That(rules.UpdateKey("ok", "xyz", new KeyPropertiesUpdate(), now)!.Field).IsEqualTo("version");
        await Assert.That(rules.Encrypt("ok", null, VaultEncryptionAlgorithm.RsaOaep256, new byte[VaultKeyRules.MaxEncryptBytes + 1], "plaintext")!.Field).IsEqualTo("plaintext");
        await Assert.That(rules.Decrypt("ok", null, VaultEncryptionAlgorithm.RsaOaep256, new byte[16], "ciphertext")!.Field).IsEqualTo("version");
        await Assert.That(rules.Decrypt("ok", FakeKeyVault.Version, VaultEncryptionAlgorithm.RsaOaep256, new byte[VaultKeyRules.MaxCiphertextBytes + 1], "wrappedKey")!.Field).IsEqualTo("wrappedKey");
        await Assert.That(rules.Sign("ok", null, (VaultSignatureAlgorithm)999, new byte[1])!.Field).IsEqualTo("algorithm");
        await Assert.That(rules.Verify("ok", FakeKeyVault.Version, VaultSignatureAlgorithm.PS256, new byte[1], [])!.Field).IsEqualTo("signature");
        await Assert.That(rules.ImportCertificate("a b", [1, 2, 3], new(), out _, out _)!.Field).IsEqualTo("name");
        await Assert.That(rules.ImportCertificate("ok", [1, 2, 3], new(), out _, out _)!.Field).IsEqualTo("certificate");
    }

    [Test]
    public async Task Signature_algorithms_map_hash_padding_and_curve()
    {
        await Assert.That(VaultKeyRules.RsaSignature(VaultSignatureAlgorithm.RS384)!.Value.Hash).IsEqualTo(HashAlgorithmName.SHA384);
        await Assert.That(VaultKeyRules.RsaSignature(VaultSignatureAlgorithm.PS512)!.Value.Padding).IsEqualTo(RSASignaturePadding.Pss);
        await Assert.That(VaultKeyRules.RsaSignature(VaultSignatureAlgorithm.ES256)).IsNull();
        await Assert.That(VaultKeyRules.EcSignature(VaultSignatureAlgorithm.ES512)!.Value.Curve).IsEqualTo(VaultKeyCurve.P521);
        await Assert.That(VaultKeyRules.EcSignature(VaultSignatureAlgorithm.ES512)!.Value.Hash).IsEqualTo(HashAlgorithmName.SHA512);
        await Assert.That(VaultKeyRules.EcSignature(VaultSignatureAlgorithm.RS256)).IsNull();
        await Assert.That(VaultKeyRules.CurveHash(VaultKeyCurve.P384)).IsEqualTo(HashAlgorithmName.SHA384);
        await Assert.That(VaultKeyRules.ToECCurve(VaultKeyCurve.P256).Oid.Value).IsEqualTo(ECCurve.NamedCurves.nistP256.Oid.Value);
    }

    [Test]
    public async Task Current_version_is_newest_created_and_tie_is_broken_by_update_and_version()
    {
        var t = DateTimeOffset.UnixEpoch;
        var versions = new[]
        {
            new SecretProperties { Name = "x", Version = "a", CreatedOn = t, UpdatedOn = t.AddHours(5) },
            new SecretProperties { Name = "x", Version = "b", CreatedOn = t.AddSeconds(1), UpdatedOn = t.AddSeconds(1) },
            new SecretProperties { Name = "x", Version = "c", CreatedOn = t.AddSeconds(1), UpdatedOn = t.AddSeconds(2) },
            new SecretProperties { Name = "x", Version = "d", CreatedOn = t.AddSeconds(1), UpdatedOn = t.AddSeconds(2) }
        };

        var newest = VaultVersionRules.Newest(versions, p => p.CreatedOn);

        await Assert.That(newest.Select(p => p.Version!)).IsEquivalentTo(new[] { "b", "c", "d" });
        await Assert.That(VaultVersionRules.BreakTie(newest, p => p.UpdatedOn, p => p.Version).Version).IsEqualTo("d");
        await Assert.That(VaultVersionRules.Newest(Array.Empty<SecretProperties>(), p => p.CreatedOn)).IsEmpty();
    }

    [Test]
    public async Task UseStores_registers_only_chosen_families_and_rejects_invalid_value()
    {
        var services = new ServiceCollection();
        services.AddTecVault(c => c.UseStores(VaultStores.Secrets | VaultStores.Certificates,
            _ => Memory.Secrets(), _ => Memory.Keys(), _ => Memory.Certificates()));
        using var provider = services.BuildServiceProvider();

        await Assert.That(provider.GetService<ISecretStore>()).IsNotNull();
        await Assert.That(provider.GetService<ICertificateStore>()).IsNotNull();
        await Assert.That(provider.GetService<IKeyStore>()).IsNull();
        await Assert.That(() => VaultBuilder.EnsureValidStores(VaultStores.None, "Opcoes.Stores")).Throws<InvalidOperationException>();
        await Assert.That(() => VaultBuilder.EnsureValidStores((VaultStores)8, "Opcoes.Stores")).Throws<InvalidOperationException>();
        await Assert.That(() => VaultBuilder.EnsureValidStores(VaultStores.Keys, "Opcoes.Stores")).ThrowsNothing();
        await Assert.That(() => new ServiceCollection().AddTecVault(c => c.UseInMemory(o => { o.AllowOutsideDevelopment = true; o.Stores = VaultStores.None; })))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Development_environment_comes_from_registered_IHostEnvironment()
    {
        var services = new ServiceCollection();
        await Assert.That(VaultEnvironment.FindHostEnvironment(services)).IsNull();

        var environment = new EnvironmentStub("Development");
        services.AddSingleton<Microsoft.Extensions.Hosting.IHostEnvironment>(environment);

        await Assert.That(VaultEnvironment.FindHostEnvironment(services)).IsSameReferenceAs(environment);
        await Assert.That(VaultEnvironment.IsDevelopment(environment)).IsTrue();
        await Assert.That(VaultEnvironment.IsDevelopment(new EnvironmentStub("Production"))).IsFalse();
    }

    [Test]
    [Arguments("Development", null, true)]
    [Arguments(null, "Development", true)]
    [Arguments("", "Development", true)]
    [Arguments("Production", "Development", false)]   // DOTNET_ENVIRONMENT esquecida não vence a ASPNETCORE_ENVIRONMENT
    [Arguments("Development", "Production", true)]
    [Arguments("Staging", null, false)]
    [Arguments(null, null, false)]
    public async Task Without_IHostEnvironment_ASPNETCORE_ENVIRONMENT_takes_precedence(string? aspnetcore, string? dotnet, bool expected)
    {
        string? Variable(string name) => name switch
        {
            "ASPNETCORE_ENVIRONMENT" => aspnetcore,
            "DOTNET_ENVIRONMENT" => dotnet,
            _ => null
        };

        await Assert.That(VaultEnvironment.IsDevelopment(null, Variable)).IsEqualTo(expected);
    }

    private sealed class EnvironmentStub(string name) : Microsoft.Extensions.Hosting.IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "testes";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }
}
