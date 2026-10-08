using System.Security.Cryptography;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using TEC.Vault.Abstractions;
using TEC.Vault.HashiCorpVault;
using TEC.Vault.Keys;
using TEC.Vault.Tests.Contracts;

namespace TEC.Vault.Tests.Integration;

/// <summary>
/// HashiCorp Vault real para os testes de integração (no CI: <c>vault server -dev</c> com Transit e PKI montados por
/// <c>.github/scripts/vault-dev.sh</c>, preparado por <c>.github/scripts/integration-setup.sh</c>). Configuração:
/// <c>TEC_TESTES_HASHICORP_ADDR</c> e <c>TEC_TESTES_HASHICORP_TOKEN</c> (ou user-secrets <c>TecTestes:HashiCorpAddr</c>/
/// <c>TecTestes:HashiCorpToken</c>); <c>TEC_TESTES_HASHICORP_PKI_ROLE</c> só para o teste do PKI. Sem endereço ou token, os
/// testes se pulam com o motivo.
/// </summary>
internal static class HashiCorpVaultFixture
{
    public const string AddressVariable = "TEC_TESTES_HASHICORP_ADDR";
    public const string TokenVariable = "TEC_TESTES_HASHICORP_TOKEN";
    public const string PkiRoleVariable = "TEC_TESTES_HASHICORP_PKI_ROLE";

    private static readonly string? Address = TestSettings.Read(AddressVariable, "HashiCorpAddr");

    private static readonly string? Token = TestSettings.Read(TokenVariable, "HashiCorpToken");

    public static HashiCorpVaultOptions Options(string basePath)
    {
        if (Address is null || Token is null)
            Skip.Test($"HashiCorp Vault de testes não configurado: defina {AddressVariable} e {TokenVariable}.");

        if (Environment.GetEnvironmentVariable(TokenVariable) is null)
            Environment.SetEnvironmentVariable(TokenVariable, Token);   // lido pelo provedor por variável (método Token)

        var options = new HashiCorpVaultOptions { Address = new Uri(Address!), HostEnvironment = new DevelopmentEnvironment() };
        options.Auth.Method = HashiCorpVaultAuthMethod.Token;
        options.Auth.TokenVariable = TokenVariable;
        options.Kv.BasePath = basePath;
        options.Pki.Role = TestSettings.Read(PkiRoleVariable, "HashiCorpPkiRole");
        return options;
    }

    public static string NewPath() => "tec-testes/" + Guid.NewGuid().ToString("N")[..12];

    /// <summary>O servidor de desenvolvimento fala HTTP em localhost: liberado só em Development.</summary>
    private sealed class DevelopmentEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "TEC.Vault.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}

[Category(TestCategories.Integration)]
[InheritsTests]
public class HashiCorpVaultLiveSecretContractTests : SecretStoreContract, IAsyncDisposable
{
    private HashiCorpVaultSecretStore? _store;

    protected override Task<ISecretStore> CreateStoreAsync()
    {
        _store = new HashiCorpVaultSecretStore(HashiCorpVaultFixture.Options(HashiCorpVaultFixture.NewPath()));
        return Task.FromResult<ISecretStore>(_store);
    }

    protected override string UnknownVersion(string existing) => "999";

    public async ValueTask DisposeAsync()
    {
        if (_store is null)
            return;
        // Limpeza: tudo o que o teste criou na pasta própria dele
        foreach (var secret in (await _store.ListSecretsAsync()).Value ?? [])
            await _store.DeleteSecretAsync(secret.Name);
        foreach (var deleted in (await _store.ListDeletedSecretsAsync()).Value ?? [])
            await _store.PurgeDeletedSecretAsync(deleted.Name);
        _store.Dispose();
        GC.SuppressFinalize(this);
    }
}

[Category(TestCategories.Integration)]
[InheritsTests]
public class HashiCorpVaultLiveCertificateContractTests : CertificateStoreContract, IAsyncDisposable
{
    private HashiCorpVaultCertificateStore? _store;

    protected override string? SelfSignedIssuer => HashiCorpVaultCertificateStore.SelfIssuer;

    protected override Task<ICertificateStore> CreateStoreAsync()
    {
        _store = new HashiCorpVaultCertificateStore(HashiCorpVaultFixture.Options(HashiCorpVaultFixture.NewPath()));
        return Task.FromResult<ICertificateStore>(_store);
    }

    public async ValueTask DisposeAsync()
    {
        if (_store is null)
            return;
        foreach (var certificate in (await _store.ListCertificatesAsync()).Value ?? [])
            await _store.DeleteCertificateAsync(certificate.Name);
        foreach (var deleted in (await _store.ListDeletedCertificatesAsync()).Value ?? [])
            await _store.PurgeDeletedCertificateAsync(deleted.Name);
        _store.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>Transit real: nomes únicos por teste (o mount é compartilhado), sempre excluídos no fim.</summary>
[Category(TestCategories.Integration)]
public class HashiCorpVaultLiveKeyTests
{
    [Test]
    public async Task Rsa_encrypts_decrypts_and_signs_on_real_transit()
    {
        using var store = new HashiCorpVaultKeyStore(HashiCorpVaultFixture.Options(HashiCorpVaultFixture.NewPath()));
        var name = "tec-teste-rsa-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            var key = await store.CreateKeyAsync(name, new CreateKeyOptions { KeySize = 2048 });
            await Assert.That(key.IsSuccess).IsTrue();

            var encrypted = await store.EncryptAsync(name, [1, 2, 3]);
            var decrypted = await store.DecryptAsync(name, encrypted.Value.KeyVersion, encrypted.Value.Ciphertext);
            await Assert.That(decrypted.Value).IsEquivalentTo(new byte[] { 1, 2, 3 });

            var data = "documento"u8.ToArray();
            var signed = await store.SignDataAsync(name, data, VaultSignatureAlgorithm.PS256);
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(key.Value.PublicKeySpki, out _);
            await Assert.That(rsa.VerifyData(data, signed.Value.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).IsTrue();

            // Encrypt com nome inexistente não pode criar chave (upsert do Transit)
            var missing = "tec-teste-nao-existe-" + Guid.NewGuid().ToString("N")[..8];
            await Assert.That((await store.EncryptAsync(missing, [1])).IsSuccess).IsFalse();
            await Assert.That((await store.GetKeyAsync(missing)).IsSuccess).IsFalse();
        }
        finally
        {
            await store.DeleteKeyAsync(name);
        }
    }

    [Test]
    public async Task Ecdsa_signs_in_p1363_verifiable_locally()
    {
        using var store = new HashiCorpVaultKeyStore(HashiCorpVaultFixture.Options(HashiCorpVaultFixture.NewPath()));
        var name = "tec-teste-ec-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            var key = await store.CreateKeyAsync(name, new CreateKeyOptions { KeyType = VaultKeyType.Ec, Curve = VaultKeyCurve.P256 });
            var data = "documento"u8.ToArray();

            var signed = await store.SignDataAsync(name, data, VaultSignatureAlgorithm.ES256);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(key.Value.PublicKeySpki, out _);
            await Assert.That(ecdsa.VerifyData(data, signed.Value.Signature, HashAlgorithmName.SHA256)).IsTrue();
            await Assert.That((await store.VerifyDataAsync(name, signed.Value.KeyVersion, data, signed.Value.Signature, VaultSignatureAlgorithm.ES256)).Value).IsTrue();
        }
        finally
        {
            await store.DeleteKeyAsync(name);
        }
    }
}

/// <summary>PKI e lixeira do KV no Vault real.</summary>
[Category(TestCategories.Integration)]
public class HashiCorpVaultLivePkiAndRecycleBinTests
{
    [Test]
    public async Task Certificate_issued_by_real_pki_from_csr()
    {
        var options = HashiCorpVaultFixture.Options(HashiCorpVaultFixture.NewPath());
        Skip.When(options.Pki.Role is null, $"Defina {HashiCorpVaultFixture.PkiRoleVariable} para testar o PKI.");
        using var store = new HashiCorpVaultCertificateStore(options);

        var created = await store.CreateCertificateAsync("api", new TEC.Vault.Certificates.CreateCertificateOptions
        {
            Subject = "CN=api.tec.teste",
            DnsNames = ["api.tec.teste"],
            KeyType = VaultKeyType.Ec,
            Curve = VaultKeyCurve.P256,
            Exportable = true,
            ValidityInMonths = 1
        });
        using var downloaded = (await store.DownloadCertificateAsync("api")).Value;

        await Assert.That(created.IsSuccess).IsTrue();
        await Assert.That(downloaded.Issuer).IsEqualTo("CN=TEC Testes CA");
        await Assert.That(downloaded.HasPrivateKey).IsTrue();
        await store.DeleteCertificateAsync("api");
        await store.PurgeDeletedCertificateAsync("api");
    }

    [Test]
    public async Task Real_kv_recycle_bin()
    {
        using var store = new HashiCorpVaultSecretStore(HashiCorpVaultFixture.Options(HashiCorpVaultFixture.NewPath()));
        await store.SetSecretAsync("db", "v1");
        await store.SetSecretAsync("db", "v2");

        await store.DeleteSecretAsync("db");
        var conflict = await store.SetSecretAsync("db", "v3");
        var deleted = await store.ListDeletedSecretsAsync();
        var recovered = await store.RecoverDeletedSecretAsync("db");
        var value = await store.GetSecretAsync("db");
        await store.DeleteSecretAsync("db");
        var purged = await store.PurgeDeletedSecretAsync("db");

        await Assert.That(conflict.Error!.Code).IsEqualTo(TEC.Vault.Common.VaultErrors.ConflictCode);
        await Assert.That(deleted.Value.Select(d => d.Name)).IsEquivalentTo(["db"]);
        await Assert.That(recovered.Value.Version).IsEqualTo("2");
        await Assert.That(value.Value.Value).IsEqualTo("v2");
        await Assert.That(purged.IsSuccess).IsTrue();
        await Assert.That((await store.ListDeletedSecretsAsync()).Value).IsEmpty();
    }
}
