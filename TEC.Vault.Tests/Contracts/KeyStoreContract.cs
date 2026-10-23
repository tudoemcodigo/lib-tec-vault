using System.Security.Cryptography;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Keys;

namespace TEC.Vault.Tests.Contracts;

/// <summary>
/// Contrato de chaves (<see cref="IKeyStore"/> + <see cref="IKeyCryptography"/>): criação, versões, criptografia, wrap e
/// assinatura com verificação local pela chave pública. O provedor em memória é a referência.
/// </summary>
public abstract class KeyStoreContract
{
    /// <summary>Cria o store vazio (implementa <see cref="IKeyStore"/> e <see cref="IKeyCryptography"/>).</summary>
    protected abstract Task<IKeyStore> CreateStoreAsync();

    private async Task<(IKeyStore Store, IKeyCryptography Crypto)> CreateAsync()
    {
        var store = await CreateStoreAsync();
        return (store, (IKeyCryptography)store);
    }

    [Test]
    public async Task Creates_rsa_key_with_public_key()
    {
        var (store, _) = await CreateAsync();

        var created = await store.CreateKeyAsync("rsa", new CreateKeyOptions { KeyType = VaultKeyType.Rsa, KeySize = 2048 });
        var read = await store.GetKeyAsync("rsa");

        await Assert.That(created.IsSuccess).IsTrue();
        await Assert.That(read.Value.KeyType).IsEqualTo(VaultKeyType.Rsa);
        await Assert.That(read.Value.KeySize).IsEqualTo(2048);
        await Assert.That(read.Value.Version).IsEqualTo(created.Value.Version);
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(read.Value.PublicKeySpki, out _);
        await Assert.That(rsa.KeySize).IsEqualTo(2048);
    }

    [Test]
    public async Task Encrypts_and_decrypts_with_rsa_oaep_256_and_result_matches_public_key()
    {
        var (store, crypto) = await CreateAsync();
        var key = (await store.CreateKeyAsync("rsa", new CreateKeyOptions { KeySize = 2048 })).Value;
        var plaintext = "dados sensíveis"u8.ToArray();

        var encrypted = await crypto.EncryptAsync("rsa", plaintext);
        var decrypted = await crypto.DecryptAsync("rsa", encrypted.Value.KeyVersion, encrypted.Value.Ciphertext);

        await Assert.That(encrypted.Value.KeyVersion).IsEqualTo(key.Version);
        await Assert.That(decrypted.Value).IsEquivalentTo(plaintext);
    }

    [Test]
    public async Task Wrap_and_unwrap_of_symmetric_key()
    {
        var (store, crypto) = await CreateAsync();
        await store.CreateKeyAsync("kek", new CreateKeyOptions { KeySize = 2048 });
        var dek = RandomNumberGenerator.GetBytes(32);

        var wrapped = await crypto.WrapKeyAsync("kek", dek);
        var unwrapped = await crypto.UnwrapKeyAsync("kek", wrapped.Value.KeyVersion, wrapped.Value.Ciphertext);

        await Assert.That(unwrapped.Value).IsEquivalentTo(dek);
    }

    [Test]
    [Arguments(VaultSignatureAlgorithm.RS256)]
    [Arguments(VaultSignatureAlgorithm.PS256)]
    [Arguments(VaultSignatureAlgorithm.RS512)]
    public async Task Rsa_signature_is_verifiable_locally_and_by_vault(VaultSignatureAlgorithm algorithm)
    {
        var (store, crypto) = await CreateAsync();
        var key = (await store.CreateKeyAsync("assina", new CreateKeyOptions { KeySize = 2048 })).Value;
        var data = "documento"u8.ToArray();

        var signed = await crypto.SignDataAsync("assina", data, algorithm);

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(key.PublicKeySpki, out _);
        var (hash, padding) = Providers.VaultKeyRules.RsaSignature(algorithm)!.Value;
        await Assert.That(rsa.VerifyData(data, signed.Value.Signature, hash, padding)).IsTrue();
        await Assert.That((await crypto.VerifyDataAsync("assina", signed.Value.KeyVersion, data, signed.Value.Signature, algorithm)).Value).IsTrue();
        await Assert.That((await crypto.VerifyDataAsync("assina", signed.Value.KeyVersion, "outro"u8.ToArray(), signed.Value.Signature, algorithm)).Value).IsFalse();
    }

    [Test]
    [Arguments(VaultKeyCurve.P256, VaultSignatureAlgorithm.ES256)]
    [Arguments(VaultKeyCurve.P384, VaultSignatureAlgorithm.ES384)]
    public async Task Ecdsa_signature_in_p1363_is_verifiable_locally(VaultKeyCurve curve, VaultSignatureAlgorithm algorithm)
    {
        var (store, crypto) = await CreateAsync();
        var key = (await store.CreateKeyAsync("ec", new CreateKeyOptions { KeyType = VaultKeyType.Ec, Curve = curve })).Value;
        var data = "documento"u8.ToArray();

        var signed = await crypto.SignDataAsync("ec", data, algorithm);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(key.PublicKeySpki, out _);
        await Assert.That(ecdsa.VerifyData(data, signed.Value.Signature, Providers.VaultKeyRules.CurveHash(curve))).IsTrue();
        await Assert.That((await crypto.VerifyDataAsync("ec", signed.Value.KeyVersion, data, signed.Value.Signature, algorithm)).Value).IsTrue();
    }

    [Test]
    public async Task Algorithm_not_matching_key_is_rejected()
    {
        var (store, crypto) = await CreateAsync();
        await store.CreateKeyAsync("ec", new CreateKeyOptions { KeyType = VaultKeyType.Ec, Curve = VaultKeyCurve.P256 });
        await store.CreateKeyAsync("rsa", new CreateKeyOptions { KeySize = 2048 });

        var wrongCurve = await crypto.SignDataAsync("ec", [1, 2, 3], VaultSignatureAlgorithm.ES384);
        var rsaOnEc = await crypto.SignDataAsync("ec", [1, 2, 3], VaultSignatureAlgorithm.RS256);
        var ecOnRsa = await crypto.SignDataAsync("rsa", [1, 2, 3], VaultSignatureAlgorithm.ES256);
        var encryptEc = await crypto.EncryptAsync("ec", [1, 2, 3]);

        await Assert.That(wrongCurve.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
        await Assert.That(rsaOnEc.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
        await Assert.That(ecOnRsa.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
        await Assert.That(encryptEc.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
    }

    [Test]
    public async Task Rotation_creates_new_version_and_previous_still_decrypts()
    {
        var (store, crypto) = await CreateAsync();
        var first = (await store.CreateKeyAsync("rot", new CreateKeyOptions { KeySize = 2048 })).Value;
        var old = await crypto.EncryptAsync("rot", [9, 9, 9]);

        var rotated = await store.RotateKeyAsync("rot");
        var fresh = await crypto.EncryptAsync("rot", [1]);

        await Assert.That(rotated.Value.Version).IsNotEqualTo(first.Version);
        await Assert.That(fresh.Value.KeyVersion).IsEqualTo(rotated.Value.Version);
        await Assert.That((await crypto.DecryptAsync("rot", old.Value.KeyVersion, old.Value.Ciphertext)).Value).IsEquivalentTo(new byte[] { 9, 9, 9 });
        await Assert.That((await store.ListKeyVersionsAsync("rot")).Value.Count).IsGreaterThanOrEqualTo(2);
        await Assert.That((await store.GetKeyAsync("rot", first.Version)).Value.Version).IsEqualTo(first.Version);
    }

    [Test]
    public async Task Missing_key_returns_NotFound()
    {
        var (store, crypto) = await CreateAsync();

        await Assert.That((await store.GetKeyAsync("nao-existe")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await crypto.EncryptAsync("nao-existe", [1])).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await crypto.SignDataAsync("nao-existe", [1], VaultSignatureAlgorithm.RS256)).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.RotateKeyAsync("nao-existe")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task Listing_and_deletion()
    {
        var (store, _) = await CreateAsync();
        await store.CreateKeyAsync("a", new CreateKeyOptions { KeySize = 2048 });
        await store.CreateKeyAsync("b", new CreateKeyOptions { KeyType = VaultKeyType.Ec });

        var listed = await store.ListKeysAsync();
        var deleted = await store.DeleteKeyAsync("a");

        await Assert.That(listed.Value.Select(k => k.Name)).IsEquivalentTo(["a", "b"]);
        await Assert.That(deleted.IsSuccess).IsTrue();
        await Assert.That((await store.GetKeyAsync("a")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.ListKeysAsync()).Value.Select(k => k.Name)).IsEquivalentTo(["b"]);
    }

    [Test]
    public async Task Invalid_input_is_rejected_before_vault()
    {
        var (store, crypto) = await CreateAsync();

        await Assert.That((await store.CreateKeyAsync("rsa", new CreateKeyOptions { KeySize = 1024 })).Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That((await crypto.DecryptAsync("rsa", "", [1])).Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That((await crypto.EncryptAsync("../x", [1])).Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
    }
}
