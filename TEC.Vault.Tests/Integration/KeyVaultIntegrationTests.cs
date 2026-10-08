using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests.Integration;

/// <summary>Testes contra o Key Vault real de testes. Veja <see cref="KeyVaultFixture"/>.</summary>
[Category(TestCategories.Integration)]
public class KeyVaultIntegrationTests
{
    // ---------------------------------------------------------------- Segredos

    [Test]
    public async Task Secret_full_cycle_crud_versions_deletion_and_recovery()
    {
        await KeyVaultFixture.RequireAsync();
        var store = KeyVaultFixture.Secrets();
        string name = KeyVaultFixture.NewName("sec");

        try
        {
            var v1 = await store.SetSecretAsync(name, "valor-1", new SecretWriteOptions
            {
                ContentType = "text/plain",
                ExpiresOn = DateTimeOffset.UtcNow.AddDays(1),
                Tags = new Dictionary<string, string> { ["origem"] = "tec-vault-testes" }
            });
            await Assert.That(v1.IsSuccess).IsTrue();
            await Assert.That((await store.GetSecretAsync(name)).Value.Value).IsEqualTo("valor-1");
            await Assert.That((await store.ExistsAsync(name)).Value).IsTrue();

            var v2 = await store.SetSecretAsync(name, "valor-2");
            await Assert.That((await store.ListSecretVersionsAsync(name)).Value.Count).IsEqualTo(2);
            await Assert.That((await store.GetSecretAsync(name, v1.Value.Version)).Value.Value).IsEqualTo("valor-1");
            await Assert.That((await store.GetSecretAsync(name)).Value.Value).IsEqualTo("valor-2");

            var disabled = await store.UpdateSecretPropertiesAsync(name, new SecretPropertiesUpdate
            {
                Enabled = false,
                Tags = new Dictionary<string, string> { ["status"] = "aposentado" }
            }, v1.Value.Version);
            await Assert.That(disabled.Value.Enabled).IsFalse();
            await Assert.That(disabled.Value.Tags["status"]).IsEqualTo("aposentado");
            await Assert.That((await store.GetSecretAsync(name, v1.Value.Version)).Error!.Code).IsEqualTo(VaultErrors.DisabledCode);

            var listed = await store.ListSecretsAsync();
            await Assert.That(listed.Value.Any(s => s.Name == name)).IsTrue();

            var backup = await store.BackupSecretAsync(name);
            await Assert.That(backup.Value.Length).IsGreaterThan(0);

            var deleted = await store.DeleteSecretAsync(name);
            await Assert.That(deleted.Value.Name).IsEqualTo(name);
            await Assert.That((await store.GetSecretAsync(name)).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
            await Assert.That((await store.ExistsAsync(name)).Value).IsFalse();
            await Assert.That((await store.ListDeletedSecretsAsync()).Value.Any(d => d.Name == name)).IsTrue();
            await Assert.That((await store.SetSecretAsync(name, "x")).Error!.Code).IsEqualTo(VaultErrors.ConflictCode);

            var recovered = await store.RecoverDeletedSecretAsync(name);
            await Assert.That(recovered.IsSuccess).IsTrue();
            await Assert.That((await store.GetSecretAsync(name)).Value.Value).IsEqualTo("valor-2");

            // Remoção definitiva + restauração do backup (somente se o cofre permitir purge)
            await store.DeleteSecretAsync(name);
            var purge = await store.PurgeDeletedSecretAsync(name);
            if (purge.IsSuccess)
            {
                var restored = await RetryOnConflictAsync(() => store.RestoreSecretBackupAsync(backup.Value));
                await Assert.That(restored.Value.Name).IsEqualTo(name);
                await Assert.That((await store.GetSecretAsync(name)).Value.Value).IsEqualTo("valor-2");
            }
        }
        finally
        {
            await CleanupAsync(() => store.DeleteSecretAsync(name), () => store.PurgeDeletedSecretAsync(name));
        }
    }

    [Test]
    public async Task Secret_generated_and_rotated_without_exposing_value()
    {
        await KeyVaultFixture.RequireAsync();
        var store = KeyVaultFixture.Secrets();
        string name = KeyVaultFixture.NewName("gen");

        try
        {
            var generated = await store.GenerateSecretAsync(name, new SecretGenerationOptions { Kind = SecretGenerationKind.Token },
                new SecretWriteOptions { ContentType = "text/plain", ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) });
            await Assert.That(generated.IsSuccess).IsTrue();
            string first = (await store.GetSecretAsync(name)).Value.Value;

            var rotated = await store.RotateSecretAsync(name, validity: TimeSpan.FromDays(1), disablePreviousVersions: true);
            string second = (await store.GetSecretAsync(name)).Value.Value;

            await Assert.That(rotated.Value.IsComplete).IsTrue();
            await Assert.That(rotated.Value.Current.ContentType).IsEqualTo("text/plain");
            await Assert.That(second).IsNotEqualTo(first);
            await Assert.That((await store.GetSecretAsync(name, generated.Value.Version)).Error!.Code).IsEqualTo(VaultErrors.DisabledCode);
        }
        finally
        {
            await CleanupAsync(() => store.DeleteSecretAsync(name), () => store.PurgeDeletedSecretAsync(name));
        }
    }

    [Test]
    public async Task Configuration_and_health_check_with_real_vault()
    {
        await KeyVaultFixture.RequireAsync();
        var store = KeyVaultFixture.Secrets();
        string prefix = KeyVaultFixture.NewName("cfg")[..30] + "--";
        string name = prefix + "Banco--Senha";

        try
        {
            await store.SetSecretAsync(name, "senha-do-banco", new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) });

            var configuration = new ConfigurationBuilder().AddTecVault(store, o => o.Prefix = prefix).Build();
            var health = await ((IVaultHealthProbe)store).CheckAccessAsync();

            await Assert.That(configuration["Banco:Senha"]).IsEqualTo("senha-do-banco");
            await Assert.That(health.IsSuccess).IsTrue();
        }
        finally
        {
            await CleanupAsync(() => store.DeleteSecretAsync(name), () => store.PurgeDeletedSecretAsync(name));
        }
    }

    [Test]
    public async Task Missing_item_returns_NotFound_for_all_types()
    {
        await KeyVaultFixture.RequireAsync();
        string name = KeyVaultFixture.NewName("nada");

        await Assert.That((await KeyVaultFixture.Secrets().GetSecretAsync(name)).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await KeyVaultFixture.Keys().GetKeyAsync(name)).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await KeyVaultFixture.Certificates().GetCertificateAsync(name)).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    // ---------------------------------------------------------------- Chaves

    [Test]
    public async Task Rsa_key_full_cycle_with_encryption_signature_envelope_and_rotation()
    {
        await KeyVaultFixture.RequireAsync();
        var store = KeyVaultFixture.Keys();
        string name = KeyVaultFixture.NewName("rsa");

        try
        {
            var created = await store.CreateKeyAsync(name, new CreateKeyOptions
            {
                KeySize = 3072,
                ExpiresOn = DateTimeOffset.UtcNow.AddDays(1),
                Tags = new Dictionary<string, string> { ["origem"] = "tec-vault-testes" }
            });
            await Assert.That(created.Value.KeySize).IsEqualTo(3072);
            await Assert.That(created.Value.Operations).IsEqualTo(VaultKeyOperations.Encrypt | VaultKeyOperations.Decrypt | VaultKeyOperations.Sign
                | VaultKeyOperations.Verify | VaultKeyOperations.WrapKey | VaultKeyOperations.UnwrapKey);
            string v1 = created.Value.Version!;

            // Criptografia
            byte[] plaintext = "dado sensível"u8.ToArray();
            var encrypted = await store.EncryptAsync(name, plaintext);
            await Assert.That(encrypted.Value.KeyVersion).IsEqualTo(v1);
            await Assert.That((await store.DecryptAsync(name, v1, encrypted.Value.Ciphertext)).Value).IsEquivalentTo(plaintext);

            // Wrap/unwrap
            byte[] dek = RandomNumberGenerator.GetBytes(32);
            var wrapped = await store.WrapKeyAsync(name, dek);
            await Assert.That((await store.UnwrapKeyAsync(name, v1, wrapped.Value.Ciphertext)).Value).IsEquivalentTo(dek);

            // Assinatura no cofre + verificação no cofre e local (chave pública)
            byte[] document = "contrato"u8.ToArray();
            var signed = await store.SignDataAsync(name, document, VaultSignatureAlgorithm.PS256);
            await Assert.That((await store.VerifyDataAsync(name, v1, document, signed.Value.Signature, VaultSignatureAlgorithm.PS256)).Value).IsTrue();
            await Assert.That((await store.VerifyDataAsync(name, v1, "adulterado"u8.ToArray(), signed.Value.Signature, VaultSignatureAlgorithm.PS256)).Value).IsFalse();
            using (var rsa = RSA.Create())
            {
                rsa.ImportSubjectPublicKeyInfo(created.Value.PublicKeySpki, out _);
                await Assert.That(rsa.VerifyData(document, signed.Value.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).IsTrue();
            }

            // Envelope com contexto
            byte[] big = RandomNumberGenerator.GetBytes(200_000);
            var envelope = await store.EncryptEnvelopeAsync(name, big, "registro:1"u8.ToArray());
            await Assert.That((await store.DecryptEnvelopeAsync(envelope.Value, "registro:1"u8.ToArray())).Value).IsEquivalentTo(big);
            await Assert.That((await store.DecryptEnvelopeAsync(envelope.Value, "registro:2"u8.ToArray())).IsFailure).IsTrue();

            // Rotação: dados antigos continuam legíveis com a versão antiga
            var rotated = await store.RotateKeyAsync(name);
            await Assert.That(rotated.Value.Version).IsNotEqualTo(v1);
            await Assert.That((await store.DecryptAsync(name, v1, encrypted.Value.Ciphertext)).Value).IsEquivalentTo(plaintext);
            await Assert.That((await store.EncryptAsync(name, plaintext)).Value.KeyVersion).IsEqualTo(rotated.Value.Version!);
            await Assert.That((await store.ListKeyVersionsAsync(name)).Value.Count).IsEqualTo(2);

            // Metadados: restringe operações (menor privilégio) e desabilita
            var restricted = await store.UpdateKeyPropertiesAsync(name, new KeyPropertiesUpdate { Operations = VaultKeyOperations.Verify });
            await Assert.That(restricted.Value.Operations).IsEqualTo(VaultKeyOperations.Verify);
            await Assert.That((await store.SignDataAsync(name, document, VaultSignatureAlgorithm.PS256)).IsFailure).IsTrue();

            var disabled = await store.UpdateKeyPropertiesAsync(name, new KeyPropertiesUpdate { Enabled = false });
            await Assert.That(disabled.Value.Properties.Enabled).IsFalse();

            await Assert.That((await store.ListKeysAsync()).Value.Any(k => k.Name == name)).IsTrue();

            // Backup, exclusão e recuperação
            var backup = await store.BackupKeyAsync(name);
            await Assert.That(backup.Value.Length).IsGreaterThan(0);
            await Assert.That((await store.DeleteKeyAsync(name)).Value.Name).IsEqualTo(name);
            await Assert.That((await store.ListDeletedKeysAsync()).Value.Any(d => d.Name == name)).IsTrue();
            await Assert.That((await store.RecoverDeletedKeyAsync(name)).Value.Name).IsEqualTo(name);
        }
        finally
        {
            await CleanupAsync(() => store.DeleteKeyAsync(name), () => store.PurgeDeletedKeyAsync(name));
        }
    }

    [Test]
    public async Task Ec_key_signs_and_verifies()
    {
        await KeyVaultFixture.RequireAsync();
        var store = KeyVaultFixture.Keys();
        string name = KeyVaultFixture.NewName("ec");

        try
        {
            var created = await store.CreateKeyAsync(name, new CreateKeyOptions { KeyType = VaultKeyType.Ec, Curve = VaultKeyCurve.P256 });
            await Assert.That(created.Value.Curve).IsEqualTo(VaultKeyCurve.P256);
            await Assert.That(created.Value.Operations).IsEqualTo(VaultKeyOperations.Sign | VaultKeyOperations.Verify);

            byte[] data = "mensagem"u8.ToArray();
            var signed = await store.SignDataAsync(name, data, VaultSignatureAlgorithm.ES256);
            await Assert.That((await store.VerifyDataAsync(name, created.Value.Version!, data, signed.Value.Signature, VaultSignatureAlgorithm.ES256)).Value).IsTrue();

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(created.Value.PublicKeySpki, out _);
            await Assert.That(ecdsa.VerifyData(data, signed.Value.Signature, HashAlgorithmName.SHA256)).IsTrue();

            // EC não cifra: o cofre recusa
            await Assert.That((await store.EncryptAsync(name, data)).IsFailure).IsTrue();
        }
        finally
        {
            await CleanupAsync(() => store.DeleteKeyAsync(name), () => store.PurgeDeletedKeyAsync(name));
        }
    }

    // ---------------------------------------------------------------- Certificados

    [Test]
    public async Task Self_signed_certificate_full_cycle()
    {
        await KeyVaultFixture.RequireAsync();
        var store = KeyVaultFixture.Certificates();
        string name = KeyVaultFixture.NewName("crt");

        try
        {
            var created = await store.CreateCertificateAsync(name, new CreateCertificateOptions
            {
                Subject = "CN=tec-vault-teste",
                DnsNames = ["tec-vault-teste.local"],
                ValidityInMonths = 1,
                KeySize = 2048,
                Exportable = true,
                Tags = new Dictionary<string, string> { ["origem"] = "tec-vault-testes" }
            });
            await Assert.That(created.Value.Properties.Thumbprint).IsNotNull();

            var fetched = await store.GetCertificateAsync(name);
            using (var publicCert = fetched.Value.ToX509Certificate())
            {
                await Assert.That(publicCert.Subject).IsEqualTo("CN=tec-vault-teste");
                await Assert.That(publicCert.HasPrivateKey).IsFalse();
            }

            var downloaded = await store.DownloadCertificateAsync(name);
            using (var withKey = downloaded.Value)
                await Assert.That(withKey.HasPrivateKey).IsTrue();

            var updated = await store.UpdateCertificatePropertiesAsync(name, new CertificatePropertiesUpdate
            {
                Tags = new Dictionary<string, string> { ["ambiente"] = "teste" }
            });
            await Assert.That(updated.Value.Tags["ambiente"]).IsEqualTo("teste");

            await Assert.That((await store.ListCertificatesAsync()).Value.Any(c => c.Name == name)).IsTrue();
            await Assert.That((await store.ListCertificateVersionsAsync(name)).Value.Count).IsEqualTo(1);
            await Assert.That((await store.BackupCertificateAsync(name)).Value.Length).IsGreaterThan(0);

            await Assert.That((await store.DeleteCertificateAsync(name)).Value.Name).IsEqualTo(name);
            await Assert.That((await store.ListDeletedCertificatesAsync()).Value.Any(d => d.Name == name)).IsTrue();
            await Assert.That((await store.RecoverDeletedCertificateAsync(name)).Value.Name).IsEqualTo(name);
        }
        finally
        {
            await CleanupAsync(() => store.DeleteCertificateAsync(name), () => store.PurgeDeletedCertificateAsync(name));
        }
    }

    [Test]
    public async Task Imported_non_exportable_certificate_does_not_release_private_key()
    {
        await KeyVaultFixture.RequireAsync();
        var store = KeyVaultFixture.Certificates();
        string name = KeyVaultFixture.NewName("imp");

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=tec-vault-importado", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var local = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
        byte[] pfx = local.Export(X509ContentType.Pkcs12, "senha-temporaria");

        try
        {
            var imported = await store.ImportCertificateAsync(name, pfx, new ImportCertificateOptions { Password = "senha-temporaria" });
            await Assert.That(imported.Value.Properties.Thumbprint).IsEqualTo(local.Thumbprint);

            var download = await store.DownloadCertificateAsync(name);
            await Assert.That(download.Error!.Code).IsEqualTo(VaultErrors.NotExportableCode);
        }
        finally
        {
            await CleanupAsync(() => store.DeleteCertificateAsync(name), () => store.PurgeDeletedCertificateAsync(name));
        }
    }

    // ---------------------------------------------------------------- Apoio

    private static async Task<Result<T>> RetryOnConflictAsync<T>(Func<Task<Result<T>>> action)
    {
        // A remoção definitiva é assíncrona no Key Vault: o nome fica em conflito por alguns segundos
        for (int i = 0; ; i++)
        {
            var result = await action();
            if (result.IsSuccess || result.Error!.Code != VaultErrors.ConflictCode || i == 20)
                return result;
            await Task.Delay(TimeSpan.FromSeconds(3));
        }
    }

    private static async Task CleanupAsync<T>(Func<Task<Result<T>>> delete, Func<Task<Result>> purge)
    {
        await delete();
        await purge();
    }
}
