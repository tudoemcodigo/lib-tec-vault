using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.InMemory;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Provedor em memória (TEC.Vault.InMemory): trava de ambiente e contrato de segredos, chaves e certificados.</summary>
public class InMemoryProviderTests
{
    private const string SecretValue = "VALOR-EM-MEMORIA-5c1e";

    // ---------- Trava de ambiente ----------

    [Test]
    public async Task Outside_development_creation_fails_closed()
    {
        var production = new InMemoryVaultOptions { HostEnvironment = new HostEnvironmentStub("Production") };

        await Assert.That(() => new InMemorySecretStore(production)).Throws<InvalidOperationException>();
        await Assert.That(() => new InMemoryKeyStore(production)).Throws<InvalidOperationException>();
        await Assert.That(() => new InMemoryCertificateStore(production)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Development_or_explicit_permission_allow_usage()
    {
        await Assert.That(() => new InMemorySecretStore(new InMemoryVaultOptions { HostEnvironment = new HostEnvironmentStub("Development") }))
            .ThrowsNothing();
        await Assert.That(() => new InMemorySecretStore(new InMemoryVaultOptions
        {
            HostEnvironment = new HostEnvironmentStub("Production"),
            AllowOutsideDevelopment = true
        })).ThrowsNothing();
    }

    [Test]
    public async Task UseInMemory_uses_IHostEnvironment_registered_in_container()
    {
        var production = new ServiceCollection();
        production.AddSingleton<IHostEnvironment>(new HostEnvironmentStub("Production"));
        var development = new ServiceCollection();
        development.AddSingleton<IHostEnvironment>(new HostEnvironmentStub("Development"));

        await Assert.That(() => production.AddTecVault(c => c.UseInMemory())).Throws<InvalidOperationException>();
        await Assert.That(() => development.AddTecVault(c => c.UseInMemory())).ThrowsNothing();
    }

    [Test]
    public async Task UseInMemory_registers_only_chosen_stores()
    {
        var services = new ServiceCollection();
        services.AddTecVault(c => c.UseInMemory(o => { o.AllowOutsideDevelopment = true; o.Stores = VaultStores.Keys; }));
        using var provider = services.BuildServiceProvider();

        await Assert.That(provider.GetService<ISecretReader>()).IsNull();
        await Assert.That(provider.GetService<ICertificateReader>()).IsNull();
        await Assert.That(provider.GetRequiredService<IKeyCryptography>()).IsTypeOf<InMemoryKeyStore>();
        await Assert.That((await provider.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync()).IsSuccess).IsTrue();
    }

    // ---------- Segredos ----------

    [Test]
    public async Task Initial_secrets_are_loaded()
    {
        var options = Memory.Options();
        options.InitialSecrets["db-senha"] = "senha-local";

        var store = new InMemorySecretStore(options);

        await Assert.That((await store.GetSecretAsync("DB-SENHA")).Value.Value).IsEqualTo("senha-local");
    }

    [Test]
    public async Task Initial_secret_with_invalid_name_is_rejected()
    {
        var options = Memory.Options();
        options.InitialSecrets["nome com espaço"] = "x";

        await Assert.That(() => new InMemorySecretStore(options)).Throws<ArgumentException>();
    }

    [Test]
    public async Task Secret_full_cycle_with_recycle_bin_and_backup()
    {
        var store = Memory.Secrets();
        var v1 = await store.SetSecretAsync("api", "v1");
        await store.SetSecretAsync("api", "v2");

        await Assert.That((await store.GetSecretAsync("api")).Value.Value).IsEqualTo("v2");
        await Assert.That((await store.GetSecretAsync("api", v1.Value.Version)).Value.Value).IsEqualTo("v1");
        await Assert.That((await store.ExistsAsync("api")).Value).IsTrue();

        var backup = await store.BackupSecretAsync("api");
        await Assert.That(Encoding.UTF8.GetString(backup.Value)).DoesNotContain("v2");   // backup opaco

        var deleted = await store.DeleteSecretAsync("api");
        await Assert.That(deleted.Value.ScheduledPurgeDate).IsNotNull();
        await Assert.That((await store.GetSecretAsync("api")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.ExistsAsync("api")).Value).IsFalse();
        await Assert.That((await store.SetSecretAsync("api", "x")).Error!.Code).IsEqualTo(VaultErrors.ConflictCode);
        await Assert.That((await store.ListDeletedSecretsAsync()).Value.Select(d => d.Name)).Contains("api");

        await store.RecoverDeletedSecretAsync("api");
        await Assert.That((await store.GetSecretAsync("api")).Value.Value).IsEqualTo("v2");

        await store.DeleteSecretAsync("api");
        await Assert.That((await store.PurgeDeletedSecretAsync("api")).IsSuccess).IsTrue();
        var restored = await store.RestoreSecretBackupAsync(backup.Value);
        await Assert.That(restored.Value.Name).IsEqualTo("api");
        await Assert.That((await store.ListSecretVersionsAsync("api")).Value.Count).IsEqualTo(2);
        await Assert.That((await store.RestoreSecretBackupAsync(backup.Value)).Error!.Code).IsEqualTo(VaultErrors.ConflictCode);
        await Assert.That((await store.RestoreSecretBackupAsync(new byte[32])).Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
    }

    [Test]
    public async Task Secret_validates_input_and_does_not_log_value()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var store = new InMemorySecretStore(Memory.Options(), factory.CreateLogger<InMemorySecretStore>());

        var invalid = await store.GetSecretAsync("../outro");
        var expired = await store.SetSecretAsync("x", "v", new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddMinutes(-1) });
        await store.SetSecretAsync("db", SecretValue);
        await store.GetSecretAsync("db");

        await Assert.That(invalid.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(expired.Error!.Field).IsEqualTo("expiresOn");
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Information && e.Text.Contains("secret.set") && e.Text.Contains("InMemory"))).IsTrue();
    }

    // ---------- Chaves ----------

    [Test]
    public async Task Rsa_key_encrypts_wraps_and_signs_and_old_version_stays_valid_after_rotation()
    {
        var keys = Memory.Keys();
        var created = await keys.CreateKeyAsync("rsa", new CreateKeyOptions { KeySize = 2048 });
        string v1 = created.Value.Version!;
        byte[] plaintext = "dado sensível"u8.ToArray();

        var encrypted = await keys.EncryptAsync("rsa", plaintext);
        var wrapped = await keys.WrapKeyAsync("rsa", RandomNumberGenerator.GetBytes(32));
        var signed = await keys.SignDataAsync("rsa", plaintext, VaultSignatureAlgorithm.PS256);
        var rotated = await keys.RotateKeyAsync("rsa");

        await Assert.That(created.Value.KeySize).IsEqualTo(2048);
        await Assert.That(created.Value.HardwareProtected).IsFalse();
        await Assert.That(encrypted.Value.KeyVersion).IsEqualTo(v1);
        await Assert.That((await keys.DecryptAsync("rsa", v1, encrypted.Value.Ciphertext)).Value).IsEquivalentTo(plaintext);
        await Assert.That((await keys.UnwrapKeyAsync("rsa", v1, wrapped.Value.Ciphertext)).Value.Length).IsEqualTo(32);
        await Assert.That((await keys.VerifyDataAsync("rsa", v1, plaintext, signed.Value.Signature, VaultSignatureAlgorithm.PS256)).Value).IsTrue();
        await Assert.That((await keys.VerifyDataAsync("rsa", v1, "outro"u8.ToArray(), signed.Value.Signature, VaultSignatureAlgorithm.PS256)).Value).IsFalse();
        await Assert.That(rotated.Value.Version).IsNotEqualTo(v1);
        await Assert.That((await keys.EncryptAsync("rsa", plaintext)).Value.KeyVersion).IsEqualTo(rotated.Value.Version!);
        await Assert.That((await keys.ListKeyVersionsAsync("rsa")).Value.Count).IsEqualTo(2);

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(created.Value.PublicKeySpki, out _);
        await Assert.That(rsa.VerifyData(plaintext, signed.Value.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)).IsTrue();
    }

    [Test]
    [Arguments(VaultKeyCurve.P256, VaultSignatureAlgorithm.ES256)]
    [Arguments(VaultKeyCurve.P384, VaultSignatureAlgorithm.ES384)]
    [Arguments(VaultKeyCurve.P521, VaultSignatureAlgorithm.ES512)]
    public async Task Ec_key_signs_in_ieee_p1363_and_does_not_encrypt(VaultKeyCurve curve, VaultSignatureAlgorithm algorithm)
    {
        var keys = Memory.Keys();
        var created = await keys.CreateKeyAsync("ec", new CreateKeyOptions { KeyType = VaultKeyType.Ec, Curve = curve });
        byte[] data = "mensagem"u8.ToArray();

        var signed = await keys.SignDataAsync("ec", data, algorithm);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(created.Value.PublicKeySpki, out _);
        await Assert.That(created.Value.Operations).IsEqualTo(VaultKeyOperations.Sign | VaultKeyOperations.Verify);
        await Assert.That(ecdsa.VerifyData(data, signed.Value.Signature, HashForCurve(curve))).IsTrue();
        await Assert.That((await keys.EncryptAsync("ec", data)).Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
        await Assert.That((await keys.SignDataAsync("ec", data, VaultSignatureAlgorithm.PS256)).Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
    }

    [Test]
    public async Task Key_respects_allowed_operations_state_and_hsm()
    {
        var keys = Memory.Keys();
        await keys.CreateKeyAsync("assinatura", new CreateKeyOptions { KeySize = 2048, Operations = VaultKeyOperations.Sign | VaultKeyOperations.Verify });

        var encrypt = await keys.EncryptAsync("assinatura", "x"u8.ToArray());
        await keys.UpdateKeyPropertiesAsync("assinatura", new KeyPropertiesUpdate { Enabled = false });
        var disabled = await keys.SignDataAsync("assinatura", "x"u8.ToArray(), VaultSignatureAlgorithm.RS256);
        var hsm = await keys.CreateKeyAsync("hsm", new CreateKeyOptions { HardwareProtected = true });
        var weak = await keys.CreateKeyAsync("fraca", new CreateKeyOptions { KeySize = 1024 });

        await Assert.That(encrypt.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
        await Assert.That(disabled.Error!.Code).IsEqualTo(VaultErrors.DisabledCode);
        await Assert.That(hsm.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
        await Assert.That(weak.Error!.Field).IsEqualTo("keySize");
    }

    [Test]
    public async Task Key_with_recycle_bin_and_backup()
    {
        var keys = Memory.Keys();
        await keys.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });
        var backup = await keys.BackupKeyAsync("k");

        await keys.DeleteKeyAsync("k");
        await Assert.That((await keys.GetKeyAsync("k")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await keys.RecoverDeletedKeyAsync("k")).Value.Name).IsEqualTo("k");
        await keys.DeleteKeyAsync("k");
        await keys.PurgeDeletedKeyAsync("k");
        await Assert.That((await keys.RestoreKeyBackupAsync(backup.Value)).Value.Name).IsEqualTo("k");
    }

    [Test]
    public async Task Returned_public_key_is_a_copy()
    {
        var keys = Memory.Keys();
        var created = await keys.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });
        created.Value.PublicKeySpki![0] ^= 0xFF;

        var again = await keys.GetKeyAsync("k");

        await Assert.That(again.Value.PublicKeySpki![0]).IsNotEqualTo(created.Value.PublicKeySpki[0]);
    }

    // ---------- Certificados ----------

    [Test]
    public async Task Exportable_self_signed_certificate_is_downloaded_with_key()
    {
        var certificates = Memory.Certificates();

        var created = await certificates.CreateCertificateAsync("api", new CreateCertificateOptions
        {
            Subject = "CN=api.local",
            DnsNames = ["api.local"],
            KeySize = 2048,
            Exportable = true
        });
        var downloaded = await certificates.DownloadCertificateAsync("api");

        using var withKey = downloaded.Value;
        using var publicOnly = created.Value.ToX509Certificate();
        await Assert.That(withKey.HasPrivateKey).IsTrue();
        await Assert.That(publicOnly.HasPrivateKey).IsFalse();
        await Assert.That(publicOnly.Subject).IsEqualTo("CN=api.local");
        await Assert.That(created.Value.Properties.Thumbprint).IsEqualTo(withKey.Thumbprint);
        await Assert.That(created.Value.Properties.ExpiresOn).IsNotNull();
    }

    [Test]
    public async Task Non_exportable_certificate_does_not_release_key_and_external_issuer_is_not_supported()
    {
        var certificates = Memory.Certificates();
        await certificates.CreateCertificateAsync("ec", new CreateCertificateOptions { Subject = "CN=ec", KeyType = VaultKeyType.Ec });

        var download = await certificates.DownloadCertificateAsync("ec");
        var issuer = await certificates.CreateCertificateAsync("ca", new CreateCertificateOptions { Subject = "CN=ca", Issuer = "DigiCert" });

        await Assert.That(download.Error!.Code).IsEqualTo(VaultErrors.NotExportableCode);
        await Assert.That(issuer.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
    }

    [Test]
    public async Task Certificate_imported_from_pfx_and_pem()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=importado", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var local = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
        byte[] pfx = local.Export(X509ContentType.Pkcs12, "senha");
        byte[] pem = Encoding.ASCII.GetBytes(local.ExportCertificatePem() + "\n" + rsa.ExportPkcs8PrivateKeyPem());
        var certificates = Memory.Certificates();

        var fromPfx = await certificates.ImportCertificateAsync("pfx", pfx, new ImportCertificateOptions { Password = "senha", Exportable = true });
        var fromPem = await certificates.ImportCertificateAsync("pem", pem, new ImportCertificateOptions { Exportable = true });
        var wrongPassword = await certificates.ImportCertificateAsync("errado", pfx, new ImportCertificateOptions { Password = "errada" });

        await Assert.That(fromPfx.Value.Properties.Thumbprint).IsEqualTo(local.Thumbprint);
        await Assert.That(fromPem.Value.Properties.Thumbprint).IsEqualTo(local.Thumbprint);
        await Assert.That(wrongPassword.Error!.Field).IsEqualTo("certificate");
        using var downloaded = (await certificates.DownloadCertificateAsync("pem")).Value;
        await Assert.That(downloaded.HasPrivateKey).IsTrue();
    }

    [Test]
    public async Task Certificate_with_recycle_bin_and_backup()
    {
        var certificates = Memory.Certificates();
        await certificates.CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=c", KeySize = 2048 });
        var backup = await certificates.BackupCertificateAsync("c");

        await certificates.DeleteCertificateAsync("c");
        await Assert.That((await certificates.ListDeletedCertificatesAsync()).Value.Single().Name).IsEqualTo("c");
        await Assert.That((await certificates.RecoverDeletedCertificateAsync("c")).Value.Name).IsEqualTo("c");
        await Assert.That((await certificates.UpdateCertificatePropertiesAsync("c", new CertificatePropertiesUpdate { Enabled = false })).Value.Enabled).IsFalse();
        await certificates.DeleteCertificateAsync("c");
        await certificates.PurgeDeletedCertificateAsync("c");
        await Assert.That((await certificates.RestoreCertificateBackupAsync(backup.Value)).Value.Name).IsEqualTo("c");
    }

    private static HashAlgorithmName HashForCurve(VaultKeyCurve curve) => curve switch
    {
        VaultKeyCurve.P384 => HashAlgorithmName.SHA384,
        VaultKeyCurve.P521 => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256
    };

    private sealed class HostEnvironmentStub(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "testes";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    // ---------- Backups limitados ----------

    [Test]
    public async Task Backups_above_limit_discard_oldest()
    {
        var options = Memory.Options();
        options.MaxBackups = 2;
        var secrets = new InMemorySecretStore(options);
        await secrets.SetSecretAsync("s", "1");

        var oldest = (await secrets.BackupSecretAsync("s")).Value;
        var middle = (await secrets.BackupSecretAsync("s")).Value;
        var newest = (await secrets.BackupSecretAsync("s")).Value;
        await secrets.DeleteSecretAsync("s");
        await secrets.PurgeDeletedSecretAsync("s");

        await Assert.That((await secrets.RestoreSecretBackupAsync(oldest)).Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
        await Assert.That((await secrets.RestoreSecretBackupAsync(newest)).IsSuccess).IsTrue();
        await secrets.DeleteSecretAsync("s");
        await secrets.PurgeDeletedSecretAsync("s");
        await Assert.That((await secrets.RestoreSecretBackupAsync(middle)).IsSuccess).IsTrue();   // restaurar não consome o backup
    }

    [Test]
    public async Task MaxBackups_below_1_is_rejected() =>
        await Assert.That(() => new InMemoryVaultOptions { MaxBackups = 0 }).Throws<ArgumentOutOfRangeException>();

    [Test]
    public async Task Discarded_backup_zeroes_own_copy_without_affecting_item_or_restores()
    {
        var erased = new List<Holder>();
        var items = new TEC.Vault.InMemory.Internal.VersionedItems<Holder>(1, h => h with { Secret = (byte[])h.Secret.Clone() }, h =>
        {
            CryptographicOperations.ZeroMemory(h.Secret);
            erased.Add(h);
        });
        var active = new Holder([1, 2, 3]);
        items.Add("k", active);

        var first = items.Backup("k")!;
        var restoredSource = items.Backup("k")!;                 // passa do limite: a cópia do primeiro é apagada

        await Assert.That(items.BackupCount).IsEqualTo(1);
        await Assert.That(erased.Count).IsEqualTo(1);
        await Assert.That(erased[0]).IsNotSameReferenceAs(active);
        await Assert.That(erased[0].Secret.All(b => b == 0)).IsTrue();
        await Assert.That(active.Secret).IsEquivalentTo(new byte[] { 1, 2, 3 });   // o item ativo não foi tocado

        items.Delete("k", DateTimeOffset.UtcNow);
        items.Purge("k");
        await Assert.That(items.Restore(first, out _, out _)).IsNull();
        var restored = items.Restore(restoredSource, out _, out _)!;
        await Assert.That(restored[0]).IsNotSameReferenceAs(active);
        await Assert.That(restored[0].Secret).IsEquivalentTo(new byte[] { 1, 2, 3 });

        items.Backup("k");                                       // descarta o backup restaurado: a cópia restaurada é independente
        await Assert.That(restored[0].Secret).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task Key_keeps_working_after_backups_are_discarded()
    {
        var options = Memory.Options();
        options.MaxBackups = 1;
        var keys = new InMemoryKeyStore(options);
        var key = (await keys.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 })).Value;

        for (int i = 0; i < 3; i++)
            await keys.BackupKeyAsync("k");                      // cada backup descarta (e zera) a cópia do anterior

        var encrypted = await keys.EncryptAsync("k", [1, 2, 3]);
        var decrypted = await keys.DecryptAsync("k", key.Properties.Version!, encrypted.Value.Ciphertext);
        await Assert.That(decrypted.Value).IsEquivalentTo(new byte[] { 1, 2, 3 });
    }

    [Test]
    public async Task Certificate_remains_downloadable_after_backups_are_discarded()
    {
        var options = Memory.Options();
        options.MaxBackups = 1;
        var certificates = new InMemoryCertificateStore(options);
        await certificates.CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=teste", Exportable = true });

        for (int i = 0; i < 3; i++)
            await certificates.BackupCertificateAsync("c");

        using var downloaded = (await certificates.DownloadCertificateAsync("c")).Value;
        await Assert.That(downloaded.HasPrivateKey).IsTrue();
    }

    internal sealed record Holder(byte[] Secret);

    // ---------- Concorrência ----------

    [Test]
    public async Task Parallel_writes_to_same_name_create_one_version_each()
    {
        var secrets = Memory.Secrets();
        const int writers = 64;

        var results = await Task.WhenAll(Enumerable.Range(0, writers)
            .Select(i => Task.Run(() => secrets.SetSecretAsync("compartilhado", $"valor-{i}"))));

        var versions = (await secrets.ListSecretVersionsAsync("compartilhado")).Value;
        var current = (await secrets.GetSecretAsync("compartilhado")).Value;
        await Assert.That(results.All(r => r.IsSuccess)).IsTrue();
        await Assert.That(results.Select(r => r.Value.Version).Distinct().Count()).IsEqualTo(writers);
        await Assert.That(versions.Count).IsEqualTo(writers);
        await Assert.That(results.Select(r => r.Value.Version)).Contains(current.Version);
        await Assert.That(current.Value).StartsWith("valor-");
    }
}
