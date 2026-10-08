using TEC.Core.Text.Codecs;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>
/// Operações do provedor Azure com o SDK real sobre o Key Vault simulado no nível HTTP: criptografia, certificados, lixeira,
/// backup, tempo limite das operações longas e o desempate da versão atual.
/// </summary>
public class AzureKeyVaultOperationsTests
{
    private const string Vault = FakeKeyVault.VaultUri;
    private const string V = FakeKeyVault.Version;
    private const string Attributes = """{"enabled":true,"created":1700000000,"updated":1700000000,"recoveryLevel":"Recoverable+Purgeable"}""";

    // ---------- Criptografia: o fake faz a operação de verdade com a chave privada ----------

    /// <summary>Cofre de chaves que executa as operações remotas (decrypt, unwrap, sign, verify, encrypt, wrap) com <paramref name="rsa"/>.</summary>
    private static FakeKeyVault CryptoVault(RSA rsa) => new((request, body) =>
    {
        string path = request.RequestUri!.AbsolutePath.TrimEnd('/');
        if (request.Method == HttpMethod.Get && path == $"/keys/kek/{V}")
            return (HttpStatusCode.OK, RsaKeyJson("kek", rsa));
        if (request.Method != HttpMethod.Post)
            return (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("KeyNotFound", "x"));

        using var json = JsonDocument.Parse(body);
        string alg = json.RootElement.GetProperty("alg").GetString()!;
        byte[] value = FromBase64Url(json.RootElement.GetProperty("value").GetString()!);
        string operation = path[(path.LastIndexOf('/') + 1)..].ToLowerInvariant();
        return operation switch
        {
            "decrypt" or "unwrapkey" when alg == "RSA-OAEP-256" => (HttpStatusCode.OK, Bytes(rsa.Decrypt(value, RSAEncryptionPadding.OaepSHA256))),
            "encrypt" or "wrapkey" when alg == "RSA-OAEP-256" => (HttpStatusCode.OK, Bytes(rsa.Encrypt(value, RSAEncryptionPadding.OaepSHA256))),
            "sign" when alg == "RS256" => (HttpStatusCode.OK, Bytes(rsa.SignHash(value, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))),
            "verify" when alg == "RS256" => (HttpStatusCode.OK, $$"""{"value":{{(rsa.VerifyHash(FromBase64Url(json.RootElement.GetProperty("digest").GetString()!), value, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) ? "true" : "false")}}}"""),
            _ => (HttpStatusCode.BadRequest, FakeKeyVault.ErrorJson("BadParameter", "x"))
        };
    });

    private static string Bytes(byte[] value) => $$"""{"kid":"{{Vault}}keys/kek/{{V}}","value":"{{ToBase64Url(value)}}"}""";

    [Test]
    public async Task DecryptAsync_decrypts_in_vault()
    {
        using var rsa = RSA.Create(2048);
        var vault = CryptoVault(rsa);
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());
        byte[] ciphertext = rsa.Encrypt([1, 2, 3], RSAEncryptionPadding.OaepSHA256);

        var result = await store.DecryptAsync("kek", V, ciphertext);

        await Assert.That(result.Value).IsEquivalentTo(new byte[] { 1, 2, 3 });
        var post = vault.Requests.Single(r => r.Method == "POST" && r.Authorized);
        await Assert.That(post.Uri.AbsolutePath).IsEqualTo($"/keys/kek/{V}/decrypt");
        await Assert.That(post.Body).Contains("RSA-OAEP-256");
    }

    [Test]
    public async Task WrapKeyAsync_and_UnwrapKeyAsync_wrap_and_recover_key()
    {
        using var rsa = RSA.Create(2048);
        var vault = CryptoVault(rsa);
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());
        byte[] dataKey = RandomNumberGenerator.GetBytes(32);

        var wrapped = await store.WrapKeyAsync("kek", dataKey, version: V);
        var unwrapped = await store.UnwrapKeyAsync("kek", V, wrapped.Value.Ciphertext);

        await Assert.That(wrapped.Value.KeyVersion).IsEqualTo(V);
        await Assert.That(rsa.Decrypt(wrapped.Value.Ciphertext, RSAEncryptionPadding.OaepSHA256)).IsEquivalentTo(dataKey);
        await Assert.That(unwrapped.Value).IsEquivalentTo(dataKey);
    }

    [Test]
    public async Task Full_envelope_through_azure_provider()
    {
        using var rsa = RSA.Create(2048);
        var store = new AzureKeyVaultKeyStore(CryptoVault(rsa).CreateClients());
        byte[] context = "registro:7"u8.ToArray();

        var envelope = await store.EncryptEnvelopeAsync("kek", "conteudo"u8.ToArray(), context, keyVersion: V);
        var opened = await store.DecryptEnvelopeAsync(envelope.Value, context);

        await Assert.That(opened.Value).IsEquivalentTo("conteudo"u8.ToArray());
    }

    [Test]
    public async Task SignDataAsync_signs_in_vault_and_VerifyDataAsync_checks()
    {
        using var rsa = RSA.Create(2048);
        var vault = CryptoVault(rsa);
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());
        byte[] data = "documento"u8.ToArray();

        var signed = await store.SignDataAsync("kek", data, VaultSignatureAlgorithm.RS256, V);
        var valid = await store.VerifyDataAsync("kek", V, data, signed.Value.Signature, VaultSignatureAlgorithm.RS256);
        var tampered = await store.VerifyDataAsync("kek", V, "documento!"u8.ToArray(), signed.Value.Signature, VaultSignatureAlgorithm.RS256);

        await Assert.That(signed.Value.KeyVersion).IsEqualTo(V);
        await Assert.That(rsa.VerifyData(data, signed.Value.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)).IsTrue();
        await Assert.That(vault.Requests.Any(r => r.Method == "POST" && r.Uri.AbsolutePath == $"/keys/kek/{V}/sign")).IsTrue();
        await Assert.That(valid.Value).IsTrue();
        await Assert.That(tampered.Value).IsFalse();      // assinatura inválida é sucesso com false
    }

    [Test]
    public async Task Decrypt_of_invalid_data_returns_Rejected()
    {
        using var rsa = RSA.Create(2048);
        var vault = new FakeKeyVault((request, _) => request.Method == HttpMethod.Get
            ? (HttpStatusCode.OK, RsaKeyJson("kek", rsa))
            : (HttpStatusCode.BadRequest, FakeKeyVault.ErrorJson("BadParameter", "The parameter is incorrect.")));
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());

        var result = await store.DecryptAsync("kek", V, new byte[256]);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
    }

    // ---------- ToModel: tipo ou curva não suportados ----------

    [Test]
    public async Task Symmetric_oct_key_returns_NotSupported()
    {
        string json = $$"""{"key":{"kid":"{{Vault}}keys/sim/{{V}}","kty":"oct-HSM","key_ops":["wrapKey"],"k":"AAAAAAAAAAAAAAAAAAAAAA"},"attributes":{{Attributes}}}""";
        var store = new AzureKeyVaultKeyStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, json)).CreateClients());

        var result = await store.GetKeyAsync("sim");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
    }

    [Test]
    public async Task Ec_key_with_unsupported_curve_returns_NotSupported()
    {
        string json = $$"""
            {"key":{"kid":"{{Vault}}keys/ec/{{V}}","kty":"EC","crv":"P-256K","key_ops":["sign","verify"],
             "x":"{{ToBase64Url(new byte[32])}}","y":"{{ToBase64Url(new byte[32])}}"},"attributes":{{Attributes}}}
            """;
        var store = new AzureKeyVaultKeyStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, json)).CreateClients());

        var result = await store.GetKeyAsync("ec");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
    }

    // ---------- Certificados ----------

    [Test]
    public async Task CreateCertificateAsync_creates_and_waits_for_completion()
    {
        using var certificate = SelfSigned(withKey: false);
        var vault = new FakeKeyVault((request, body) =>
        {
            string path = request.RequestUri!.AbsolutePath.TrimEnd('/');
            return path switch
            {
                "/certificates/web/create" => (HttpStatusCode.Accepted, OperationJson("web", "inProgress")),
                "/certificates/web/pending" => (HttpStatusCode.OK, OperationJson("web", "completed")),
                "/certificates/web" => (HttpStatusCode.OK, CertificateJson("web", certificate)),
                _ => (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("CertificateNotFound", "x"))
            };
        });
        var store = new AzureKeyVaultCertificateStore(vault.CreateClients());

        var result = await store.CreateCertificateAsync("web", new CreateCertificateOptions { Subject = "CN=web", DnsNames = ["web.exemplo.com"] });

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Properties.Version).IsEqualTo(V);
        await Assert.That(result.Value.Cer).IsEquivalentTo(certificate.RawData);
        using var create = JsonDocument.Parse(vault.Requests.Single(r => r.Method == "POST" && r.Authorized).Body);
        var policy = create.RootElement.GetProperty("policy");
        await Assert.That(policy.GetProperty("issuer").GetProperty("name").GetString()).IsEqualTo("Self");
        await Assert.That(policy.GetProperty("key_props").GetProperty("exportable").GetBoolean()).IsFalse();
        await Assert.That(policy.GetProperty("x509_props").GetProperty("subject").GetString()).IsEqualTo("CN=web");
    }

    [Test]
    public async Task DownloadCertificateAsync_with_private_key_returns_certificate()
    {
        using var certificate = SelfSigned(withKey: true);
        var vault = CertificateVault("web", certificate, certificate.Export(X509ContentType.Pkcs12));
        var store = new AzureKeyVaultCertificateStore(vault.CreateClients());

        var result = await store.DownloadCertificateAsync("web");

        using var downloaded = result.Value;
        await Assert.That(downloaded.HasPrivateKey).IsTrue();
        await Assert.That(downloaded.Thumbprint).IsEqualTo(certificate.Thumbprint);
        await Assert.That(vault.Requests.Any(r => r.Uri.AbsolutePath == $"/secrets/web/{V}")).IsTrue();
    }

    [Test]
    public async Task DownloadCertificateAsync_without_private_key_returns_NotExportable()
    {
        using var withKey = SelfSigned(withKey: true);
        using var publicOnly = VaultCertificateLoader.LoadCertificate(withKey.RawData);
        var vault = CertificateVault("web", publicOnly, publicOnly.Export(X509ContentType.Pkcs12));
        var store = new AzureKeyVaultCertificateStore(vault.CreateClients());

        var result = await store.DownloadCertificateAsync("web");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotExportableCode);
    }

    private static FakeKeyVault CertificateVault(string name, X509Certificate2 certificate, byte[] pfx) => new((request, _) =>
    {
        string path = request.RequestUri!.AbsolutePath.TrimEnd('/');
        if (path == $"/certificates/{name}" || path == $"/certificates/{name}/{V}")
            return (HttpStatusCode.OK, CertificateJson(name, certificate));
        if (path == $"/secrets/{name}/{V}")
        {
            return (HttpStatusCode.OK, $$"""
                {"value":"{{Convert.ToBase64String(pfx)}}","id":"{{Vault}}secrets/{{name}}/{{V}}","contentType":"application/x-pkcs12",
                 "kid":"{{Vault}}keys/{{name}}/{{V}}","managed":true,"attributes":{{Attributes}}}
                """);
        }

        return (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("NotFound", "x"));
    });

    // ---------- Lixeira e backup (segredos, chaves e certificados) ----------

    [Test]
    public async Task Secret_delete_recover_purge_backup_restore()
    {
        string secretBundle = $$"""{"id":"{{Vault}}secrets/s/{{V}}","attributes":{{Attributes}},"tags":{} }""";
        var vault = new FakeKeyVault((request, _) => (request.Method.Method, request.RequestUri!.AbsolutePath.TrimEnd('/')) switch
        {
            ("DELETE", "/secrets/s") => (HttpStatusCode.OK, DeletedJson("secrets", "s", secretBundle)),
            ("GET", "/deletedsecrets/s") => (HttpStatusCode.OK, DeletedJson("secrets", "s", secretBundle)),
            ("POST", "/deletedsecrets/s/recover") => (HttpStatusCode.OK, secretBundle),
            ("GET", "/secrets/s") => (HttpStatusCode.OK, secretBundle),
            ("DELETE", "/deletedsecrets/s") => (HttpStatusCode.NoContent, ""),
            ("POST", "/secrets/s/backup") => (HttpStatusCode.OK, BackupJson()),
            ("POST", "/secrets/restore") => (HttpStatusCode.OK, secretBundle),
            _ => (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("SecretNotFound", "x"))
        });
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var deleted = await store.DeleteSecretAsync("s");
        var recovered = await store.RecoverDeletedSecretAsync("s");
        var purged = await store.PurgeDeletedSecretAsync("s");
        var backup = await store.BackupSecretAsync("s");
        var restored = await store.RestoreSecretBackupAsync(backup.Value);

        await AssertDeleted(deleted.Value, "s");
        await Assert.That(recovered.Value.Name).IsEqualTo("s");
        await Assert.That(purged.IsSuccess).IsTrue();
        await Assert.That(backup.Value).IsEquivalentTo(BackupBytes);
        await Assert.That(restored.Value.Version).IsEqualTo(V);
        await AssertRestoreBody(vault, "/secrets/restore");
    }

    [Test]
    public async Task Key_delete_recover_purge_backup_restore()
    {
        using var rsa = RSA.Create(2048);
        string keyBundle = RsaKeyJson("k", rsa);
        var vault = new FakeKeyVault((request, _) => (request.Method.Method, request.RequestUri!.AbsolutePath.TrimEnd('/')) switch
        {
            ("DELETE", "/keys/k") => (HttpStatusCode.OK, DeletedJson("keys", "k", keyBundle)),
            ("GET", "/deletedkeys/k") => (HttpStatusCode.OK, DeletedJson("keys", "k", keyBundle)),
            ("POST", "/deletedkeys/k/recover") => (HttpStatusCode.OK, keyBundle),
            ("GET", "/keys/k") => (HttpStatusCode.OK, keyBundle),
            ("DELETE", "/deletedkeys/k") => (HttpStatusCode.NoContent, ""),
            ("POST", "/keys/k/backup") => (HttpStatusCode.OK, BackupJson()),
            ("POST", "/keys/restore") => (HttpStatusCode.OK, keyBundle),
            _ => (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("KeyNotFound", "x"))
        });
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());

        var deleted = await store.DeleteKeyAsync("k");
        var recovered = await store.RecoverDeletedKeyAsync("k");
        var purged = await store.PurgeDeletedKeyAsync("k");
        var backup = await store.BackupKeyAsync("k");
        var restored = await store.RestoreKeyBackupAsync(backup.Value);

        await AssertDeleted(deleted.Value, "k");
        await Assert.That(recovered.Value.Properties.Name).IsEqualTo("k");
        await Assert.That(recovered.Value.PublicKeySpki).IsEquivalentTo(rsa.ExportSubjectPublicKeyInfo());
        await Assert.That(purged.IsSuccess).IsTrue();
        await Assert.That(backup.Value).IsEquivalentTo(BackupBytes);
        await Assert.That(restored.Value.KeyType).IsEqualTo(VaultKeyType.Rsa);
        await AssertRestoreBody(vault, "/keys/restore");
    }

    [Test]
    public async Task Certificate_delete_recover_purge_backup_restore()
    {
        using var certificate = SelfSigned(withKey: false);
        string certificateBundle = CertificateJson("c", certificate);
        var vault = new FakeKeyVault((request, _) => (request.Method.Method, request.RequestUri!.AbsolutePath.TrimEnd('/')) switch
        {
            ("DELETE", "/certificates/c") => (HttpStatusCode.OK, DeletedJson("certificates", "c", certificateBundle)),
            ("GET", "/deletedcertificates/c") => (HttpStatusCode.OK, DeletedJson("certificates", "c", certificateBundle)),
            ("POST", "/deletedcertificates/c/recover") => (HttpStatusCode.OK, certificateBundle),
            ("GET", "/certificates/c") => (HttpStatusCode.OK, certificateBundle),
            ("DELETE", "/deletedcertificates/c") => (HttpStatusCode.NoContent, ""),
            ("POST", "/certificates/c/backup") => (HttpStatusCode.OK, BackupJson()),
            ("POST", "/certificates/restore") => (HttpStatusCode.OK, certificateBundle),
            _ => (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("CertificateNotFound", "x"))
        });
        var store = new AzureKeyVaultCertificateStore(vault.CreateClients());

        var deleted = await store.DeleteCertificateAsync("c");
        var recovered = await store.RecoverDeletedCertificateAsync("c");
        var purged = await store.PurgeDeletedCertificateAsync("c");
        var backup = await store.BackupCertificateAsync("c");
        var restored = await store.RestoreCertificateBackupAsync(backup.Value);

        await AssertDeleted(deleted.Value, "c");
        await Assert.That(recovered.Value.Cer).IsEquivalentTo(certificate.RawData);
        await Assert.That(purged.IsSuccess).IsTrue();
        await Assert.That(backup.Value).IsEquivalentTo(BackupBytes);
        await Assert.That(restored.Value.Properties.Thumbprint).IsEqualTo(certificate.Thumbprint);
        await AssertRestoreBody(vault, "/certificates/restore");
    }

    private static async Task AssertDeleted(DeletedVaultItem deleted, string name)
    {
        await Assert.That(deleted.Name).IsEqualTo(name);
        await Assert.That(deleted.DeletedOn).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1700000100));
        await Assert.That(deleted.ScheduledPurgeDate).IsEqualTo(DateTimeOffset.FromUnixTimeSeconds(1707776100));
    }

    private static async Task AssertRestoreBody(FakeKeyVault vault, string path)
    {
        using var json = JsonDocument.Parse(vault.Requests.Single(r => r.Authorized && r.Uri.AbsolutePath == path).Body);
        await Assert.That(FromBase64Url(json.RootElement.GetProperty("value").GetString()!)).IsEquivalentTo(BackupBytes);
    }

    // ---------- OperationTimeout ----------

    [Test]
    public async Task Long_operation_exceeding_OperationTimeout_returns_unavailable()
    {
        string secretBundle = $$"""{"id":"{{Vault}}secrets/s/{{V}}","attributes":{{Attributes}}}""";
        var vault = new FakeKeyVault((request, _) => request.Method == HttpMethod.Delete
            ? (HttpStatusCode.OK, DeletedJson("secrets", "s", secretBundle))
            : (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("SecretNotFound", "Exclusão ainda em andamento.")));   // nunca conclui
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(configure: o => o.OperationTimeout = TimeSpan.FromMilliseconds(300)));

        var started = TimeProvider.System.GetTimestamp();
        var result = await store.DeleteSecretAsync("s");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(30));
    }

    // ---------- UpdateSecretProperties: desempate só para item desabilitado ----------

    private const string Older = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Newer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// <summary>Duas versões criadas no mesmo segundo; a leitura sem versão (para desempatar) responde <paramref name="current"/>.</summary>
    private static FakeKeyVault TieVault(Func<(HttpStatusCode, string)> current) => new((request, _) =>
    {
        string path = request.RequestUri!.AbsolutePath.TrimEnd('/');
        if (request.Method == HttpMethod.Patch)
            return (HttpStatusCode.OK, $$"""{"id":"{{Vault}}secrets/x/{{path[(path.LastIndexOf('/') + 1)..]}}","attributes":{{Attributes}}}""");
        if (path.EndsWith("/versions", StringComparison.Ordinal))
        {
            return (HttpStatusCode.OK, $$"""
                {"value":[
                  {"id":"{{Vault}}secrets/x/{{Older}}","attributes":{"enabled":true,"created":1700000000,"updated":1700000000} },
                  {"id":"{{Vault}}secrets/x/{{Newer}}","attributes":{"enabled":false,"created":1700000000,"updated":1700000005} }]}
                """);
        }

        return current();
    });

    [Test]
    [Arguments("ForbiddenByRbac")]
    [Arguments("ForbiddenByConnection")]
    [Arguments("ForbiddenByFirewall")]
    [Arguments(null)]
    public async Task UpdateSecretProperties_with_tie_and_access_denied_403_fails_without_changes(string? innerCode)
    {
        var vault = TieVault(() => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "Access denied.", innerCode)));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.UpdateSecretPropertiesAsync("x", new SecretPropertiesUpdate { ContentType = "text/plain" });

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);
        await Assert.That(vault.Requests.Any(r => r.Method == "PATCH")).IsFalse();     // nenhuma versão alterada "no escuro"
    }

    [Test]
    public async Task UpdateSecretProperties_with_tie_and_disabled_current_version_breaks_tie_by_metadata()
    {
        var vault = TieVault(() => (HttpStatusCode.Forbidden,
            FakeKeyVault.ErrorJson("Forbidden", "Operation get is not allowed on a disabled secret.", "SecretDisabled")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.UpdateSecretPropertiesAsync("x", new SecretPropertiesUpdate { Enabled = true });

        await Assert.That(result.IsSuccess).IsTrue();
        // Desempate: maior UpdatedOn (a versão desabilitada, alterada depois)
        await Assert.That(vault.Requests.Single(r => r.Method == "PATCH" && r.Authorized).Uri.AbsolutePath).IsEqualTo($"/secrets/x/{Newer}");
    }

    // ---------- UpdateKeyProperties: metadados pela listagem (chave desabilitada pode ser reabilitada) ----------

    [Test]
    [Arguments(null)]
    [Arguments(V)]
    public async Task UpdateKeyProperties_reenables_disabled_key_without_key_get(string? version)
    {
        using var rsa = RSA.Create(2048);
        string list = $$"""{"value":[{"kid":"{{Vault}}keys/k/{{V}}","attributes":{"enabled":false,"created":1700000000,"updated":1700000000} }]}""";
        var vault = new FakeKeyVault((request, _) =>
        {
            string path = request.RequestUri!.AbsolutePath.TrimEnd('/');
            if (request.Method == HttpMethod.Patch)
                return (HttpStatusCode.OK, RsaKeyJson("k", rsa));
            if (path.EndsWith("/versions", StringComparison.Ordinal))
                return (HttpStatusCode.OK, list);
            // Como o serviço real: GET de chave desabilitada é recusado
            return (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "Operation get is not allowed on a disabled key.", "KeyDisabled"));
        });
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());

        var result = await store.UpdateKeyPropertiesAsync("k", new KeyPropertiesUpdate { Enabled = true }, version);

        await Assert.That(result.IsSuccess).IsTrue();
        var patch = vault.Requests.Single(r => r.Method == "PATCH" && r.Authorized);
        await Assert.That(patch.Uri.AbsolutePath).IsEqualTo($"/keys/k/{V}");
        await Assert.That(patch.Body).Contains("\"enabled\":true");
    }

    [Test]
    public async Task UpdateKeyProperties_of_missing_version_returns_NotFound_without_changes()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK,
            $$"""{"value":[{"kid":"{{Vault}}keys/k/{{V}}","attributes":{"enabled":true,"created":1700000000,"updated":1700000000} }]}"""));
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());

        var result = await store.UpdateKeyPropertiesAsync("k", new KeyPropertiesUpdate { Enabled = false }, Older);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That(vault.Requests.Any(r => r.Method == "PATCH")).IsFalse();
    }

    // ---------- Auxiliares ----------

    private static readonly byte[] BackupBytes = [0x0B, 0xAC, 0x4B, 0x09, 0x00, 0xFF];

    private static string BackupJson() => $$"""{"value":"{{ToBase64Url(BackupBytes)}}"}""";

    private static string DeletedJson(string collection, string name, string bundle) =>
        bundle.TrimEnd()[..^1] + $$""","recoveryId":"{{Vault}}deleted{{collection}}/{{name}}","deletedDate":1700000100,"scheduledPurgeDate":1707776100}""";

    private static string RsaKeyJson(string name, RSA rsa)
    {
        var parameters = rsa.ExportParameters(false);
        return $$"""
            {"key":{"kid":"{{Vault}}keys/{{name}}/{{V}}","kty":"RSA","key_ops":["encrypt","decrypt","wrapKey","unwrapKey","sign","verify"],
             "n":"{{ToBase64Url(parameters.Modulus!)}}","e":"{{ToBase64Url(parameters.Exponent!)}}"},"attributes":{{Attributes}}}
            """;
    }

    private static string OperationJson(string name, string status) => $$"""
        {"id":"{{Vault}}certificates/{{name}}/pending","issuer":{"name":"Self"},"csr":"","cancellation_requested":false,
         "status":"{{status}}","target":"{{Vault}}certificates/{{name}}","request_id":"r1"}
        """;

    private static string CertificateJson(string name, X509Certificate2 certificate) => $$"""
        {"id":"{{Vault}}certificates/{{name}}/{{V}}","kid":"{{Vault}}keys/{{name}}/{{V}}","sid":"{{Vault}}secrets/{{name}}/{{V}}",
         "x5t":"{{ToBase64Url(Convert.FromHexString(certificate.Thumbprint))}}","cer":"{{Convert.ToBase64String(certificate.RawData)}}",
         "attributes":{{Attributes}},
         "policy":{"id":"{{Vault}}certificates/{{name}}/policy","key_props":{"exportable":true,"kty":"RSA","key_size":2048,"reuse_key":false},
           "secret_props":{"contentType":"application/x-pkcs12"},"x509_props":{"subject":"CN={{name}}","validity_months":12},
           "issuer":{"name":"Self"},"attributes":{"enabled":true} },
         "tags":{} }
        """;

    private static X509Certificate2 SelfSigned(bool withKey)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=web", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        if (withKey)
            return certificate;

        using (certificate)
            return VaultCertificateLoader.LoadCertificate(certificate.RawData);
    }

    private static string ToBase64Url(byte[] data) => Base64UrlEncoder.Encode(data);

    private static byte[] FromBase64Url(string value) =>
        Base64UrlEncoder.TryDecode(value, out var bytes) ? bytes : throw new FormatException("Base64Url inválido na requisição.");
}
