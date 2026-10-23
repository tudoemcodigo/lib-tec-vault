using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Providers;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>
/// Importação de certificado PEM: detecção (inclusive com "Bag Attributes" do OpenSSL), carga local com a chave privada
/// (RSA e EC, com e sem senha) e conteúdo enviado ao cofre. Tudo gerado em memória, sem Azure.
/// </summary>
public class CertificatePemTests
{
    private const string Password = "senha-do-pem";

    private static readonly PbeParameters Pbe = new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);

    private static (string CertificatePem, X509Certificate2 Certificate) CreateRsa(out RSA key)
    {
        key = RSA.Create(2048);
        var request = new CertificateRequest("CN=pem-rsa", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return (certificate.ExportCertificatePem(), certificate);
    }

    private static (string CertificatePem, X509Certificate2 Certificate) CreateEc(out ECDsa key)
    {
        key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=pem-ec", key, HashAlgorithmName.SHA256);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        return (certificate.ExportCertificatePem(), certificate);
    }

    /// <summary>Formato do <c>openssl pkcs12 -nodes</c>: atributos antes de cada bloco.</summary>
    private static string OpenSslStyle(string certificatePem, string keyPem) =>
        "Bag Attributes\n    localKeyID: 01 00 00 00\n    friendlyName: meu-certificado-com-nome-longo-para-passar-de-64-bytes\n" +
        "subject=CN = pem-rsa\nissuer=CN = pem-rsa\n" + certificatePem + "\n" +
        "Bag Attributes\n    localKeyID: 01 00 00 00\nKey Attributes: <No Attributes>\n" + keyPem + "\n";

    [Test]
    public async Task Pem_rsa_without_password_loads_private_key()
    {
        var (pem, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
        {
            byte[] content = Encoding.ASCII.GetBytes(pem + "\n" + rsa.ExportPkcs8PrivateKeyPem());

            var error = VaultCertificateRules.InspectImport(content, null, CertificateContentFormat.Pem, out var subject);

            await Assert.That(VaultCertificateRules.IsPem(content)).IsTrue();
            await Assert.That(error).IsNull();
            await Assert.That(subject).IsEqualTo("CN=pem-rsa");
        }
    }

    [Test]
    public async Task Pem_rsa_pkcs1_without_password_loads_private_key()
    {
        var (pem, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
        {
            byte[] content = Encoding.ASCII.GetBytes(rsa.ExportRSAPrivateKeyPem() + "\n" + pem);   // chave antes do certificado

            await Assert.That(VaultCertificateRules.InspectImport(content, null, CertificateContentFormat.Pem, out _)).IsNull();
        }
    }

    [Test]
    public async Task Pem_rsa_with_password_requires_correct_password()
    {
        var (pem, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
        {
            byte[] content = Encoding.ASCII.GetBytes(pem + "\n" + rsa.ExportEncryptedPkcs8PrivateKeyPem(Password, Pbe));

            var ok = VaultCertificateRules.InspectImport(content, Password, CertificateContentFormat.Pem, out var subject);
            var wrong = VaultCertificateRules.InspectImport(content, "errada", CertificateContentFormat.Pem, out _);
            var missing = VaultCertificateRules.InspectImport(content, null, CertificateContentFormat.Pem, out _);

            await Assert.That(ok).IsNull();
            await Assert.That(subject).IsEqualTo("CN=pem-rsa");
            await Assert.That(wrong!.Field).IsEqualTo("certificate");
            await Assert.That(missing!.Field).IsEqualTo("certificate");
        }
    }

    [Test]
    public async Task Pem_ec_without_password_pkcs8_and_sec1()
    {
        var (pem, cert) = CreateEc(out var ec);
        using (cert)
        using (ec)
        {
            byte[] pkcs8 = Encoding.ASCII.GetBytes(pem + "\n" + ec.ExportPkcs8PrivateKeyPem());
            byte[] sec1 = Encoding.ASCII.GetBytes(pem + "\n" + ec.ExportECPrivateKeyPem());

            await Assert.That(VaultCertificateRules.InspectImport(pkcs8, null, CertificateContentFormat.Pem, out var subject)).IsNull();
            await Assert.That(VaultCertificateRules.InspectImport(sec1, null, CertificateContentFormat.Pem, out _)).IsNull();
            await Assert.That(subject).IsEqualTo("CN=pem-ec");
        }
    }

    [Test]
    public async Task Pem_ec_with_password()
    {
        var (pem, cert) = CreateEc(out var ec);
        using (cert)
        using (ec)
        {
            byte[] content = Encoding.ASCII.GetBytes(pem + "\n" + ec.ExportEncryptedPkcs8PrivateKeyPem(Password, Pbe));

            await Assert.That(VaultCertificateRules.InspectImport(content, Password, CertificateContentFormat.Pem, out _)).IsNull();
            await Assert.That(VaultCertificateRules.InspectImport(content, "errada", CertificateContentFormat.Pem, out _)).IsNotNull();
        }
    }

    [Test]
    public async Task OpenSsl_pem_with_bag_attributes_is_detected_and_loaded()
    {
        var (pem, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
        {
            byte[] content = Encoding.ASCII.GetBytes(OpenSslStyle(pem, rsa.ExportPkcs8PrivateKeyPem()));

            await Assert.That(content.AsSpan(0, 64).IndexOf("-----BEGIN"u8)).IsEqualTo(-1);   // o caso que a detecção antiga perdia
            await Assert.That(VaultCertificateRules.IsPem(content)).IsTrue();
            await Assert.That(VaultCertificateRules.InspectImport(content, null, CertificateContentFormat.Pem, out _)).IsNull();

            string normalized = Encoding.ASCII.GetString(VaultCertificateRules.NormalizePem(content));
            await Assert.That(normalized).DoesNotContain("Bag Attributes");
            await Assert.That(normalized).Contains("-----BEGIN CERTIFICATE-----");
            await Assert.That(normalized).Contains("-----BEGIN PRIVATE KEY-----");
        }
    }

    [Test]
    public async Task Pem_with_utf8_bom_is_detected_and_loaded()
    {
        var (pem, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
        {
            byte[] content = [0xEF, 0xBB, 0xBF, .. Encoding.ASCII.GetBytes(pem + "\n" + rsa.ExportPkcs8PrivateKeyPem())];

            await Assert.That(VaultCertificateRules.IsPem(content)).IsTrue();
            await Assert.That(VaultCertificateRules.InspectImport(content, null, CertificateContentFormat.Pem, out _)).IsNull();
        }
    }

    [Test]
    public async Task Pem_without_key_or_with_key_of_other_certificate_is_rejected()
    {
        var (pem, cert) = CreateRsa(out var rsa);
        using var other = RSA.Create(2048);
        using (cert)
        using (rsa)
        {
            byte[] noKey = Encoding.ASCII.GetBytes(pem);
            byte[] wrongKey = Encoding.ASCII.GetBytes(pem + "\n" + other.ExportPkcs8PrivateKeyPem());

            await Assert.That(VaultCertificateRules.InspectImport(noKey, null, CertificateContentFormat.Pem, out _)!.Field).IsEqualTo("certificate");
            await Assert.That(VaultCertificateRules.InspectImport(wrongKey, null, CertificateContentFormat.Pem, out _)!.Field).IsEqualTo("certificate");
        }
    }

    [Test]
    public async Task Pfx_is_not_mistaken_for_pem()
    {
        var (_, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
            await Assert.That(VaultCertificateRules.IsPem(cert.Export(X509ContentType.Pkcs12, "x"))).IsFalse();
    }

    [Test]
    public async Task Pem_import_sends_only_pem_blocks_as_pem_content()
    {
        var (pem, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
        {
            byte[] content = Encoding.ASCII.GetBytes(OpenSslStyle(pem, rsa.ExportPkcs8PrivateKeyPem()));
            string response = $$$"""
                {"id":"{{{FakeKeyVault.VaultUri}}}certificates/pem/{{{FakeKeyVault.Version}}}","cer":"{{{Convert.ToBase64String(cert.RawData)}}}",
                 "attributes":{"enabled":true,"created":1700000000,"updated":1700000000}}
                """;
            var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, response));
            var store = new AzureKeyVaultCertificateStore(vault.CreateClients());

            var result = await store.ImportCertificateAsync("pem", content);

            await Assert.That(result.IsSuccess).IsTrue();
            var post = vault.Requests.Single(r => r.Method == "POST" && r.Authorized);
            using var json = JsonDocument.Parse(post.Body);
            string sent = json.RootElement.GetProperty("value").GetString()!;
            string contentType = json.RootElement.GetProperty("policy").GetProperty("secret_props").GetProperty("contentType").GetString()!;
            await Assert.That(contentType).IsEqualTo("application/x-pem-file");
            await Assert.That(sent).Contains("-----BEGIN CERTIFICATE-----");
            await Assert.That(sent).DoesNotContain("Bag Attributes");
        }
    }

    [Test]
    public async Task Pem_normalization_and_loading_do_not_change_caller_content()
    {
        // As cópias internas (texto PEM decodificado, PEM normalizado) são zeradas; o array recebido é do chamador e fica intacto
        var (pem, cert) = CreateRsa(out var rsa);
        using (cert)
        using (rsa)
        {
            string keyPem = rsa.ExportPkcs8PrivateKeyPem();
            byte[] content = Encoding.ASCII.GetBytes(OpenSslStyle(pem, keyPem));
            byte[] original = [.. content];

            byte[] normalized = VaultCertificateRules.NormalizePem(content);
            using var loaded = VaultCertificateRules.LoadPem(content, null);
            var memory = await Memory.Certificates().ImportCertificateAsync("pem", content);

            await Assert.That(Encoding.ASCII.GetString(normalized)).IsEqualTo(pem + "\n" + keyPem + "\n");
            await Assert.That(loaded.HasPrivateKey).IsTrue();
            await Assert.That(memory.IsSuccess).IsTrue();
            await Assert.That(content.AsSpan().SequenceEqual(original)).IsTrue();
        }
    }

    [Test]
    public async Task Invalid_pem_import_is_rejected_without_calling_vault()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var store = new AzureKeyVaultCertificateStore(vault.CreateClients());

        var result = await store.ImportCertificateAsync("pem", Encoding.ASCII.GetBytes("-----BEGIN CERTIFICATE-----\nlixo\n-----END CERTIFICATE-----\n"));

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(vault.Requests).IsEmpty();
    }
}
