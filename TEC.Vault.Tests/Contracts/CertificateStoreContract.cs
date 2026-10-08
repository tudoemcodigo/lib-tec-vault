using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TEC.Vault.Abstractions;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Keys;

namespace TEC.Vault.Tests.Contracts;

/// <summary>Contrato de <see cref="ICertificateStore"/>: criação autoassinada, importação, download controlado, habilitar e excluir.</summary>
public abstract class CertificateStoreContract
{
    /// <summary>Cria o store vazio.</summary>
    protected abstract Task<ICertificateStore> CreateStoreAsync();

    /// <summary>Valor de <see cref="CreateCertificateOptions.Issuer"/> que gera autoassinado no provedor (padrão: <c>null</c>).</summary>
    protected virtual string? SelfSignedIssuer => null;

    private CreateCertificateOptions SelfSigned(bool exportable = true, VaultKeyType type = VaultKeyType.Rsa) => new()
    {
        Subject = "CN=api.exemplo.com",
        DnsNames = ["api.exemplo.com"],
        Issuer = SelfSignedIssuer,
        KeyType = type,
        KeySize = 2048,
        Exportable = exportable
    };

    private static byte[] Pfx(string password)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=importado", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return certificate.Export(X509ContentType.Pkcs12, password);
    }

    [Test]
    public async Task Creates_self_signed_and_reads_public_part()
    {
        var store = await CreateStoreAsync();

        var created = await store.CreateCertificateAsync("api", SelfSigned());
        var read = await store.GetCertificateAsync("api");

        await Assert.That(created.IsSuccess).IsTrue();
        using var certificate = read.Value.ToX509Certificate();
        await Assert.That(certificate.Subject).IsEqualTo("CN=api.exemplo.com");
        await Assert.That(certificate.HasPrivateKey).IsFalse();
        await Assert.That(read.Value.Properties.Thumbprint).IsEqualTo(certificate.Thumbprint);
        await Assert.That(read.Value.Properties.ExpiresOn).IsNotNull();
    }

    [Test]
    public async Task Download_brings_private_key_only_if_exportable()
    {
        var store = await CreateStoreAsync();
        await store.CreateCertificateAsync("exportavel", SelfSigned(exportable: true));
        await store.CreateCertificateAsync("preso", SelfSigned(exportable: false, type: VaultKeyType.Ec));

        var exported = await store.DownloadCertificateAsync("exportavel");
        var locked = await store.DownloadCertificateAsync("preso");

        using var certificate = exported.Value;
        await Assert.That(certificate.HasPrivateKey).IsTrue();
        await Assert.That(locked.Error!.Code).IsEqualTo(VaultErrors.NotExportableCode);
    }

    [Test]
    public async Task Imports_pfx_with_password()
    {
        var store = await CreateStoreAsync();

        var imported = await store.ImportCertificateAsync("importado", Pfx("senha-do-pfx"),
            new ImportCertificateOptions { Password = "senha-do-pfx", Exportable = true });
        var downloaded = await store.DownloadCertificateAsync("importado");

        await Assert.That(imported.IsSuccess).IsTrue();
        using var certificate = downloaded.Value;
        await Assert.That(certificate.Subject).IsEqualTo("CN=importado");
        await Assert.That(certificate.HasPrivateKey).IsTrue();
    }

    [Test]
    public async Task Pfx_with_wrong_password_is_rejected()
    {
        var store = await CreateStoreAsync();

        var result = await store.ImportCertificateAsync("importado", Pfx("certa"), new ImportCertificateOptions { Password = "errada" });

        await Assert.That(result.IsSuccess).IsFalse();
    }

    [Test]
    public async Task Disabled_certificate_is_not_downloaded()
    {
        var store = await CreateStoreAsync();
        await store.CreateCertificateAsync("api", SelfSigned());

        var updated = await store.UpdateCertificatePropertiesAsync("api", new CertificatePropertiesUpdate { Enabled = false });
        var download = await store.DownloadCertificateAsync("api");

        await Assert.That(updated.Value.Enabled).IsFalse();
        await Assert.That(download.Error!.Code).IsEqualTo(VaultErrors.DisabledCode);
    }

    [Test]
    public async Task New_version_lists_versions_and_deletion_removes_from_read()
    {
        var store = await CreateStoreAsync();
        var first = await store.CreateCertificateAsync("api", SelfSigned());
        var second = await store.CreateCertificateAsync("api", SelfSigned());

        await Assert.That(second.Value.Version).IsNotEqualTo(first.Value.Version);
        await Assert.That((await store.ListCertificateVersionsAsync("api")).Value.Count).IsEqualTo(2);
        await Assert.That((await store.ListCertificatesAsync()).Value.Select(c => c.Name)).IsEquivalentTo(["api"]);

        var deleted = await store.DeleteCertificateAsync("api");

        await Assert.That(deleted.IsSuccess).IsTrue();
        await Assert.That((await store.GetCertificateAsync("api")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.ListCertificatesAsync()).Value).IsEmpty();
    }

    [Test]
    public async Task Missing_returns_NotFound()
    {
        var store = await CreateStoreAsync();

        await Assert.That((await store.GetCertificateAsync("nao-existe")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.DownloadCertificateAsync("nao-existe")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }
}
