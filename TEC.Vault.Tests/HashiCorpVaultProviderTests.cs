using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Abstractions;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HashiCorpVault;
using TEC.Vault.InMemory;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Vault.Synced;
using TEC.Vault.Tests.Contracts;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Opções apontando para o Vault simulado, com o token da service account em arquivo.</summary>
internal static class HashiCorpTestOptions
{
    public static HashiCorpVaultOptions Create(FakeHashiCorpVault fake, string folder, Action<HashiCorpVaultOptions>? configure = null)
    {
        var jwt = Path.Combine(folder, "sa-token");
        if (!File.Exists(jwt))
            File.WriteAllText(jwt, fake.ServiceAccountJwt);

        var options = new HashiCorpVaultOptions { Address = new Uri("https://vault.teste:8200") };
        options.Auth.Method = HashiCorpVaultAuthMethod.Kubernetes;
        options.Auth.Role = FakeHashiCorpVault.Role;
        options.Auth.ServiceAccountTokenFile = jwt;
        options.Kv.BasePath = "minha-api";
        options.Pki.Role = FakeHashiCorpVault.Role;
        options.Http.Handler = fake;
        options.Http.MaxRetries = 2;
        configure?.Invoke(options);
        return options;
    }
}

[InheritsTests]
public class HashiCorpVaultSecretStoreContractTests : SecretStoreContract, IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("tec-vault-hcv").FullName;

    protected override Task<ISecretStore> CreateStoreAsync() =>
        Task.FromResult<ISecretStore>(new HashiCorpVaultSecretStore(HashiCorpTestOptions.Create(new FakeHashiCorpVault(), _folder)));

    protected override string UnknownVersion(string existing) => "999";

    public void Dispose()
    {
        Directory.Delete(_folder, recursive: true);
        GC.SuppressFinalize(this);
    }
}

[InheritsTests]
public class HashiCorpVaultKeyStoreContractTests : KeyStoreContract, IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("tec-vault-hcv").FullName;

    protected override Task<IKeyStore> CreateStoreAsync() =>
        Task.FromResult<IKeyStore>(new HashiCorpVaultKeyStore(HashiCorpTestOptions.Create(new FakeHashiCorpVault(), _folder)));

    public void Dispose()
    {
        Directory.Delete(_folder, recursive: true);
        GC.SuppressFinalize(this);
    }
}

[InheritsTests]
public class HashiCorpVaultCertificateStoreContractTests : CertificateStoreContract, IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("tec-vault-hcv").FullName;

    protected override string? SelfSignedIssuer => HashiCorpVaultCertificateStore.SelfIssuer;

    protected override Task<ICertificateStore> CreateStoreAsync() =>
        Task.FromResult<ICertificateStore>(new HashiCorpVaultCertificateStore(HashiCorpTestOptions.Create(new FakeHashiCorpVault(), _folder)));

    public void Dispose()
    {
        Directory.Delete(_folder, recursive: true);
        GC.SuppressFinalize(this);
    }
}

[InheritsTests]
public class InMemoryKeyStoreContractTests : KeyStoreContract
{
    protected override Task<IKeyStore> CreateStoreAsync() => Task.FromResult<IKeyStore>(new InMemoryKeyStore(Memory.Options()));
}

[InheritsTests]
public class InMemoryCertificateStoreContractTests : CertificateStoreContract
{
    protected override Task<ICertificateStore> CreateStoreAsync() => Task.FromResult<ICertificateStore>(new InMemoryCertificateStore(Memory.Options()));
}

/// <summary>Comportamento específico do HashiCorp Vault.</summary>
public class HashiCorpVaultProviderTests : TempFolderTest
{
    private HashiCorpVaultOptions Options(FakeHashiCorpVault fake, Action<HashiCorpVaultOptions>? configure = null) =>
        HashiCorpTestOptions.Create(fake, Folder, configure);

    // ---------- Login ----------

    [Test]
    public async Task Kubernetes_logs_in_once_and_renews_after_revocation()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultSecretStore(Options(fake));
        await store.SetSecretAsync("db", "x");
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => store.GetSecretAsync("db")));

        await Assert.That(fake.Logins).IsEqualTo(1);

        fake.RevokeTokens();
        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("x");
        await Assert.That(fake.Logins).IsEqualTo(2);
    }

    [Test]
    public async Task AppRole_reads_secret_id_from_file()
    {
        var fake = new FakeHashiCorpVault();
        var secretId = Write("secret-id", fake.SecretId + "\n");
        using var store = new HashiCorpVaultSecretStore(Options(fake, o =>
        {
            o.Auth.Method = HashiCorpVaultAuthMethod.AppRole;
            o.Auth.RoleId = FakeHashiCorpVault.RoleId;
            o.Auth.SecretIdFile = secretId;
        }));

        await Assert.That((await store.SetSecretAsync("db", "x")).IsSuccess).IsTrue();
        await Assert.That(fake.Requests).Contains("POST v1/auth/approle/login");
    }

    [Test]
    public async Task Ready_token_is_reread_from_file()
    {
        var fake = new FakeHashiCorpVault();
        var tokenFile = Write("token", "hvs.antigo");
        using var store = new HashiCorpVaultSecretStore(Options(fake, o =>
        {
            o.Auth.Method = HashiCorpVaultAuthMethod.Token;
            o.Auth.TokenFile = tokenFile;
        }));

        var refused = await store.ListSecretsAsync();
        File.WriteAllText(tokenFile, fake.StaticToken);   // o Vault Agent renovou o token no arquivo
        var accepted = await store.ListSecretsAsync();

        await Assert.That(refused.Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);
        await Assert.That(accepted.IsSuccess).IsTrue();
        await Assert.That(fake.Logins).IsEqualTo(0);
    }

    [Test]
    public async Task Rejected_credential_becomes_AuthenticationFailed()
    {
        var fake = new FakeHashiCorpVault { ServiceAccountJwt = "outro" };
        File.WriteAllText(Path.Combine(Folder, "sa-token"), "jwt-errado");
        using var store = new HashiCorpVaultSecretStore(Options(fake));

        await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
    }

    [Test]
    public async Task Namespace_goes_in_every_request()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultSecretStore(Options(fake, o => o.Namespace = "time-a"));

        await store.SetSecretAsync("db", "x");

        await Assert.That(fake.Namespaces.All(n => n == "time-a")).IsTrue();
    }

    [Test]
    public async Task Read_is_retried_on_transient_failure()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultSecretStore(Options(fake));
        await store.SetSecretAsync("db", "x");
        fake.Failures.Enqueue(HttpStatusCode.ServiceUnavailable);

        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("x");
    }

    // ---------- KV v2 ----------

    [Test]
    public async Task Recycle_bin_deletes_recovers_and_purges()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultSecretStore(Options(fake));
        await store.SetSecretAsync("db", "v1");
        await store.SetSecretAsync("db", "v2");

        await store.DeleteSecretAsync("db");
        var deleted = await store.ListDeletedSecretsAsync();
        var setWhileDeleted = await store.SetSecretAsync("db", "v3");
        var recovered = await store.RecoverDeletedSecretAsync("db");

        await Assert.That(deleted.Value.Select(d => d.Name)).IsEquivalentTo(["db"]);
        await Assert.That(setWhileDeleted.Error!.Code).IsEqualTo(VaultErrors.ConflictCode);
        await Assert.That(recovered.Value.Version).IsEqualTo("2");
        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("v2");

        await store.DeleteSecretAsync("db");
        await Assert.That((await store.PurgeDeletedSecretAsync("db")).IsSuccess).IsTrue();
        await Assert.That((await store.ListDeletedSecretsAsync()).Value).IsEmpty();
        await Assert.That((await store.SetSecretAsync("db", "novo")).Value.Version).IsEqualTo("1");
    }

    [Test]
    public async Task Purge_of_active_secret_returns_NotFound()
    {
        using var store = new HashiCorpVaultSecretStore(Options(new FakeHashiCorpVault()));
        await store.SetSecretAsync("db", "x");

        await Assert.That((await store.PurgeDeletedSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.GetSecretAsync("db")).IsSuccess).IsTrue();
    }

    [Test]
    public async Task Tags_become_custom_metadata_and_value_field_is_configurable()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultSecretStore(Options(fake, o => o.Kv.ValueField = "senha"));

        await store.SetSecretAsync("db", "x", new SecretWriteOptions { Tags = new Dictionary<string, string> { ["dono"] = "time-a" } });
        await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate { Tags = new Dictionary<string, string> { ["dono"] = "time-b" } });

        var listed = (await store.ListSecretsAsync()).Value.Single();
        await Assert.That(listed.Tags["dono"]).IsEqualTo("time-b");
        await Assert.That(listed.Id).IsEqualTo("secret/minha-api/db");
        await Assert.That(fake.Requests).Contains("POST v1/secret/data/minha-api/db");
    }

    [Test]
    public async Task Item_written_by_other_tool_without_value_field_is_unexpected_format()
    {
        var fake = new FakeHashiCorpVault();
        fake.SeedKv("minha-api/db", new Dictionary<string, string> { ["username"] = "app" });
        using var store = new HashiCorpVaultSecretStore(Options(fake));

        await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    [Test]
    public async Task Names_differing_only_in_case_make_read_ambiguous()
    {
        var fake = new FakeHashiCorpVault();
        fake.SeedKv("minha-api/Senha", new Dictionary<string, string> { ["value"] = "a" });
        fake.SeedKv("minha-api/SENHA", new Dictionary<string, string> { ["value"] = "b" });
        using var store = new HashiCorpVaultSecretStore(Options(fake));

        await Assert.That((await store.GetSecretAsync("SENHA")).Value.Value).IsEqualTo("b");
        await Assert.That((await store.GetSecretAsync("senha")).Error!.Code).IsEqualTo(VaultErrors.ConflictCode);
    }

    [Test]
    public async Task Certificates_folder_does_not_appear_among_secrets()
    {
        var fake = new FakeHashiCorpVault();
        var options = Options(fake);
        using var secrets = new HashiCorpVaultSecretStore(options);
        using var certificates = new HashiCorpVaultCertificateStore(options);
        await secrets.SetSecretAsync("db", "x");
        await certificates.CreateCertificateAsync("api", new CreateCertificateOptions { Subject = "CN=api", Issuer = "Self", KeySize = 2048 });

        await Assert.That((await secrets.ListSecretsAsync()).Value.Select(s => s.Name)).IsEquivalentTo(["db"]);
        await Assert.That((await certificates.ListCertificatesAsync()).Value.Select(c => c.Name)).IsEquivalentTo(["api"]);
    }

    [Test]
    public async Task Options_kv_lacks_are_rejected_before_call()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultSecretStore(Options(fake));

        var result = await store.SetSecretAsync("db", "x", new SecretWriteOptions { ContentType = "text/plain" });

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(fake.Requests).IsEmpty();
    }

    // ---------- Transit ----------

    [Test]
    public async Task Deleting_key_allows_deletion_first()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultKeyStore(Options(fake));
        await store.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });

        var deleted = await store.DeleteKeyAsync("k");

        await Assert.That(deleted.IsSuccess).IsTrue();
        var requests = fake.Requests.ToList();
        await Assert.That(requests.IndexOf("POST v1/transit/keys/k/config")).IsLessThan(requests.IndexOf("DELETE v1/transit/keys/k"));
    }

    [Test]
    public async Task Creating_existing_key_adds_version_or_conflicts_if_type_changes()
    {
        using var store = new HashiCorpVaultKeyStore(Options(new FakeHashiCorpVault()));
        await store.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });

        var again = await store.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });
        var otherType = await store.CreateKeyAsync("k", new CreateKeyOptions { KeyType = VaultKeyType.Ec });

        await Assert.That(again.Value.Version).IsEqualTo("2");
        await Assert.That(otherType.Error!.Code).IsEqualTo(VaultErrors.ConflictCode);
    }

    [Test]
    public async Task Options_transit_lacks_are_rejected()
    {
        using var store = new HashiCorpVaultKeyStore(Options(new FakeHashiCorpVault()));

        var expires = await store.CreateKeyAsync("k", new CreateKeyOptions { ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) });
        var hsm = await store.CreateKeyAsync("k", new CreateKeyOptions { HardwareProtected = true });

        await Assert.That(expires.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(hsm.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
    }

    // ---------- PKI ----------

    [Test]
    public async Task Certificate_issued_by_pki_from_csr()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultCertificateStore(Options(fake));

        var created = await store.CreateCertificateAsync("api", new CreateCertificateOptions
        {
            Subject = "CN=api.interno",
            DnsNames = ["api.interno"],
            KeyType = VaultKeyType.Ec,
            Curve = VaultKeyCurve.P384,
            Exportable = true
        });
        using var downloaded = (await store.DownloadCertificateAsync("api")).Value;

        await Assert.That(created.IsSuccess).IsTrue();
        await Assert.That(downloaded.Issuer).IsEqualTo(fake.Ca.Subject);
        await Assert.That(downloaded.HasPrivateKey).IsTrue();
        await Assert.That(downloaded.GetECDsaPublicKey()!.KeySize).IsEqualTo(384);
        await Assert.That(fake.Requests).Contains("POST v1/pki/sign/minha-api");
    }

    [Test]
    public async Task Explicit_issuer_uses_issuer_path()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultCertificateStore(Options(fake));

        var known = await store.CreateCertificateAsync("a", new CreateCertificateOptions { Subject = "CN=a", Issuer = "default", KeySize = 2048 });
        var unknown = await store.CreateCertificateAsync("b", new CreateCertificateOptions { Subject = "CN=b", Issuer = "outra-ca", KeySize = 2048 });

        await Assert.That(known.IsSuccess).IsTrue();
        await Assert.That(unknown.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
    }

    [Test]
    public async Task Without_pki_role_only_self_signed()
    {
        using var store = new HashiCorpVaultCertificateStore(Options(new FakeHashiCorpVault(), o => o.Pki.Role = null));

        var pki = await store.CreateCertificateAsync("a", new CreateCertificateOptions { Subject = "CN=a", KeySize = 2048 });
        var self = await store.CreateCertificateAsync("b", new CreateCertificateOptions { Subject = "CN=b", Issuer = "Self", KeySize = 2048 });

        await Assert.That(pki.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
        await Assert.That(self.IsSuccess).IsTrue();
    }

    [Test]
    public async Task Reserved_tag_is_rejected()
    {
        using var store = new HashiCorpVaultCertificateStore(Options(new FakeHashiCorpVault()));

        var result = await store.CreateCertificateAsync("a", new CreateCertificateOptions
        {
            Subject = "CN=a",
            Issuer = "Self",
            KeySize = 2048,
            Tags = new Dictionary<string, string> { ["tec.disabled"] = "false" }
        });

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
    }

    // ---------- Opções e configuração ----------

    [Test]
    [Arguments("http://vault.teste:8200")]
    [Arguments("http://localhost:8200")]
    [Arguments("https://vault.teste:8200/v1")]
    [Arguments("https://user:pass@vault.teste:8200")]
    public async Task Insecure_address_is_rejected(string address)
    {
        await Assert.That(() => new HashiCorpVaultSecretStore(Options(new FakeHashiCorpVault(), o => o.Address = new Uri(address))))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("../outro")]
    [Arguments("/minha-api")]
    [Arguments("a b")]
    public async Task Invalid_path_is_rejected(string path)
    {
        await Assert.That(() => new HashiCorpVaultSecretStore(Options(new FakeHashiCorpVault(), o => o.Kv.BasePath = path)))
            .Throws<InvalidOperationException>();
    }

    private IConfiguration Config(params (string Key, string Value)[] extra)
    {
        Write("sa-token", new FakeHashiCorpVault().ServiceAccountJwt);
        var values = new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "HashiCorpVault",
            ["Vault:HashiCorpVault:Address"] = "https://vault.teste:8200",
            ["Vault:HashiCorpVault:Auth:Method"] = "Kubernetes",
            ["Vault:HashiCorpVault:Auth:Role"] = FakeHashiCorpVault.Role,
            ["Vault:HashiCorpVault:Auth:ServiceAccountTokenFile"] = Path.Combine(Folder, "sa-token"),
            ["Vault:HashiCorpVault:Kv:BasePath"] = "minha-api",
            ["Vault:HashiCorpVault:Pki:Role"] = FakeHashiCorpVault.Role
        };
        foreach (var (key, value) in extra)
            values["Vault:" + key] = value;
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build().GetSection("Vault");
    }

    [Test]
    public async Task By_configuration_three_stores_share_one_login()
    {
        var fake = new FakeHashiCorpVault();
        var services = new ServiceCollection();
        services.AddTecVault(Config(), p => p.AddHashiCorpVault(o => o.Http.Handler = fake));
        await using var sp = services.BuildServiceProvider();

        await sp.GetRequiredService<ISecretStore>().SetSecretAsync("db", "x");
        await sp.GetRequiredService<IKeyStore>().CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });
        await sp.GetRequiredService<ICertificateStore>().CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=c", KeySize = 2048 });

        await Assert.That(fake.Logins).IsEqualTo(1);
        await Assert.That((await sp.GetRequiredService<IVaultHealthProbe>().CheckAccessAsync()).IsSuccess).IsTrue();
    }

    [Test]
    public async Task Secrets_from_another_provider_and_keys_from_vault()
    {
        Write("segredos/db", "do-arquivo");
        var fake = new FakeHashiCorpVault();
        var services = new ServiceCollection();
        services.AddTecVault(Config(("Secrets:Provider", "Directory"), ("Directory:Path", Path.Combine(Folder, "segredos")), ("Certificates:Provider", "None")),
            p => p.AddHashiCorpVault(o => o.Http.Handler = fake).AddSynced());
        await using var sp = services.BuildServiceProvider();

        await Assert.That(sp.GetRequiredService<ISecretReader>()).IsTypeOf<DirectorySecretStore>();
        await Assert.That(sp.GetRequiredService<IKeyCryptography>()).IsTypeOf<HashiCorpVaultKeyStore>();
        await Assert.That(sp.GetService<ICertificateReader>()).IsNull();
    }

    [Test]
    [Arguments("HashiCorpVault:Auth:Token")]
    [Arguments("HashiCorpVault:Auth:SecretId")]
    [Arguments("HashiCorpVault:Auth:Jwt")]
    public async Task Plain_text_credential_in_configuration_is_rejected(string key)
    {
        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(Config((key, "hvs.colado")), p => p.AddHashiCorpVault()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).DoesNotContain("hvs.colado");
    }

    [Test]
    public async Task Unknown_key_in_subsection_is_rejected()
    {
        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(Config(("HashiCorpVault:Kv:BasPath", "x")), p => p.AddHashiCorpVault()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:HashiCorpVault:Kv:BasPath");
    }
}
