using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Abstractions;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.DependencyInjection;
using TEC.Vault.HashiCorpVault;
using TEC.Vault.Infisical;
using TEC.Vault.Keys;
using TEC.Vault.Providers.Http;
using TEC.Vault.Secrets;
using TEC.Vault.Synced;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>Regressões dos achados da revisão técnica de 2026-10-19 (docs/revisao-tecnica.md, RT-01 a RT-14).</summary>
public class TechnicalReviewRegressionTests : TempFolderTest
{
    private HashiCorpVaultOptions HashiCorp(FakeHashiCorpVault fake, Action<HashiCorpVaultOptions>? configure = null) =>
        HashiCorpTestOptions.Create(fake, Folder, configure);

    // ---------- RT-02: 5xx/429 no login mantêm o status real ----------

    [Test]
    [Arguments(HttpStatusCode.ServiceUnavailable, VaultErrors.UnavailableCode)]
    [Arguments(HttpStatusCode.InternalServerError, VaultErrors.UnavailableCode)]
    [Arguments(HttpStatusCode.TooManyRequests, VaultErrors.ThrottledCode)]
    [Arguments(HttpStatusCode.BadRequest, VaultErrors.AuthenticationFailedCode)]
    public async Task HashiCorp_login_failure_keeps_real_status(HttpStatusCode status, string expected)
    {
        var fake = new FakeHashiCorpVault();
        fake.LoginFailures.Enqueue(status);
        using var store = new HashiCorpVaultSecretStore(HashiCorp(fake, o => o.Http.MaxRetries = 0));

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(expected);
    }

    [Test]
    [Arguments(HttpStatusCode.ServiceUnavailable, VaultErrors.UnavailableCode)]
    [Arguments(HttpStatusCode.TooManyRequests, VaultErrors.ThrottledCode)]
    [Arguments(HttpStatusCode.Unauthorized, VaultErrors.AuthenticationFailedCode)]
    public async Task Infisical_login_failure_keeps_real_status(HttpStatusCode status, string expected)
    {
        var fake = new FakeInfisical();
        fake.LoginFailures.Enqueue(status);
        using var store = InfisicalTestStore.Create(fake, Folder, o => o.Http.MaxRetries = 0);

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(expected);
    }

    [Test]
    public async Task Login_unavailable_opens_the_circuit()
    {
        var fake = new FakeHashiCorpVault();
        for (var i = 0; i < 50; i++)
            fake.LoginFailures.Enqueue(HttpStatusCode.ServiceUnavailable);
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        using var store = new HashiCorpVaultSecretStore(HashiCorp(fake, o =>
        {
            o.Http.MaxRetries = 0;
            o.TimeProvider = time;
            o.Http.CircuitBreaker.MinimumThroughput = 2;
        }));

        Result<VaultSecret>? last = null;
        for (var i = 0; i < 6; i++)
        {
            last = await store.GetSecretAsync("db");
            time.Now = time.Now.AddSeconds(3);   // passa a janela da falha guardada (RT-03): cada chamada tenta o login
        }

        await Assert.That(last!.Error!.Code).IsEqualTo(VaultErrors.CircuitOpenCode);
    }

    // ---------- RT-03: falha de login compartilhada ----------

    [Test]
    public async Task Concurrent_calls_share_one_failed_login_and_the_failure_is_kept_briefly()
    {
        var calls = 0;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        using var source = new VaultTokenSource(async _ =>
        {
            Interlocked.Increment(ref calls);
            await release.Task;
            throw new VaultLoginException("recusado");
        }, time);

        var waiting = Enumerable.Range(0, 20).Select(_ => source.GetAsync(CancellationToken.None).AsTask()).ToList();
        release.SetResult();
        var failures = 0;
        foreach (var task in waiting)
        {
            try
            {
                await task;
            }
            catch (VaultLoginException)
            {
                failures++;
            }
        }

        await Assert.That(failures).IsEqualTo(20);
        await Assert.That(calls).IsEqualTo(1);

        // Dentro da janela: falha na hora, sem novo login
        await Assert.That(async () => await source.GetAsync(CancellationToken.None)).Throws<VaultLoginException>();
        await Assert.That(calls).IsEqualTo(1);

        // Depois da janela: tenta de novo
        time.Now = time.Now + VaultTokenSource.FailureCooldown + TimeSpan.FromMilliseconds(1);
        await Assert.That(async () => await source.GetAsync(CancellationToken.None)).Throws<VaultLoginException>();
        await Assert.That(calls).IsEqualTo(2);
    }

    [Test]
    public async Task Caller_cancellation_does_not_cancel_the_shared_login()
    {
        var calls = 0;
        var gate = new TaskCompletionSource<VaultToken>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var source = new VaultTokenSource(ct =>
        {
            Interlocked.Increment(ref calls);
            return gate.Task.WaitAsync(ct);
        });
        using var cancel = new CancellationTokenSource();

        var canceled = source.GetAsync(cancel.Token).AsTask();
        var other = source.GetAsync(CancellationToken.None).AsTask();
        await cancel.CancelAsync();
        await Assert.That(async () => await canceled).Throws<OperationCanceledException>();
        gate.SetResult(new VaultToken("tok", null));

        await Assert.That(await other.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo("tok");
        await Assert.That(calls).IsEqualTo(1);
    }

    // ---------- RT-06: token de vida curta ----------

    [Test]
    public async Task Short_lived_token_is_reused_until_half_of_its_life()
    {
        var calls = 0;
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        using var source = new VaultTokenSource(_ =>
        {
            Interlocked.Increment(ref calls);
            return Task.FromResult(new VaultToken("tok-" + calls, time.Now.AddSeconds(8)));
        }, time);

        await source.GetAsync(CancellationToken.None);
        await source.GetAsync(CancellationToken.None);
        await Assert.That(calls).IsEqualTo(1);

        time.Now = time.Now.AddSeconds(5);   // passou da metade da vida (4 s): renova
        await source.GetAsync(CancellationToken.None);
        await Assert.That(calls).IsEqualTo(2);
    }

    // ---------- RT-13: o token guardado não aparece em ToString ----------

    [Test]
    public async Task Cached_token_entry_does_not_print_the_token()
    {
        using var source = new VaultTokenSource(_ => Task.FromResult(new VaultToken("hvs.valor-secreto", null)));
        await source.GetAsync(CancellationToken.None);

        var entry = typeof(VaultTokenSource).GetField("_current", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(source)!;

        await Assert.That(entry.ToString()!).DoesNotContain("hvs.valor-secreto");
        await Assert.That(entry.GetType().GetCustomAttribute<System.Diagnostics.DebuggerDisplayAttribute>()).IsNotNull();
    }

    // ---------- RT-04: 403 de política não refaz o login ----------

    [Test]
    public async Task Policy_forbidden_does_not_log_in_again_nor_drop_the_shared_token()
    {
        var fake = new FakeHashiCorpVault();
        fake.ForbiddenPaths.Add("secret/metadata/minha-api/proibido");
        fake.ForbiddenPaths.Add("secret/data/minha-api/proibido");
        using var store = new HashiCorpVaultSecretStore(HashiCorp(fake));
        await store.SetSecretAsync("db", "x");

        for (var i = 0; i < 10; i++)
            await Assert.That((await store.GetSecretAsync("proibido")).Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);

        await Assert.That(fake.Logins).IsEqualTo(1);
        await Assert.That(fake.Lookups).IsEqualTo(1);   // a confirmação do token vale por alguns segundos
        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("x");
        await Assert.That(fake.Logins).IsEqualTo(1);
    }

    // ---------- RT-07: renew-self ----------

    [Test]
    public async Task Renewable_token_is_renewed_instead_of_a_new_login_until_max_ttl()
    {
        var fake = new FakeHashiCorpVault();
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        using var store = new HashiCorpVaultSecretStore(HashiCorp(fake, o => o.TimeProvider = time));
        await store.SetSecretAsync("db", "x");

        time.Now = time.Now.AddSeconds(3400);   // dentro da margem de renovação (5 min antes de 1 h)
        await Assert.That((await store.GetSecretAsync("db")).IsSuccess).IsTrue();
        await Assert.That(fake.Logins).IsEqualTo(1);
        await Assert.That(fake.Renewals).IsEqualTo(1);

        fake.RenewLeaseDuration = 10;   // token_max_ttl: a renovação não estende mais
        time.Now = time.Now.AddSeconds(3400);
        await Assert.That((await store.GetSecretAsync("db")).IsSuccess).IsTrue();
        await Assert.That(fake.Renewals).IsEqualTo(2);
        await Assert.That(fake.Logins).IsEqualTo(2);
    }

    // ---------- RT-01: chave privada em item separado ----------

    [Test]
    public async Task Private_key_is_stored_apart_from_the_public_item()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultCertificateStore(HashiCorp(fake));

        var created = await store.CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=c", KeySize = 2048, Exportable = true });

        await Assert.That(created.IsSuccess).IsTrue();
        var publicItem = fake.KvFields("minha-api/_certificates/c")!;
        var keyItem = fake.KvFields("minha-api/_certificates-keys/c")!;
        await Assert.That(publicItem.ContainsKey("pkcs12")).IsFalse();
        await Assert.That(publicItem.ContainsKey("key_version")).IsTrue();
        await Assert.That(keyItem.ContainsKey("pkcs12")).IsTrue();
        await Assert.That(keyItem.ContainsKey("cer")).IsFalse();
    }

    [Test]
    public async Task Policy_denying_the_keys_folder_still_allows_reading_and_listing()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultCertificateStore(HashiCorp(fake));
        await store.CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=c", KeySize = 2048, Exportable = true });
        fake.ForbiddenPaths.Add("secret/data/minha-api/_certificates-keys/");
        fake.ForbiddenPaths.Add("secret/metadata/minha-api/_certificates-keys/");
        while (fake.Requests.TryDequeue(out _))
        {
        }

        await Assert.That((await store.GetCertificateAsync("c")).IsSuccess).IsTrue();
        await Assert.That((await store.ListCertificatesAsync()).Value.Count).IsEqualTo(1);
        await Assert.That((await store.ListCertificateVersionsAsync("c")).Value.Count).IsEqualTo(1);
        await Assert.That(fake.Requests.Any(r => r.Contains("_certificates-keys", StringComparison.Ordinal))).IsFalse();

        await Assert.That((await store.DownloadCertificateAsync("c")).Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);
    }

    [Test]
    public async Task Non_exportable_certificate_never_reads_the_keys_folder()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultCertificateStore(HashiCorp(fake));
        await store.CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=c", KeySize = 2048, Exportable = false });
        while (fake.Requests.TryDequeue(out _))
        {
        }

        await Assert.That((await store.DownloadCertificateAsync("c")).Error!.Code).IsEqualTo(VaultErrors.NotExportableCode);
        await Assert.That(fake.Requests.Any(r => r.Contains("_certificates-keys", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task Legacy_item_is_readable_and_migrates_to_the_new_layout()
    {
        var fake = new FakeHashiCorpVault();
        using var key = RSA.Create(2048);
        using var legacy = new CertificateRequest("CN=antigo", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var legacyFields = new Dictionary<string, string>
        {
            ["cer"] = Convert.ToBase64String(legacy.RawData),
            ["pkcs12"] = Convert.ToBase64String(legacy.Export(X509ContentType.Pkcs12)),
            ["exportable"] = "true"
        };
        fake.SeedKv("minha-api/_certificates/antigo", legacyFields);
        fake.SeedKv("minha-api/_certificates/antigo", legacyFields);
        using var store = new HashiCorpVaultCertificateStore(HashiCorp(fake));

        // Formato antigo continua legível
        await Assert.That((await store.GetCertificateAsync("antigo")).Value.Properties.Thumbprint).IsEqualTo(legacy.Thumbprint);
        using (var downloaded = (await store.DownloadCertificateAsync("antigo")).Value)
            await Assert.That(downloaded.HasPrivateKey).IsTrue();

        var migrated = await store.MigrateCertificateKeysAsync("antigo");

        await Assert.That(migrated.Value).IsTrue();
        await Assert.That(fake.KvFields("minha-api/_certificates/antigo")!.ContainsKey("pkcs12")).IsFalse();
        await Assert.That(fake.KvFields("minha-api/_certificates-keys/antigo")!.ContainsKey("pkcs12")).IsTrue();
        var versions = fake.KvVersions("minha-api/_certificates/antigo");
        await Assert.That(versions.Where(v => v.Data.ContainsKey("pkcs12")).Count()).IsEqualTo(0);
        await Assert.That(versions.Count(v => v.Destroyed)).IsEqualTo(2);
        using (var downloaded = (await store.DownloadCertificateAsync("antigo")).Value)
        {
            await Assert.That(downloaded.HasPrivateKey).IsTrue();
            await Assert.That(downloaded.Thumbprint).IsEqualTo(legacy.Thumbprint);
        }

        await Assert.That((await store.MigrateCertificateKeysAsync("antigo")).Value).IsFalse();
    }

    [Test]
    public async Task Delete_recover_and_purge_also_apply_to_the_private_key()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultCertificateStore(HashiCorp(fake));
        await store.CreateCertificateAsync("c", new CreateCertificateOptions { Subject = "CN=c", Issuer = "Self", KeySize = 2048, Exportable = true });

        await Assert.That(fake.KvVersions("minha-api/_certificates-keys/c").Count).IsEqualTo(1);
        await store.DeleteCertificateAsync("c");
        await Assert.That(fake.KvVersions("minha-api/_certificates-keys/c").All(v => v.Deleted)).IsTrue();

        await store.RecoverDeletedCertificateAsync("c");
        await Assert.That(fake.KvVersions("minha-api/_certificates-keys/c").Any(v => v.Deleted)).IsFalse();
        using (var downloaded = (await store.DownloadCertificateAsync("c")).Value)
            await Assert.That(downloaded.HasPrivateKey).IsTrue();

        await store.DeleteCertificateAsync("c");
        await Assert.That((await store.PurgeDeletedCertificateAsync("c")).IsSuccess).IsTrue();
        await Assert.That(fake.KvVersions("minha-api/_certificates-keys/c").Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("_certificates")]
    [Arguments("_certificates/keys")]
    public async Task Keys_folder_inside_or_equal_to_certificates_folder_is_rejected(string keysPath)
    {
        var options = HashiCorp(new FakeHashiCorpVault(), o => o.Kv.CertificateKeysPath = keysPath);

        await Assert.That(() => new HashiCorpVaultCertificateStore(options)).Throws<InvalidOperationException>();
    }

    // ---------- RT-05: cadeia preservada ----------

    private static (X509Certificate2 Leaf, X509Certificate2 Intermediate, RSA LeafKey) Chain()
    {
        using var rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Raiz Teste", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));

        using var intermediateKey = RSA.Create(2048);
        var intermediateRequest = new CertificateRequest("CN=Intermediaria Teste", intermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var intermediate = intermediateRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(4), [1, 2, 3, 4]);
        using var intermediateWithKey = intermediate.CopyWithPrivateKey(intermediateKey);

        var leafKey = RSA.Create(2048);
        var leafRequest = new CertificateRequest("CN=api.teste", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var leaf = leafRequest.Create(intermediateWithKey, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), [5, 6, 7, 8]);
        return (leaf.CopyWithPrivateKey(leafKey), intermediate, leafKey);
    }

    [Test]
    public async Task Imported_pfx_keeps_its_intermediates()
    {
        var (leaf, intermediate, leafKey) = Chain();
        using (leaf)
        using (intermediate)
        using (leafKey)
        {
            var pfx = new X509Certificate2Collection { leaf, intermediate }.Export(X509ContentType.Pkcs12, "senha")!;
            using var store = new HashiCorpVaultCertificateStore(HashiCorp(new FakeHashiCorpVault()));
            await Assert.That((await store.ImportCertificateAsync("tls", pfx, new ImportCertificateOptions { Password = "senha", Exportable = true })).IsSuccess)
                .IsTrue();

            var chain = (await store.DownloadCertificateWithChainAsync("tls")).Value;
            try
            {
                await Assert.That(chain.Count).IsEqualTo(2);
                await Assert.That(chain[0].HasPrivateKey).IsTrue();
                await Assert.That(chain[0].Thumbprint).IsEqualTo(leaf.Thumbprint);
                await Assert.That(chain[1].Thumbprint).IsEqualTo(intermediate.Thumbprint);
            }
            finally
            {
                foreach (var item in chain)
                    item.Dispose();
            }

            using var single = (await store.DownloadCertificateAsync("tls")).Value;
            await Assert.That(single.Thumbprint).IsEqualTo(leaf.Thumbprint);
            await Assert.That(single.HasPrivateKey).IsTrue();
        }
    }

    [Test]
    public async Task Imported_pem_keeps_its_intermediates()
    {
        var (leaf, intermediate, leafKey) = Chain();
        using (leaf)
        using (intermediate)
        using (leafKey)
        {
            var pem = Encoding.ASCII.GetBytes(leaf.ExportCertificatePem() + "\n" + leafKey.ExportPkcs8PrivateKeyPem() + "\n" + intermediate.ExportCertificatePem());
            using var store = new HashiCorpVaultCertificateStore(HashiCorp(new FakeHashiCorpVault()));
            await Assert.That((await store.ImportCertificateAsync("tls", pem, new ImportCertificateOptions { Exportable = true })).IsSuccess).IsTrue();

            var chain = (await store.DownloadCertificateWithChainAsync("tls")).Value;
            try
            {
                await Assert.That(chain.Count).IsEqualTo(2);
                await Assert.That(chain[0].Thumbprint).IsEqualTo(leaf.Thumbprint);
                await Assert.That(chain[0].HasPrivateKey).IsTrue();
                await Assert.That(chain[1].Thumbprint).IsEqualTo(intermediate.Thumbprint);
            }
            finally
            {
                foreach (var item in chain)
                    item.Dispose();
            }
        }
    }

    [Test]
    public async Task Pki_issued_certificate_keeps_the_ca_chain()
    {
        var fake = new FakeHashiCorpVault { UseIntermediateCa = true };
        using var store = new HashiCorpVaultCertificateStore(HashiCorp(fake));
        await Assert.That((await store.CreateCertificateAsync("pki", new CreateCertificateOptions { Subject = "CN=api.teste", KeySize = 2048, Exportable = true }))
            .IsSuccess).IsTrue();

        var chain = (await store.DownloadCertificateWithChainAsync("pki")).Value;
        try
        {
            await Assert.That(chain.Count).IsEqualTo(3);
            await Assert.That(chain[0].HasPrivateKey).IsTrue();
            await Assert.That(chain.Skip(1).Select(c => c.Thumbprint)).Contains(fake.Intermediate.Thumbprint);
            await Assert.That(chain.Skip(1).Select(c => c.Thumbprint)).Contains(fake.Ca.Thumbprint);
        }
        finally
        {
            foreach (var item in chain)
                item.Dispose();
        }
    }

    // ---------- RT-08: teto do ReloadInterval ----------

    [Test]
    public async Task Reload_interval_above_24_hours_is_rejected()
    {
        await Assert.That(() => new VaultConfigurationOptions { ReloadInterval = TimeSpan.FromHours(25) }).Throws<ArgumentOutOfRangeException>();
        await Assert.That(new VaultConfigurationOptions { ReloadInterval = TimeSpan.FromHours(24) }.ReloadInterval).IsEqualTo(TimeSpan.FromHours(24));
    }

    [Test]
    public async Task Reload_interval_as_plain_number_points_to_the_key()
    {
        var section = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "EnvironmentVariables",
            ["Vault:EnvironmentVariables:Prefix"] = "APP_TESTE_RT08_",
            ["Vault:Configuration:ReloadInterval"] = "30"   // 30 dias, não 30 minutos
        }).Build().GetSection("Vault");

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecVault(section, p => p.AddSynced())).Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:Configuration:ReloadInterval");
    }

    // ---------- RT-09: store da fonte de configuração descartado ----------

    private sealed class TrackedReader(Tracker tracker) : ISecretReader, IDisposable
    {
        public string ProviderName => "Rastreado";

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<VaultSecret>>(VaultErrors.NotFound());

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => Task.FromResult<Result<bool>>(false);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(Array.Empty<SecretProperties>());

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(VaultErrors.NotFound());

        public void Dispose() => Interlocked.Increment(ref tracker.Disposed);
    }

    private sealed class Tracker
    {
        public int Created;
        public int Disposed;

        public VaultProviderRegistration Registration => new("Rastreado", VaultStores.Secrets, (_, _, _) => { }, (_, _) =>
        {
            Interlocked.Increment(ref Created);
            return new TrackedReader(this);
        });
    }

    private static IConfiguration TrackedSection() =>
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Vault:Provider"] = "Rastreado" }).Build().GetSection("Vault");

    [Test]
    public async Task Store_created_by_the_configuration_source_is_disposed_with_it()
    {
        var tracker = new Tracker();
        var root = new ConfigurationBuilder().AddTecVault(TrackedSection(), p => p.Add(tracker.Registration)).Build();

        await Assert.That(tracker.Created).IsEqualTo(1);
        await Assert.That(tracker.Disposed).IsEqualTo(0);

        ((IDisposable)root).Dispose();
        await Assert.That(tracker.Disposed).IsEqualTo(1);
    }

    [Test]
    public async Task Rebuilt_configuration_providers_get_their_own_store()
    {
        var tracker = new Tracker();
        var manager = new ConfigurationManager();
        manager.AddTecVault(TrackedSection(), p => p.Add(tracker.Registration));

        ((IConfigurationBuilder)manager).Properties["remonta"] = true;   // o ConfigurationManager remonta e descarta os provedores

        await Assert.That(tracker.Created).IsEqualTo(2);
        await Assert.That(tracker.Disposed).IsEqualTo(1);
        manager.Dispose();
        await Assert.That(tracker.Disposed).IsEqualTo(2);
    }

    [Test]
    public async Task Store_passed_by_the_application_is_not_disposed_by_the_source()
    {
        var tracker = new Tracker();
        var root = new ConfigurationBuilder().AddTecVault(new TrackedReader(tracker)).Build();

        ((IDisposable)root).Dispose();

        await Assert.That(tracker.Disposed).IsEqualTo(0);
    }

    // ---------- RT-10: um cliente por container ----------

    [Test]
    public async Task Disposing_one_container_does_not_break_another_built_from_the_same_collection()
    {
        var fake = new FakeHashiCorpVault();
        var jwt = Path.Combine(Folder, "sa-token");
        File.WriteAllText(jwt, fake.ServiceAccountJwt);
        var services = new ServiceCollection();
        services.AddTecVault(vault => vault.UseHashiCorpVault(o =>
        {
            o.Address = new Uri("https://vault.teste:8200");
            o.Auth.Method = HashiCorpVaultAuthMethod.Kubernetes;
            o.Auth.Role = FakeHashiCorpVault.Role;
            o.Auth.ServiceAccountTokenFile = jwt;
            o.Kv.BasePath = "minha-api";
            o.Http.Handler = fake;
        }));

        var temporary = services.BuildServiceProvider();
        await temporary.GetRequiredService<ISecretStore>().SetSecretAsync("db", "x");
        await using var application = services.BuildServiceProvider();
        var store = application.GetRequiredService<ISecretStore>();
        await temporary.DisposeAsync();

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("x");
    }

    // ---------- RT-11: deletion_allowed revertido ----------

    [Test]
    public async Task Failed_key_deletion_restores_deletion_protection()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultKeyStore(HashiCorp(fake, o => o.Http.MaxRetries = 0));
        await store.CreateKeyAsync("k", new CreateKeyOptions { KeySize = 2048 });
        fake.DeleteKeyFailures.Enqueue(HttpStatusCode.InternalServerError);

        var result = await store.DeleteKeyAsync("k");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(fake.TransitDeletionAllowed("k")).IsFalse();
        await Assert.That((await store.GetKeyAsync("k")).IsSuccess).IsTrue();
    }

    // ---------- RT-12: Infisical com limite de listagem ----------

    [Test]
    public async Task Infisical_listing_respects_MaxListItems()
    {
        var fake = new FakeInfisical();
        fake.Seed("a", "1");
        fake.Seed("b", "2");
        fake.Seed("c", "3");
        using var store = InfisicalTestStore.Create(fake, Folder, o => o.MaxListItems = 2);

        await Assert.That((await store.ListSecretsAsync()).Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That((await store.GetSecretAsync("nao-existe")).Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That((await store.GetSecretAsync("a")).Value.Value).IsEqualTo("1");
    }

    [Test]
    public async Task Infisical_without_case_insensitive_names_does_not_list_the_folder()
    {
        var fake = new FakeInfisical();
        fake.Seed("Db", "1");
        using var store = InfisicalTestStore.Create(fake, Folder, o => o.CaseInsensitiveNames = false);

        await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That(fake.Requests.Any(r => r == "GET api/v4/secrets")).IsFalse();
    }

    [Test]
    public async Task Infisical_MaxListItems_out_of_range_fails_at_startup()
    {
        await Assert.That(() => InfisicalTestStore.Create(new FakeInfisical(), Folder, o => o.MaxListItems = 0)).Throws<InvalidOperationException>();
    }
}
