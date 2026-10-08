using TEC.Core.Text.Codecs;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Azure;
using Azure.Security.KeyVault.Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.AzureKeyVault.Internal;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Provedor Azure com o SDK real sobre um Key Vault simulado no nível HTTP.</summary>
public class AzureKeyVaultProviderTests
{
    [Test]
    public async Task GetSecret_returns_value_and_metadata()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("db-senha", "s3nh@")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.GetSecretAsync("db-senha");

        await Assert.That(result.Value.Value).IsEqualTo("s3nh@");
        await Assert.That(result.Value.Version).IsEqualTo(FakeKeyVault.Version);
        await Assert.That(result.Value.Properties.ContentType).IsEqualTo("text/plain");
        await Assert.That(result.Value.Properties.Tags["sistema"]).IsEqualTo("teste");
        await Assert.That(result.Value.Properties.Enabled).IsTrue();
    }

    [Test]
    public async Task GetSecret_missing_returns_NotFound()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("SecretNotFound", "A secret with (name/id) x was not found.")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.GetSecretAsync("x");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task GetSecret_disabled_returns_Disabled()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.Forbidden,
            FakeKeyVault.ErrorJson("Forbidden", "Operation get is not allowed on a disabled secret.", "SecretDisabled")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.GetSecretAsync("x");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.DisabledCode);
    }

    [Test]
    public async Task Throttling_returns_error_hidden_from_client()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.TooManyRequests, FakeKeyVault.ErrorJson("Throttled", "Rate limit.")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.GetSecretAsync("x");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.ThrottledCode);
    }

    [Test]
    public async Task SetSecret_sends_value_and_attributes()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("api-key", "abc")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());
        var expires = DateTimeOffset.UtcNow.AddDays(30);

        var result = await store.SetSecretAsync("api-key", "abc", new SecretWriteOptions
        {
            ContentType = "text/plain",
            ExpiresOn = expires,
            Tags = new Dictionary<string, string> { ["dono"] = "financeiro" }
        });

        var put = vault.Requests.Single(r => r.Method == "PUT" && r.Authorized);
        using var json = JsonDocument.Parse(put.Body);
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(put.Uri.AbsolutePath).IsEqualTo("/secrets/api-key");
        await Assert.That(json.RootElement.GetProperty("value").GetString()).IsEqualTo("abc");
        await Assert.That(json.RootElement.GetProperty("tags").GetProperty("dono").GetString()).IsEqualTo("financeiro");
        await Assert.That(json.RootElement.GetProperty("attributes").GetProperty("exp").GetInt64()).IsEqualTo(expires.ToUnixTimeSeconds());
    }

    [Test]
    public async Task ListSecrets_walks_all_pages()
    {
        var vault = new FakeKeyVault((request, _) => request.RequestUri!.Query.Contains("pagina2", StringComparison.Ordinal)
            ? (HttpStatusCode.OK, """{"value":[{"id":"https://kv-teste.vault.azure.net/secrets/b","attributes":{"enabled":true}}],"nextLink":null}""")
            : (HttpStatusCode.OK, """{"value":[{"id":"https://kv-teste.vault.azure.net/secrets/a","attributes":{"enabled":false},"managed":true}],"nextLink":"https://kv-teste.vault.azure.net/secrets?api-version=7.6&pagina2=1"}"""));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.ListSecretsAsync();

        await Assert.That(result.Value.Select(s => s.Name)).IsEquivalentTo(new[] { "a", "b" });
        await Assert.That(result.Value[0].IsManaged).IsTrue();
        await Assert.That(result.Value[0].Enabled).IsFalse();
    }

    [Test]
    public async Task Exists_queries_only_metadata()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("SecretNotFound", "x")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.ExistsAsync("x");

        await Assert.That(result.Value).IsFalse();
        await Assert.That(vault.Requests.All(r => r.Uri.AbsolutePath.EndsWith("/versions", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    public async Task UpdateSecretProperties_does_not_read_value()
    {
        var vault = new FakeKeyVault((request, _) => request.Method == HttpMethod.Patch
            ? (HttpStatusCode.OK, FakeKeyVault.SecretJson("x", "", enabled: false).Replace("\"value\":\"\",", "", StringComparison.Ordinal))
            : (HttpStatusCode.OK, $$$"""{"value":[{"id":"https://kv-teste.vault.azure.net/secrets/x/{{{FakeKeyVault.Version}}}","attributes":{"enabled":true,"created":1700000000}}]}"""));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.UpdateSecretPropertiesAsync("x", new SecretPropertiesUpdate { Enabled = false });

        await Assert.That(result.Value.Enabled).IsFalse();
        await Assert.That(vault.Requests.Any(r => r.Method == "GET" && r.Uri.AbsolutePath == $"/secrets/x/{FakeKeyVault.Version}")).IsFalse();
        await Assert.That(vault.Requests.Single(r => r.Method == "PATCH" && r.Authorized).Uri.AbsolutePath).IsEqualTo($"/secrets/x/{FakeKeyVault.Version}");
    }

    [Test]
    public async Task HealthProbe_only_lists_metadata()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, """{"value":[]}"""));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.CheckAccessAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(vault.Requests.All(r => r.Uri.AbsolutePath.TrimEnd('/') == "/secrets")).IsTrue();
    }

    [Test]
    public async Task Caller_cancellation_throws_OperationCanceledException()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.That(async () => { await store.GetSecretAsync("x", cancellationToken: cts.Token); }).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task AddTecVault_registers_three_stores_and_probe()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecVault(vault => vault.UseAzureKeyVault(o =>
        {
            o.VaultUri = new Uri(FakeKeyVault.VaultUri);
            o.Credential = new FakeCredential();
        }));

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        await Assert.That(provider.GetRequiredService<ISecretStore>().ProviderName).IsEqualTo("AzureKeyVault");
        await Assert.That(provider.GetRequiredService<IKeyStore>()).IsNotNull();
        await Assert.That(provider.GetRequiredService<ICertificateStore>()).IsNotNull();
        await Assert.That(provider.GetRequiredService<IVaultHealthProbe>()).IsNotNull();
    }

    [Test]
    public async Task UpdateSecretProperties_with_CreatedOn_tie_uses_vault_current_version()
    {
        const string older = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const string current = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        // As duas versões foram criadas no mesmo segundo; a listagem traz a atual primeiro (ordem não garantida pelo serviço)
        string list = $$$"""
            {"value":[
              {"id":"{{{FakeKeyVault.VaultUri}}}secrets/x/{{{current}}}","attributes":{"enabled":true,"created":1700000000,"updated":1700000000}},
              {"id":"{{{FakeKeyVault.VaultUri}}}secrets/x/{{{older}}}","attributes":{"enabled":true,"created":1700000000,"updated":1700000000}}]}
            """;
        string currentJson = $$$"""
            {"value":"v","id":"{{{FakeKeyVault.VaultUri}}}secrets/x/{{{current}}}","attributes":{"enabled":true,"created":1700000000,"updated":1700000000}}
            """;
        var vault = new FakeKeyVault((request, _) =>
        {
            string path = request.RequestUri!.AbsolutePath.TrimEnd('/');
            if (request.Method == HttpMethod.Patch)
                return (HttpStatusCode.OK, currentJson.Replace("\"value\":\"v\",", "", StringComparison.Ordinal));
            return path.EndsWith("/versions", StringComparison.Ordinal) ? (HttpStatusCode.OK, list) : (HttpStatusCode.OK, currentJson);
        });
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.UpdateSecretPropertiesAsync("x", new SecretPropertiesUpdate { ContentType = "text/plain" });

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(vault.Requests.Single(r => r.Method == "PATCH" && r.Authorized).Uri.AbsolutePath).IsEqualTo($"/secrets/x/{current}");
    }

    [Test]
    public async Task CryptographyClient_is_reused_by_name_and_version()
    {
        var store = new AzureKeyVaultKeyStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        var a = store.GetCryptographyClient("chave", FakeKeyVault.Version);
        var b = store.GetCryptographyClient("CHAVE", FakeKeyVault.Version.ToUpperInvariant());
        var other = store.GetCryptographyClient("chave", "fedcba9876543210fedcba9876543210");
        var latest1 = store.GetCryptographyClient("chave", null);
        var latest2 = store.GetCryptographyClient("chave", null);

        await Assert.That(b).IsSameReferenceAs(a);
        await Assert.That(other).IsNotSameReferenceAs(a);
        await Assert.That(latest2).IsNotSameReferenceAs(latest1);   // sem versão não é guardado (seguiria a versão antiga após rotação)
        await Assert.That(store.CachedCryptographyClients).IsEqualTo(2);
    }

    [Test]
    public async Task CryptographyClient_is_recreated_after_max_lifetime()
    {
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var store = new AzureKeyVaultKeyStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients(configure: o =>
        {
            o.CryptographyClientLifetime = TimeSpan.FromMinutes(10);
            o.TimeProvider = time;
        }));

        var first = store.GetCryptographyClient("chave", FakeKeyVault.Version);
        time.Now += TimeSpan.FromMinutes(9);
        var beforeExpiry = store.GetCryptographyClient("chave", FakeKeyVault.Version);
        time.Now += TimeSpan.FromMinutes(1);
        var afterExpiry = store.GetCryptographyClient("chave", FakeKeyVault.Version);
        var reused = store.GetCryptographyClient("chave", FakeKeyVault.Version);

        await Assert.That(beforeExpiry).IsSameReferenceAs(first);
        await Assert.That(afterExpiry).IsNotSameReferenceAs(first);     // recriado: a chave pública (e o estado) é lida de novo
        await Assert.That(reused).IsSameReferenceAs(afterExpiry);
        await Assert.That(store.CachedCryptographyClients).IsEqualTo(1);
    }

    [Test]
    public async Task Disabled_key_stops_encrypting_locally_after_client_lifetime()
    {
        // O SDK cifra localmente com a chave pública lida na 1ª operação; sem prazo, a chave desabilitada no cofre
        // continuaria cifrando até o processo reiniciar
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        string keyJson = $$$"""
            {"key":{"kid":"{{{FakeKeyVault.VaultUri}}}keys/kek/{{{FakeKeyVault.Version}}}","kty":"RSA","key_ops":["encrypt","decrypt","wrapKey","unwrapKey"],
             "n":"{{{Base64Url(parameters.Modulus!)}}}","e":"{{{Base64Url(parameters.Exponent!)}}}"},
             "attributes":{"enabled":true,"created":1700000000,"updated":1700000000}}
            """;
        bool disabled = false;
        var vault = new FakeKeyVault((_, _) => Volatile.Read(ref disabled)
            ? (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "Operation is not allowed on a disabled key.", "KeyDisabled"))
            : (HttpStatusCode.OK, keyJson));
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var store = new AzureKeyVaultKeyStore(vault.CreateClients(configure: o => o.TimeProvider = time));
        byte[] data = [1, 2, 3];

        var enabled = await store.EncryptAsync("kek", data, version: FakeKeyVault.Version);
        Volatile.Write(ref disabled, true);                  // chave desabilitada no cofre
        var stillCached = await store.EncryptAsync("kek", data, version: FakeKeyVault.Version);
        time.Now += new AzureKeyVaultOptions().CryptographyClientLifetime;
        var afterLifetime = await store.EncryptAsync("kek", data, version: FakeKeyVault.Version);

        await Assert.That(enabled.IsSuccess).IsTrue();
        await Assert.That(stillCached.IsSuccess).IsTrue();   // dentro do prazo: operação local, o cofre não é consultado
        await Assert.That(afterLifetime.Error!.Code).IsEqualTo(VaultErrors.DisabledCode);
        await Assert.That(rsa.Decrypt(enabled.Value.Ciphertext, RSAEncryptionPadding.OaepSHA256)).IsEquivalentTo(data);
    }

    [Test]
    [Arguments(59)]
    [Arguments(24 * 60 * 60 + 1)]
    public async Task CryptographyClientLifetime_out_of_range_fails_at_startup(int seconds)
    {
        var options = new AzureKeyVaultOptions
        {
            VaultUri = new Uri(FakeKeyVault.VaultUri),
            Credential = new FakeCredential(),
            CryptographyClientLifetime = TimeSpan.FromSeconds(seconds)
        };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CryptographyClientLifetime_default_and_limits_are_accepted()
    {
        var options = new AzureKeyVaultOptions { VaultUri = new Uri(FakeKeyVault.VaultUri), Credential = new FakeCredential() };

        await Assert.That(options.CryptographyClientLifetime).IsEqualTo(TimeSpan.FromMinutes(10));
        await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
        options.CryptographyClientLifetime = AzureKeyVaultOptions.MinCryptographyClientLifetime;
        await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
        options.CryptographyClientLifetime = AzureKeyVaultOptions.MaxCryptographyClientLifetime;
        await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
    }

    // ---------- Cofre fora do ar: falha de transporte, com e sem retentativas ----------

    private static Exception TransportFailure(string kind) => kind switch
    {
        "http" => new HttpRequestException("Nenhuma conexão pôde ser feita."),
        "io" => new IOException("Conexão interrompida."),
        "socket" => new SocketException(10061),
        _ => new TaskCanceledException("Tempo limite de rede.")
    };

    [Test]
    [Arguments(0, "http")]
    [Arguments(0, "io")]
    [Arguments(0, "socket")]
    [Arguments(0, "timeout")]
    [Arguments(2, "http")]
    [Arguments(2, "io")]
    [Arguments(2, "socket")]
    [Arguments(2, "timeout")]
    public async Task Vault_down_returns_unavailable_with_and_without_retries(int maxRetries, string kind)
    {
        var vault = new FakeKeyVault((_, _) => throw TransportFailure(kind));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(configure: o => o.MaxRetries = maxRetries));

        var result = await store.GetSecretAsync("x");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
    }

    [Test]
    public async Task Sdk_throws_AggregateException_when_all_retries_fail_by_exception()
    {
        // Documenta o comportamento do Azure.Core que o mapeamento trata: com retentativas, as exceções de transporte
        // chegam agrupadas ("Retry failed after N tries"); sem retentativas, chega a exceção única
        var vault = new FakeKeyVault((_, _) => throw TransportFailure("io"));

        var retried = await Assert.That(async () => { await vault.CreateClients(configure: o => o.MaxRetries = 2).Secrets.GetSecretAsync("x"); })
            .Throws<AggregateException>();
        await Assert.That(retried!.InnerExceptions.Count).IsEqualTo(3);
        await Assert.That(retried.InnerExceptions[^1]).IsTypeOf<IOException>();
        await Assert.That(async () => { await vault.CreateClients().Secrets.GetSecretAsync("x"); }).Throws<IOException>();

        var http = new FakeKeyVault((_, _) => throw TransportFailure("http"));
        var single = await Assert.That(async () => { await http.CreateClients().Secrets.GetSecretAsync("x"); }).Throws<RequestFailedException>();
        await Assert.That(single!.Status).IsEqualTo(0);
    }

    [Test]
    public async Task AggregateException_is_mapped_by_last_exception_or_as_unavailable()
    {
        var known = AzureKeyVaultStoreBase.Map(new AggregateException(new IOException("a"), new RequestFailedException(429, "x", "Throttled", null)));
        var unknown = AzureKeyVaultStoreBase.Map(new AggregateException("Retry failed after 2 tries.", new InvalidCastException("a"), new InvalidCastException("b")));
        var empty = AzureKeyVaultStoreBase.Map(new AggregateException());

        await Assert.That(known!.Value.Error.Code).IsEqualTo(VaultErrors.ThrottledCode);
        await Assert.That(unknown!.Value.Error.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(unknown.Value.Detail).DoesNotContain("Retry failed");
        await Assert.That(empty).IsNull();
    }

    [Test]
    public async Task CryptographyClient_cache_is_bounded()
    {
        var store = new AzureKeyVaultKeyStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        for (int i = 0; i < AzureKeyVaultKeyStore.MaxCryptographyClients + 10; i++)
            store.GetCryptographyClient($"chave-{i}", FakeKeyVault.Version);

        await Assert.That(store.CachedCryptographyClients).IsLessThanOrEqualTo(AzureKeyVaultKeyStore.MaxCryptographyClients);
    }

    [Test]
    [Arguments("Development", true)]
    [Arguments("Production", false)]
    [Arguments("Staging", false)]
    public async Task Developer_credential_uses_IHostEnvironment_when_given(string environment, bool allowed)
    {
        var options = new AzureKeyVaultOptions
        {
            VaultUri = new Uri(FakeKeyVault.VaultUri),
            Authentication = AzureKeyVaultAuthentication.Developer,
            HostEnvironment = new FakeHostEnvironment(environment)
        };

        if (allowed)
            await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
        else
            await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task UseAzureKeyVault_uses_IHostEnvironment_registered_in_container()
    {
        var production = new ServiceCollection();
        production.AddSingleton<IHostEnvironment>(new FakeHostEnvironment("Production"));
        var development = new ServiceCollection();
        development.AddSingleton<IHostEnvironment>(new FakeHostEnvironment("Development"));

        static void Configure(AzureKeyVaultOptions o)
        {
            o.VaultUri = new Uri(FakeKeyVault.VaultUri);
            o.Authentication = AzureKeyVaultAuthentication.Developer;
        }

        await Assert.That(() => production.AddTecVault(c => c.UseAzureKeyVault(Configure))).Throws<InvalidOperationException>();
        await Assert.That(() => development.AddTecVault(c => c.UseAzureKeyVault(Configure))).ThrowsNothing();
    }

    private sealed class FakeHostEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "testes";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    [Test]
    public async Task AddTecVault_registers_azure_capabilities_on_same_instance()
    {
        var services = new ServiceCollection();
        services.AddTecVault(vault => vault.UseAzureKeyVault(o =>
        {
            o.VaultUri = new Uri(FakeKeyVault.VaultUri);
            o.Credential = new FakeCredential();
        }));
        using var provider = services.BuildServiceProvider();

        var secrets = provider.GetRequiredService<ISecretReader>();
        var keys = provider.GetRequiredService<IKeyCryptography>();
        var certificates = provider.GetRequiredService<ICertificateReader>();

        await Assert.That(secrets).IsTypeOf<AzureKeyVaultSecretStore>();
        await Assert.That(provider.GetRequiredService<ISecretStore>()).IsSameReferenceAs(secrets);
        await Assert.That(provider.GetRequiredService<ISecretRecycleBin>()).IsSameReferenceAs(secrets);
        await Assert.That(provider.GetRequiredService<ISecretBackup>()).IsSameReferenceAs(secrets);
        await Assert.That(provider.GetRequiredService<IKeyStore>()).IsSameReferenceAs(keys);
        await Assert.That(provider.GetRequiredService<IKeyRecycleBin>()).IsSameReferenceAs(keys);
        await Assert.That(provider.GetRequiredService<IKeyBackup>()).IsSameReferenceAs(keys);
        await Assert.That(provider.GetRequiredService<ICertificateStore>()).IsSameReferenceAs(certificates);
        await Assert.That(provider.GetRequiredService<ICertificateRecycleBin>()).IsSameReferenceAs(certificates);
        await Assert.That(provider.GetRequiredService<ICertificateBackup>()).IsSameReferenceAs(certificates);
    }

    [Test]
    public async Task CreateKey_with_HardwareProtected_creates_hsm_key_and_model_stays_neutral()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(false);
        string json = $$$"""
            {"key":{"kid":"{{{FakeKeyVault.VaultUri}}}keys/hsm/{{{FakeKeyVault.Version}}}","kty":"RSA-HSM","key_ops":["sign","verify"],
             "n":"{{{Base64Url(parameters.Modulus!)}}}","e":"{{{Base64Url(parameters.Exponent!)}}}"},
             "attributes":{"enabled":true,"created":1700000000,"updated":1700000000}}
            """;
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, json));
        var store = new AzureKeyVaultKeyStore(vault.CreateClients());

        var result = await store.CreateKeyAsync("hsm", new CreateKeyOptions
        {
            KeySize = 2048,
            HardwareProtected = true,
            Operations = VaultKeyOperations.Sign | VaultKeyOperations.Verify
        });

        using var body = JsonDocument.Parse(vault.Requests.Single(r => r.Method == "POST" && r.Authorized).Body);
        await Assert.That(body.RootElement.GetProperty("kty").GetString()).IsEqualTo("RSA-HSM");
        await Assert.That(result.Value.KeyType).IsEqualTo(VaultKeyType.Rsa);
        await Assert.That(result.Value.HardwareProtected).IsTrue();
        await Assert.That(result.Value.Properties.Id).IsEqualTo($"{FakeKeyVault.VaultUri}keys/hsm/{FakeKeyVault.Version}");
    }

    [Test]
    public async Task Certificate_policy_without_issuer_is_self_signed_and_hsm_is_mapped()
    {
        var self = AzureKeyVaultCertificateStore.BuildPolicy(new CreateCertificateOptions { Subject = "CN=x" });
        var hsm = AzureKeyVaultCertificateStore.BuildPolicy(new CreateCertificateOptions
        {
            Subject = "CN=x", Issuer = "MinhaCA", KeyType = VaultKeyType.Ec, HardwareProtected = true
        });

        await Assert.That(self.IssuerName).IsEqualTo("Self");
        await Assert.That(self.KeyType).IsEqualTo(CertificateKeyType.Rsa);
        await Assert.That(hsm.IssuerName).IsEqualTo("MinhaCA");
        await Assert.That(hsm.KeyType).IsEqualTo(CertificateKeyType.EcHsm);
        await Assert.That(AzureKeyVaultCertificateStore.ValidateCreate(new CreateCertificateOptions { Subject = "CN=x", Issuer = "nome inválido" })!.Field)
            .IsEqualTo("issuer");
    }

    private static string Base64Url(byte[] data) => Base64UrlEncoder.Encode(data);

    [Test]
    public async Task AddTecVault_with_invalid_address_fails_at_startup()
    {
        var services = new ServiceCollection();

        await Assert.That(() => services.AddTecVault(c => c.UseAzureKeyVault(o => o.VaultUri = new Uri("https://evil.com/"))))
            .Throws<InvalidOperationException>();
    }
}
