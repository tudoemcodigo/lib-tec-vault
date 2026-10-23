using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Infisical;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Contracts;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>Store contra o Infisical simulado, com o segredo do cliente em arquivo.</summary>
internal static class InfisicalTestStore
{
    public static InfisicalSecretStore Create(FakeInfisical fake, string folder, Action<InfisicalOptions>? configure = null, ILogger<InfisicalSecretStore>? logger = null)
    {
        var secretFile = Path.Combine(folder, "client-secret");
        if (!File.Exists(secretFile))
            File.WriteAllText(secretFile, fake.ClientSecret + "\n");

        var options = new InfisicalOptions
        {
            SiteUrl = new Uri("https://infisical.teste/"),
            ProjectId = FakeInfisical.ProjectId,
            Environment = FakeInfisical.Environment,
            ClientId = FakeInfisical.ClientId,
            ClientSecretFile = secretFile
        };
        options.Http.Handler = fake;
        options.Http.MaxRetries = 2;
        configure?.Invoke(options);
        return new InfisicalSecretStore(options, logger);
    }
}

[InheritsTests]
public class InfisicalSecretStoreContractTests : SecretStoreContract, IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("tec-vault-infisical").FullName;

    protected override Task<ISecretStore> CreateStoreAsync() => Task.FromResult<ISecretStore>(InfisicalTestStore.Create(new FakeInfisical(), _folder));

    protected override string UnknownVersion(string existing) => "999";

    public void Dispose()
    {
        Directory.Delete(_folder, recursive: true);
        GC.SuppressFinalize(this);
    }
}

/// <summary>Comportamento específico do Infisical: login, retentativa, nomes, opções e configuração.</summary>
public class InfisicalProviderTests : TempFolderTest
{
    [Test]
    public async Task Login_happens_once_and_token_is_reused()
    {
        var fake = new FakeInfisical();
        fake.Seed("db", "x");
        using var store = InfisicalTestStore.Create(fake, Folder);

        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => store.GetSecretAsync("db")));

        await Assert.That(fake.Logins).IsEqualTo(1);
    }

    [Test]
    public async Task Token_near_expiry_is_renewed_early()
    {
        var fake = new FakeInfisical { ExpiresIn = 600 };
        fake.Seed("db", "x");
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        using var store = InfisicalTestStore.Create(fake, Folder, o => o.TimeProvider = time);

        await store.GetSecretAsync("db");
        time.Now = time.Now.AddSeconds(545);   // faltam 55 s: dentro da margem de 10% (60 s)
        await store.GetSecretAsync("db");

        await Assert.That(fake.Logins).IsEqualTo(2);
    }

    [Test]
    public async Task Revoked_token_triggers_one_new_login()
    {
        var fake = new FakeInfisical();
        fake.Seed("db", "x");
        using var store = InfisicalTestStore.Create(fake, Folder);
        await store.GetSecretAsync("db");

        fake.RevokeTokens();
        var result = await store.GetSecretAsync("db");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(fake.Logins).IsEqualTo(2);
    }

    [Test]
    public async Task Client_secret_is_reread_from_file_on_each_login()
    {
        var fake = new FakeInfisical();
        fake.Seed("db", "x");
        using var store = InfisicalTestStore.Create(fake, Folder);
        await store.GetSecretAsync("db");

        fake.ClientSecret = "rotacionado";
        File.WriteAllText(Path.Combine(Folder, "client-secret"), "rotacionado");
        fake.RevokeTokens();

        await Assert.That((await store.GetSecretAsync("db")).IsSuccess).IsTrue();
    }

    [Test]
    public async Task Missing_or_rejected_credential_becomes_AuthenticationFailed_without_leaking_secret()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var fake = new FakeInfisical();
        File.WriteAllText(Path.Combine(Folder, "client-secret"), "segredo-errado-do-cliente");
        using var wrong = InfisicalTestStore.Create(fake, Folder, logger: factory.CreateLogger<InfisicalSecretStore>());
        using var missing = InfisicalTestStore.Create(fake, Folder, o => o.ClientSecretFile = Path.Combine(Folder, "nao-existe"));

        var refused = await wrong.GetSecretAsync("db");
        var absent = await missing.GetSecretAsync("db");

        await Assert.That(refused.Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(absent.Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(logs.AllText).DoesNotContain("segredo-errado-do-cliente");
    }

    [Test]
    public async Task Kubernetes_auth_sends_service_account_token()
    {
        var fake = new FakeInfisical();
        fake.Seed("db", "x");
        var jwt = Path.Combine(Folder, "token");
        File.WriteAllText(jwt, fake.ServiceAccountJwt);
        using var store = InfisicalTestStore.Create(fake, Folder, o =>
        {
            o.Authentication = InfisicalAuthentication.Kubernetes;
            o.IdentityId = FakeInfisical.IdentityId;
            o.ServiceAccountTokenFile = jwt;
        });

        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("x");
        await Assert.That(fake.Requests).Contains("POST api/v1/auth/kubernetes-auth/login");
    }

    [Test]
    public async Task Read_is_retried_on_transient_failure()
    {
        var fake = new FakeInfisical();
        fake.Seed("db", "x");
        using var store = InfisicalTestStore.Create(fake, Folder);
        await store.GetSecretAsync("db");
        fake.Failures.Enqueue(HttpStatusCode.ServiceUnavailable);
        fake.Failures.Enqueue(HttpStatusCode.TooManyRequests);

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.IsSuccess).IsTrue();
    }

    [Test]
    public async Task Creation_is_not_retried_on_5xx_to_avoid_writing_twice()
    {
        var fake = new FakeInfisical();
        using var store = InfisicalTestStore.Create(fake, Folder);
        fake.WriteFailures.Enqueue(HttpStatusCode.ServiceUnavailable);

        var result = await store.SetSecretAsync("novo", "v1");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(fake.Requests.Count(r => r.StartsWith("POST api/v4", StringComparison.Ordinal))).IsEqualTo(1);
    }

    [Test]
    public async Task Persistent_failure_becomes_Unavailable_without_response_body_in_log()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var fake = new FakeInfisical();
        using var store = InfisicalTestStore.Create(fake, Folder, logger: factory.CreateLogger<InfisicalSecretStore>());
        await store.ListSecretsAsync();
        for (var i = 0; i < 5; i++)
            fake.Failures.Enqueue(HttpStatusCode.BadGateway);

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(logs.AllText).DoesNotContain("detalhe-interno-do-servidor");
    }

    [Test]
    public async Task Names_differing_only_in_case_make_read_ambiguous()
    {
        var fake = new FakeInfisical();
        fake.Seed("Senha", "a");
        fake.Seed("SENHA", "b");
        using var store = InfisicalTestStore.Create(fake, Folder);

        await Assert.That((await store.GetSecretAsync("Senha")).Value.Value).IsEqualTo("a");
        await Assert.That((await store.GetSecretAsync("senha")).Error!.Code).IsEqualTo(VaultErrors.ConflictCode);
    }

    [Test]
    public async Task Writing_with_other_casing_updates_existing_secret()
    {
        var fake = new FakeInfisical();
        fake.Seed("ApiKey", "v1");
        using var store = InfisicalTestStore.Create(fake, Folder);

        var result = await store.SetSecretAsync("APIKEY", "v2");

        await Assert.That(result.Value.Name).IsEqualTo("ApiKey");
        await Assert.That(result.Value.Version).IsEqualTo("2");
        await Assert.That((await store.ListSecretsAsync()).Value.Count).IsEqualTo(1);
    }

    [Test]
    public async Task Tags_become_secret_metadata()
    {
        using var store = InfisicalTestStore.Create(new FakeInfisical(), Folder);

        await store.SetSecretAsync("db", "x", new SecretWriteOptions { Tags = new Dictionary<string, string> { ["dono"] = "time-a" } });
        await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate { Tags = new Dictionary<string, string> { ["dono"] = "time-b" } });

        var listed = (await store.ListSecretsAsync()).Value.Single();
        await Assert.That(listed.Tags["dono"]).IsEqualTo("time-b");
    }

    [Test]
    public async Task Options_infisical_lacks_are_rejected_before_call()
    {
        var fake = new FakeInfisical();
        using var store = InfisicalTestStore.Create(fake, Folder);

        var expires = await store.SetSecretAsync("db", "x", new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) });
        var disabled = await store.SetSecretAsync("db", "x", new SecretWriteOptions { Enabled = false });
        var contentType = await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate { ContentType = "text/plain" });

        await Assert.That(expires.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(disabled.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(contentType.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(fake.Requests).IsEmpty();
    }

    [Test]
    public async Task Write_pending_approval_returns_NotSupported()
    {
        var fake = new FakeInfisical { RequireApproval = true };
        using var store = InfisicalTestStore.Create(fake, Folder);

        var result = await store.SetSecretAsync("db", "x");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
    }

    [Test]
    public async Task Configured_folder_is_used_in_every_call()
    {
        var fake = new FakeInfisical { SecretPath = "/minha-api" };
        using var store = InfisicalTestStore.Create(fake, Folder, o => o.SecretPath = "/minha-api/");

        await store.SetSecretAsync("db", "x");

        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("x");
    }

    [Test]
    [Arguments("http://infisical.teste/")]
    [Arguments("https://usuario:senha@infisical.teste/")]
    [Arguments("https://infisical.teste/api")]
    [Arguments("https://infisical.teste/?x=1")]
    public async Task Insecure_address_is_rejected_on_creation(string url)
    {
        await Assert.That(() => InfisicalTestStore.Create(new FakeInfisical(), Folder, o => o.SiteUrl = new Uri(url)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("")]
    [Arguments("sem-barra")]
    [Arguments("/../outro")]
    [Arguments("/a b")]
    public async Task Invalid_folder_is_rejected(string path)
    {
        await Assert.That(() => InfisicalTestStore.Create(new FakeInfisical(), Folder, o => o.SecretPath = path == "" ? "x" : path))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Client_secret_in_file_and_variable_at_once_is_rejected()
    {
        await Assert.That(() => InfisicalTestStore.Create(new FakeInfisical(), Folder, o => o.ClientSecretVariable = "X"))
            .Throws<InvalidOperationException>();
    }

    // ---------- Configuração ----------

    private IConfiguration Config(params (string Key, string Value)[] extra)
    {
        var values = new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "Infisical",
            ["Vault:Infisical:SiteUrl"] = "https://infisical.teste/",
            ["Vault:Infisical:ProjectId"] = FakeInfisical.ProjectId,
            ["Vault:Infisical:Environment"] = FakeInfisical.Environment,
            ["Vault:Infisical:ClientId"] = FakeInfisical.ClientId,
            ["Vault:Infisical:ClientSecretFile"] = Path.Combine(Folder, "client-secret")
        };
        foreach (var (key, value) in extra)
            values["Vault:" + key] = value;
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build().GetSection("Vault");
    }

    [Test]
    public async Task Chosen_by_configuration_reads_and_writes()
    {
        var fake = new FakeInfisical();
        File.WriteAllText(Path.Combine(Folder, "client-secret"), fake.ClientSecret);
        var services = new ServiceCollection();
        services.AddTecVault(Config(), p => p.AddInfisical(o => o.Http.Handler = fake));
        using var sp = services.BuildServiceProvider();

        var store = sp.GetRequiredService<ISecretStore>();
        await store.SetSecretAsync("db", "valor");

        await Assert.That(store).IsTypeOf<InfisicalSecretStore>();
        await Assert.That((await sp.GetRequiredService<ISecretReader>().GetSecretAsync("db")).Value.Value).IsEqualTo("valor");
        await Assert.That(sp.GetService<IKeyReader>()).IsNull();
    }

    [Test]
    [Arguments("Infisical:ClientSecret")]
    [Arguments("Infisical:AccessToken")]
    public async Task Plain_text_secret_in_configuration_is_rejected(string key)
    {
        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(Config((key, "segredo-colado")), p => p.AddInfisical()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("File");
        await Assert.That(exception.Message).DoesNotContain("segredo-colado");
    }
}
