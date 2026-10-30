using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.GoogleSecretManager;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>
/// Provedor Google Secret Manager sobre <c>VaultHttpClient</c> e <c>VaultTokenSource</c>: token estático, Service Account (JWT
/// conferido pelo fake, <c>token_uri</c> validado), Metadata Server, 401, tetos, labels e listagem.
/// </summary>
public class GoogleSecretManagerProviderTests : TempFolderTest
{
    // ---------- Leitura ----------

    [Test]
    public async Task Get_decodes_base64_payload_with_bearer_token()
    {
        var fake = new FakeGoogle();
        fake.Seed("db-pass", "google-secret-123");
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake));

        var result = await store.GetSecretAsync("db-pass");

        await Assert.That(result.Value.Value).IsEqualTo("google-secret-123");
        await Assert.That(result.Value.Version).IsEqualTo("1");
    }

    [Test]
    public async Task Missing_secret_is_NotFound_and_Exists_false()
    {
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(new FakeGoogle()));

        await Assert.That((await store.GetSecretAsync("nao-existe")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.ExistsAsync("nao-existe")).Value).IsFalse();
    }

    [Test]
    public async Task Body_that_stalls_after_headers_times_out_as_unavailable()
    {
        var options = GoogleTestOptions.Create(new FakeGoogle(), o =>
        {
            o.Http.Handler = new StallingBodyHandler();
            o.Http.MaxRetries = 0;
            o.Http.NetworkTimeout = TimeSpan.FromMilliseconds(300);
        });
        using var store = new GoogleSecretManagerSecretStore(options);

        var started = TimeProvider.System.GetTimestamp();
        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));
    }

    [Test]
    public async Task Response_above_MaxResponseBytes_is_provider_failure()
    {
        var options = GoogleTestOptions.Create(new FakeGoogle(), o =>
        {
            o.Http.Handler = new GiantBodyHandler(4 * 1024 * 1024);
            o.Http.MaxResponseBytes = 64 * 1024;
        });
        using var store = new GoogleSecretManagerSecretStore(options);

        await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    // ---------- Credenciais ----------

    [Test]
    public async Task Service_account_jwt_is_exchanged_once_and_cached()
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v");
        using var store = new GoogleSecretManagerSecretStore(ServiceAccount(fake, fake.ServiceAccountJson()));

        await store.GetSecretAsync("db");
        var second = await store.GetSecretAsync("db");

        await Assert.That(second.Value.Value).IsEqualTo("v");
        await Assert.That(fake.TokenCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments("https://evil.example/token")]
    [Arguments("http://oauth2.googleapis.com/token")]
    [Arguments("https://oauth2.googleapis.com:8443/token")]
    [Arguments("https://oauth2.googleapis.com/token?redirect=https://evil.example")]
    public async Task Token_uri_outside_the_allow_list_is_refused_before_sending_the_jwt(string tokenUri)
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v");
        using var store = new GoogleSecretManagerSecretStore(ServiceAccount(fake, fake.ServiceAccountJson(tokenUri)));

        var result = await store.GetSecretAsync("db");

        // Antes: o JWT assinado ia para o endereço que o arquivo indicasse, inclusive em HTTP
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(fake.UnexpectedHosts).IsEmpty();
        await Assert.That(fake.TokenCalls).IsEqualTo(0);
    }

    [Test]
    public async Task Credential_of_another_type_is_refused()
    {
        var fake = new FakeGoogle();
        using var store = new GoogleSecretManagerSecretStore(ServiceAccount(fake, fake.ServiceAccountJson(type: "authorized_user")));

        await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(fake.TokenCalls).IsEqualTo(0);
    }

    [Test]
    public async Task Rejected_token_is_discarded_and_renewed_once()
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v");
        using var store = new GoogleSecretManagerSecretStore(ServiceAccount(fake, fake.ServiceAccountJson()));
        await store.GetSecretAsync("db");

        fake.RevokeTokens();   // o token em cache passa a receber 401
        var result = await store.GetSecretAsync("db");

        // Antes: o 401 virava VAULT_AUTENTICACAO_FALHOU e o token recusado continuava em uso até expirar
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(fake.TokenCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Login_failure_is_authentication_failure_and_respects_cooldown()
    {
        var fake = new FakeGoogle();
        fake.TokenFailures.Enqueue(HttpStatusCode.BadRequest);
        using var store = new GoogleSecretManagerSecretStore(ServiceAccount(fake, fake.ServiceAccountJson()));

        var first = await store.GetSecretAsync("db");
        var second = await store.GetSecretAsync("db");

        await Assert.That(first.Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(second.Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(fake.TokenCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Metadata_server_token_is_used_when_nothing_else_is_configured()
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v");
        using var store = new GoogleSecretManagerSecretStore(MetadataServer(fake));

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Value.Value).IsEqualTo("v");
        await Assert.That(fake.MetadataCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Metadata_response_without_flavor_header_is_refused()
    {
        var fake = new FakeGoogle { MetadataFlavor = false };
        using var store = new GoogleSecretManagerSecretStore(MetadataServer(fake));

        await Assert.That((await store.GetSecretAsync("db")).Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
    }

    [Test]
    public async Task Metadata_server_failure_keeps_its_cause()
    {
        var fake = new FakeGoogle { MetadataStatus = HttpStatusCode.ServiceUnavailable };
        using var store = new GoogleSecretManagerSecretStore(MetadataServer(fake, o => o.Http.MaxRetries = 0));

        var result = await store.GetSecretAsync("db");

        // Antes: um catch vazio engolia a falha e o resultado era VAULT_FALHA ("nenhuma credencial")
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
    }

    [Test]
    public async Task Configured_credentials_file_that_does_not_exist_fails_at_startup()
    {
        await Assert.That(() => new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(new FakeGoogle(), o =>
        {
            o.AccessToken = null;
            o.CredentialsJsonFile = Path.Combine(Folder, "nao-existe.json");
            o.UseMetadataServer = true;
        }))).Throws<InvalidOperationException>();
    }

    // ---------- Endereço ----------

    [Test]
    [Arguments("http://secretmanager.googleapis.com/")]
    [Arguments("https://secretmanager.googleapis.com/v1/")]
    [Arguments("https://usuario@secretmanager.googleapis.com/")]
    public async Task Endpoint_must_be_https_and_server_only(string endpoint)
    {
        await Assert.That(() => new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(new FakeGoogle(), o => o.Endpoint = new Uri(endpoint))))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("projeto/../../outro")]
    [Arguments("Projeto")]
    [Arguments("")]
    public async Task Project_id_cannot_change_the_path(string projectId)
    {
        await Assert.That(() => new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(new FakeGoogle(), o => o.ProjectId = projectId)))
            .Throws<InvalidOperationException>();
    }

    // ---------- Listagem ----------

    [Test]
    public async Task Listing_above_MaxListItems_fails_instead_of_truncating()
    {
        var fake = new FakeGoogle();
        foreach (var name in new[] { "a", "b", "c" })
            fake.Seed(name, "v");
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake, o => o.MaxListItems = 2));

        await Assert.That((await store.ListSecretsAsync()).Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
    }

    [Test]
    public async Task Listing_follows_every_page()
    {
        var fake = new FakeGoogle { PageSize = 2 };
        foreach (var name in new[] { "a", "b", "c", "d", "e" })
            fake.Seed(name, "v", new Dictionary<string, string> { ["equipe"] = "pagamentos" });
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake));

        var result = await store.ListSecretsAsync();

        await Assert.That(result.Value.Select(p => p.Name)).IsEquivalentTo(["a", "b", "c", "d", "e"]);
        await Assert.That(result.Value.All(p => p.Tags["equipe"] == "pagamentos")).IsTrue();
    }

    // ---------- Escrita e labels ----------

    [Test]
    public async Task UpdateSecretProperties_replaces_the_labels()
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v", new Dictionary<string, string> { ["velha"] = "1" });
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake));

        var result = await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate
        {
            Tags = new Dictionary<string, string> { ["equipe"] = "pagamentos" }
        });

        // Antes: as tags eram aceitas e ignoradas, com sucesso
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(fake.LabelsOf("db")).IsEquivalentTo(new Dictionary<string, string> { ["equipe"] = "pagamentos" });
        await Assert.That(result.Value.Tags).IsEquivalentTo(new Dictionary<string, string> { ["equipe"] = "pagamentos" });
    }

    [Test]
    [Arguments("Maiuscula", "x")]
    [Arguments("1-comeca-com-digito", "x")]
    [Arguments("chave", "Valor Com Espaco")]
    public async Task Invalid_label_is_refused_before_calling_google(string key, string value)
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v");
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake));
        while (fake.Requests.TryDequeue(out _))
        {
        }

        var result = await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate
        {
            Tags = new Dictionary<string, string> { [key] = value }
        });

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(fake.Requests).IsEmpty();
    }

    [Test]
    public async Task Disabling_a_version_returns_its_real_state()
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v");
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake));

        var result = await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate { Enabled = false }, "1");

        await Assert.That(result.Value.Enabled).IsFalse();
        await Assert.That(fake.StateOf("db", 1)).IsEqualTo("DISABLED");
    }

    [Test]
    public async Task SetSecret_on_existing_secret_adds_a_version_and_replaces_the_labels()
    {
        var fake = new FakeGoogle();
        fake.Seed("db", "v1", new Dictionary<string, string> { ["velha"] = "1" });
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake));

        var written = await store.SetSecretAsync("db", "v2", new SecretWriteOptions { Tags = new Dictionary<string, string> { ["nova"] = "2" } });

        await Assert.That(written.Value.Version).IsEqualTo("2");
        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("v2");
        await Assert.That(fake.LabelsOf("db")).IsEquivalentTo(new Dictionary<string, string> { ["nova"] = "2" });
    }

    [Test]
    public async Task SetSecret_creates_a_missing_secret_with_labels()
    {
        var fake = new FakeGoogle();
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(fake));

        var written = await store.SetSecretAsync("novo", "v1", new SecretWriteOptions { Tags = new Dictionary<string, string> { ["equipe"] = "x" } });

        await Assert.That(written.Value.Version).IsEqualTo("1");
        await Assert.That(fake.LabelsOf("novo")).IsEquivalentTo(new Dictionary<string, string> { ["equipe"] = "x" });
    }

    // ---------- Sonda ----------

    [Test]
    public async Task CheckAccess_propagates_cancellation()
    {
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(new FakeGoogle()));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.That(async () => { await store.CheckAccessAsync(cts.Token); }).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task CheckAccess_records_the_metric()
    {
        using var metrics = new OperationMetrics(GoogleSecretManagerSecretStore.Provider);
        using var store = new GoogleSecretManagerSecretStore(GoogleTestOptions.Create(new FakeGoogle()));

        await Assert.That((await store.CheckAccessAsync()).IsSuccess).IsTrue();
        await Assert.That(metrics.Recorded.Any(m => m.Operation == "secret.health" && m.Error is null)).IsTrue();
    }

    // ---------- Configuração ----------

    [Test]
    public async Task Inline_access_token_in_configuration_is_rejected_without_echoing_it()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "GoogleSecretManager",
            ["Vault:GoogleSecretManager:ProjectId"] = FakeGoogle.ProjectId,
            ["Vault:GoogleSecretManager:AccessToken"] = "ya29.colado-por-engano"
        }).Build();

        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(configuration.GetSection("Vault"), p => p.AddGoogleSecretManager()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:GoogleSecretManager:AccessToken");
        await Assert.That(exception.Message).DoesNotContain("ya29.colado-por-engano");
    }

    private GoogleSecretManagerOptions ServiceAccount(FakeGoogle fake, string json) =>
        GoogleTestOptions.Create(fake, o =>
        {
            o.AccessToken = null;
            o.CredentialsJsonFile = Write("service-account.json", json);
        });

    private static GoogleSecretManagerOptions MetadataServer(FakeGoogle fake, Action<GoogleSecretManagerOptions>? configure = null) =>
        GoogleTestOptions.Create(fake, o =>
        {
            o.AccessToken = null;
            o.UseMetadataServer = true;
            configure?.Invoke(o);
        });
}
