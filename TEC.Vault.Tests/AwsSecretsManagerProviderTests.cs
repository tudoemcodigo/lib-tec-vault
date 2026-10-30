using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.AwsSecretsManager;
using TEC.Vault.Common;
using TEC.Vault.DependencyInjection;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>
/// Provedor AWS Secrets Manager sobre <c>VaultHttpClient</c> e <c>VaultTokenSource</c>: assinatura SigV4 conferida pelo cofre
/// simulado, cadeia de credenciais (web identity, container, IMDSv2, estática), erros da AWS em HTTP 400, tetos e tags.
/// </summary>
public class AwsSecretsManagerProviderTests : TempFolderTest
{
    // ---------- Leitura e assinatura ----------

    [Test]
    public async Task Get_signs_with_sigv4_and_reads_secret()
    {
        var fake = new FakeAws();
        fake.Seed("app-key", "valor-secreto");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        var result = await store.GetSecretAsync("app-key");

        // O fake recusa (InvalidSignatureException) uma assinatura que não confira com a requisição enviada
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("valor-secreto");
        await Assert.That(fake.Actions).IsEquivalentTo(["GetSecretValue"]);
    }

    [Test]
    public async Task ResourceNotFound_in_http_400_maps_to_NotFound_and_Exists_false()
    {
        var fake = new FakeAws();
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        await Assert.That((await store.GetSecretAsync("nao-existe")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That((await store.ExistsAsync("nao-existe")).Value).IsFalse();
    }

    [Test]
    public async Task Throttling_in_http_400_is_retried_like_429_and_counts_as_throttled()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake, configure: o => o.Http.MaxRetries = 1));

        fake.Failures.Enqueue((HttpStatusCode.BadRequest, "ThrottlingException"));
        var retried = await store.GetSecretAsync("db");
        fake.Failures.Enqueue((HttpStatusCode.BadRequest, "ThrottlingException"));
        fake.Failures.Enqueue((HttpStatusCode.BadRequest, "ThrottlingException"));
        var throttled = await store.GetSecretAsync("db");

        await Assert.That(retried.IsSuccess).IsTrue();
        await Assert.That(throttled.Error!.Code).IsEqualTo(VaultErrors.ThrottledCode);
        await Assert.That(fake.Actions.Count).IsEqualTo(4);
    }

    [Test]
    public async Task Body_that_stalls_after_headers_times_out_as_unavailable()
    {
        var handler = new StallingBodyHandler();
        var options = AwsTestOptions.Create(new FakeAws(), configure: o =>
        {
            o.Http.Handler = handler;
            o.Http.MaxRetries = 0;
            o.Http.NetworkTimeout = TimeSpan.FromMilliseconds(300);
        });
        using var store = new AwsSecretsManagerSecretStore(options);

        var started = TimeProvider.System.GetTimestamp();
        var result = await store.GetSecretAsync("db");

        // Antes: o corpo era lido sem tempo limite próprio e a chamada ficava presa
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));
    }

    [Test]
    public async Task Response_above_MaxResponseBytes_is_provider_failure()
    {
        var handler = new GiantBodyHandler(4 * 1024 * 1024);
        var options = AwsTestOptions.Create(new FakeAws(), configure: o =>
        {
            o.Http.Handler = handler;
            o.Http.MaxResponseBytes = 64 * 1024;
        });
        using var store = new AwsSecretsManagerSecretStore(options);

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    // ---------- Credenciais ----------

    [Test]
    public async Task Expired_credential_is_discarded_and_renewed_once()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v");
        using var store = new AwsSecretsManagerSecretStore(WebIdentity(fake, "jwt-da-service-account"));
        await store.GetSecretAsync("db");
        foreach (var key in fake.ValidKeys.Where(k => k.StartsWith("ASIA", StringComparison.Ordinal)))
            fake.Expire(key);   // a AWS passa a responder ExpiredTokenException (HTTP 400) para a credencial em cache

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(fake.StsCalls).IsEqualTo(2);
    }

    [Test]
    public async Task Web_identity_renews_before_expiry_and_rereads_the_token_file()
    {
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        var fake = new FakeAws { Now = () => time.Now, WebIdentityToken = "jwt-1" };
        fake.Seed("db", "v");
        using var store = new AwsSecretsManagerSecretStore(WebIdentity(fake, "jwt-1", o => o.TimeProvider = time));

        await store.GetSecretAsync("db");
        Write("token", "jwt-2");                          // o Kubernetes troca o token projetado
        fake.WebIdentityToken = "jwt-2";
        time.Now = time.Now.AddMinutes(56);               // credencial de 1 hora: renovada 5 minutos antes de expirar
        var renewed = await store.GetSecretAsync("db");

        await Assert.That(renewed.IsSuccess).IsTrue();
        await Assert.That(fake.StsCalls).IsEqualTo(2);
        await Assert.That(fake.ReceivedWebIdentityTokens.Last()).IsEqualTo("jwt-2");
    }

    [Test]
    public async Task Sts_rejection_is_authentication_failure_and_is_not_retried_during_cooldown()
    {
        var fake = new FakeAws { WebIdentityToken = "outro" };
        using var store = new AwsSecretsManagerSecretStore(WebIdentity(fake, "jwt-recusado"));

        var first = await store.GetSecretAsync("db");
        var second = await store.GetSecretAsync("db");

        await Assert.That(first.Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(second.Error!.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(fake.StsCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Container_credentials_use_the_authorization_token_file()
    {
        var fake = new FakeAws { ContainerAuthorization = "token-do-pod-identity" };
        fake.Seed("db", "v");
        var variables = new Dictionary<string, string?>
        {
            ["AWS_CONTAINER_CREDENTIALS_FULL_URI"] = "http://169.254.170.23/v1/credentials",
            ["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"] = Write("pod-token", "token-do-pod-identity\n")
        };
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake, variables, o => o.UseContainerCredentials = true));

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(fake.ContainerCalls).IsEqualTo(1);
    }

    [Test]
    [Arguments("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://evil.example/credenciais")]
    [Arguments("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://usuario@169.254.170.2/credenciais")]
    [Arguments("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "//evil.example/credenciais")]
    [Arguments("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "credenciais-sem-barra")]
    public async Task Container_address_outside_the_allowed_hosts_fails_at_startup(string variable, string value)
    {
        var variables = new Dictionary<string, string?> { [variable] = value };

        await Assert.That(() => new AwsSecretsManagerSecretStore(AwsTestOptions.Create(new FakeAws(), variables, o => o.UseContainerCredentials = true)))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Imds_v2_gets_a_session_token_and_then_the_role_credentials()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake, [], o => o.UseInstanceMetadata = true));

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(fake.ImdsCalls).IsEqualTo(3);   // PUT do token, nome do papel, credencial
    }

    [Test]
    public async Task Unreachable_imds_falls_back_to_static_keys_for_the_process()
    {
        var fake = new FakeAws { ImdsReachable = false };
        fake.Seed("db", "v");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake, configure: o => o.UseInstanceMetadata = true));

        var first = await store.GetSecretAsync("db");
        var imdsCalls = fake.ImdsCalls;
        fake.Failures.Enqueue((HttpStatusCode.BadRequest, "ExpiredTokenException"));   // força um novo login
        var second = await store.GetSecretAsync("db");

        await Assert.That(first.IsSuccess).IsTrue();
        await Assert.That(second.IsSuccess).IsTrue();
        await Assert.That(imdsCalls).IsGreaterThan(0);
        await Assert.That(fake.ImdsCalls).IsEqualTo(imdsCalls);   // o novo login foi direto às chaves estáticas
    }

    [Test]
    public async Task Without_any_credential_source_startup_fails()
    {
        await Assert.That(() => new AwsSecretsManagerSecretStore(AwsTestOptions.Create(new FakeAws(), [])))
            .Throws<InvalidOperationException>();
    }

    // ---------- Endereço e região ----------

    [Test]
    [Arguments("http://secretsmanager.sa-east-1.amazonaws.com/")]
    [Arguments("https://usuario:senha@secretsmanager.sa-east-1.amazonaws.com/")]
    [Arguments("https://secretsmanager.sa-east-1.amazonaws.com/caminho")]
    [Arguments("https://secretsmanager.sa-east-1.amazonaws.com/?x=1")]
    public async Task Endpoint_must_be_https_and_server_only(string endpoint)
    {
        await Assert.That(() => new AwsSecretsManagerSecretStore(AwsTestOptions.Create(new FakeAws(), configure: o => o.Endpoint = new Uri(endpoint))))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("sa-east-1.evil.example/")]
    [Arguments("SA-EAST-1")]
    [Arguments(" ")]
    public async Task Region_cannot_change_the_host(string region)
    {
        await Assert.That(() => new AwsSecretsManagerSecretStore(AwsTestOptions.Create(new FakeAws(), configure: o => o.Region = region)))
            .Throws<InvalidOperationException>();
    }

    // ---------- Listagem ----------

    [Test]
    public async Task Listing_above_MaxListItems_fails_instead_of_truncating()
    {
        var fake = new FakeAws();
        foreach (var name in new[] { "a", "b", "c" })
            fake.Seed(name, "v");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake, configure: o => o.MaxListItems = 2));

        var result = await store.ListSecretsAsync();

        // Antes: devolvia os 2 primeiros com sucesso, e a fonte de IConfiguration carregava só uma parte
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
    }

    [Test]
    public async Task Listing_follows_every_page_and_reports_current_version()
    {
        var fake = new FakeAws { PageSize = 2 };
        foreach (var name in new[] { "a", "b", "c", "d", "e" })
            fake.Seed(name, "v");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        var result = await store.ListSecretsAsync();

        await Assert.That(result.Value.Select(p => p.Name)).IsEquivalentTo(["a", "b", "c", "d", "e"]);
        await Assert.That(result.Value.All(p => p.Version is not null)).IsTrue();
        await Assert.That(fake.Actions.Count(a => a == "ListSecrets")).IsEqualTo(3);
    }

    // ---------- Escrita e tags ----------

    [Test]
    public async Task UpdateSecretProperties_replaces_the_tags()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v", new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" });
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        var result = await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate
        {
            Tags = new Dictionary<string, string> { ["b"] = "3", ["c"] = "4" }
        });

        // Antes: só conferia que o segredo existia e devolvia sucesso sem aplicar as tags
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(fake.TagsOf("db")).IsEquivalentTo(new Dictionary<string, string> { ["b"] = "3", ["c"] = "4" });
        await Assert.That(result.Value.Tags).IsEquivalentTo(new Dictionary<string, string> { ["b"] = "3", ["c"] = "4" });
        await Assert.That(fake.Actions).Contains("UntagResource");
        await Assert.That(fake.Actions).Contains("TagResource");
    }

    [Test]
    public async Task UpdateSecretProperties_refuses_what_aws_cannot_apply_without_calling_it()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        var disable = await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate { Enabled = false });
        var tagsOfVersion = await store.UpdateSecretPropertiesAsync("db", new SecretPropertiesUpdate
        {
            Tags = new Dictionary<string, string> { ["a"] = "1" }
        }, version: "c0a80101-0000-0000-0000-000000000001");

        await Assert.That(disable.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(tagsOfVersion.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(fake.Actions).IsEmpty();
    }

    [Test]
    public async Task SetSecret_on_existing_secret_writes_a_version_and_replaces_the_tags()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v1", new Dictionary<string, string> { ["velha"] = "1" });
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        var written = await store.SetSecretAsync("db", "v2", new SecretWriteOptions { Tags = new Dictionary<string, string> { ["nova"] = "2" } });

        await Assert.That(written.IsSuccess).IsTrue();
        await Assert.That((await store.GetSecretAsync("db")).Value.Value).IsEqualTo("v2");
        await Assert.That(fake.TagsOf("db")).IsEquivalentTo(new Dictionary<string, string> { ["nova"] = "2" });
    }

    [Test]
    public async Task SetSecret_retried_after_server_error_reuses_the_ClientRequestToken()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v1");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake, configure: o => o.Http.MaxRetries = 1));
        fake.Failures.Enqueue((HttpStatusCode.InternalServerError, "InternalServiceError"));

        var written = await store.SetSecretAsync("db", "v2");

        await Assert.That(written.IsSuccess).IsTrue();
        await Assert.That(fake.ClientRequestTokens.Distinct().Count()).IsEqualTo(1);
        await Assert.That(fake.VersionCount("db")).IsEqualTo(2);
    }

    [Test]
    public async Task SetSecret_refuses_disabled_version_and_validity()
    {
        var fake = new FakeAws();
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        var disabled = await store.SetSecretAsync("db", "v", new SecretWriteOptions { Enabled = false });
        var expiring = await store.SetSecretAsync("db", "v", new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) });

        await Assert.That(disabled.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(expiring.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(fake.Actions).IsEmpty();
    }

    [Test]
    public async Task Delete_reports_the_aws_deletion_date()
    {
        var fake = new FakeAws();
        fake.Seed("db", "v");
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(fake));

        var deleted = await store.DeleteSecretAsync("db");

        await Assert.That(deleted.Value.ScheduledPurgeDate!.Value).IsGreaterThan(DateTimeOffset.UtcNow.AddDays(29));
        await Assert.That((await store.ExistsAsync("db")).Value).IsFalse();
    }

    // ---------- Sonda ----------

    [Test]
    public async Task CheckAccess_propagates_cancellation()
    {
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(new FakeAws()));
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        // Antes: um catch geral devolvia VAULT_INDISPONIVEL para o cancelamento
        await Assert.That(async () => { await store.CheckAccessAsync(cts.Token); }).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task CheckAccess_goes_through_the_provider_base_and_records_the_metric()
    {
        using var metrics = new OperationMetrics(AwsSecretsManagerSecretStore.Provider);
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(new FakeAws()));

        var result = await store.CheckAccessAsync();

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(metrics.Recorded.Any(m => m.Operation == "secret.health" && m.Error is null)).IsTrue();
    }

    // ---------- Configuração ----------

    [Test]
    [Arguments("SecretAccessKey")]
    [Arguments("SessionToken")]
    public async Task Inline_secret_in_configuration_is_rejected_without_echoing_it(string key)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "AwsSecretsManager",
            ["Vault:AwsSecretsManager:Region"] = "sa-east-1",
            [$"Vault:AwsSecretsManager:{key}"] = "valor-colado-por-engano"
        }).Build();

        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(configuration.GetSection("Vault"), p => p.AddAwsSecretsManager()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains($"Vault:AwsSecretsManager:{key}");
        await Assert.That(exception.Message).DoesNotContain("valor-colado-por-engano");
    }

    [Test]
    public async Task Unknown_key_in_configuration_is_rejected()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "AwsSecretsManager",
            ["Vault:AwsSecretsManager:Regiao"] = "sa-east-1"
        }).Build();

        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(configuration.GetSection("Vault"), p => p.AddAwsSecretsManager()))
            .Throws<InvalidOperationException>();

        // Antes: a chave desconhecida era ignorada em silêncio
        await Assert.That(exception!.Message).Contains("Vault:AwsSecretsManager:Regiao");
    }

    [Test]
    public async Task NameComparer_is_case_sensitive_like_aws()
    {
        using var store = new AwsSecretsManagerSecretStore(AwsTestOptions.Create(new FakeAws()));

        await Assert.That(store.NameComparer).IsEqualTo(StringComparer.Ordinal);
    }

    private AwsSecretsManagerOptions WebIdentity(FakeAws fake, string token, Action<AwsSecretsManagerOptions>? configure = null) =>
        AwsTestOptions.Create(fake, [], o =>
        {
            o.RoleArn = "arn:aws:iam::123456789012:role/minha-api";
            o.WebIdentityTokenFile = Write("token", token);
            configure?.Invoke(o);
        });
}
