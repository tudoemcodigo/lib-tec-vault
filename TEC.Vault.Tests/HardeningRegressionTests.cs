using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Caching;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.HashiCorpVault;
using TEC.Vault.InMemory;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>Regressões das correções da revisão de robustez (os comentários "Antes:" descrevem a falha que cada teste pegava).</summary>
public class HardeningRegressionTests : TempFolderTest
{
    // ---------------------------------------------------------------- HashiCorp Vault

    [Test]
    public async Task HashiCorp_version_beyond_int_range_is_invalid_input_not_provider_failure()
    {
        var fake = new FakeHashiCorpVault();
        using var secrets = new HashiCorpVaultSecretStore(HashiCorpTestOptions.Create(fake, Folder));
        using var keys = new HashiCorpVaultKeyStore(HashiCorpTestOptions.Create(fake, Folder));
        await secrets.SetSecretAsync("db", "valor");

        var secret = await secrets.GetSecretAsync("db", "9999999999");
        var key = await keys.GetKeyAsync("chave", "9999999999");

        // Antes: 10 dígitos passavam na validação e o int.Parse estourava dentro da operação (VAULT_FALHA, exceção no log)
        await Assert.That(secret.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(key.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That((await secrets.GetSecretAsync("db", "999999999")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task HashiCorp_malformed_signature_is_unexpected_format_without_unexpected_exception()
    {
        var fake = new FakeHashiCorpVault();
        using var logs = new CapturingLoggerProvider();
        using var loggerFactory = new LoggerFactory([logs]);
        var tampering = new SignatureTamperingHandler { InnerHandler = fake };
        using var store = new HashiCorpVaultKeyStore(HashiCorpTestOptions.Create(fake, Folder, o => o.Http.Handler = tampering),
            loggerFactory.CreateLogger<HashiCorpVaultKeyStore>());
        await store.CreateKeyAsync("assinatura", new CreateKeyOptions { KeyType = VaultKeyType.Ec });

        var signed = await store.SignDataAsync("assinatura", [1, 2, 3], VaultSignatureAlgorithm.ES256);

        await Assert.That(signed.Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
        await Assert.That(logs.AllText).Contains("resposta em formato inesperado");
        await Assert.That(logs.AllText).DoesNotContain("FormatException");
    }

    [Test]
    public async Task HashiCorp_listing_above_MaxListItems_fails_without_reading_items()
    {
        var fake = new FakeHashiCorpVault();
        using var secrets = new HashiCorpVaultSecretStore(HashiCorpTestOptions.Create(fake, Folder, o => o.MaxListItems = 2));
        using var certificates = new HashiCorpVaultCertificateStore(HashiCorpTestOptions.Create(fake, Folder, o => o.MaxListItems = 2));
        foreach (var name in new[] { "a", "b", "c" })
        {
            await secrets.SetSecretAsync(name, "valor");
            await certificates.CreateCertificateAsync(name, new TEC.Vault.Certificates.CreateCertificateOptions
            {
                Subject = "CN=" + name, Issuer = HashiCorpVaultCertificateStore.SelfIssuer, KeySize = 2048
            });
        }

        fake.Requests.Clear();
        var listed = await secrets.ListSecretsAsync();
        var deleted = await secrets.ListDeletedSecretsAsync();
        var listedCertificates = await certificates.ListCertificatesAsync();

        await Assert.That(listed.Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That(deleted.Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That(listedCertificates.Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        // Só as listagens de nomes: nenhum metadado de item foi lido depois de passar do limite
        await Assert.That(fake.Requests.Count(r => r.StartsWith("GET v1/secret/metadata/minha-api/", StringComparison.Ordinal)
            && !r.EndsWith("/_certificates", StringComparison.Ordinal))).IsEqualTo(0);

        using var roomy = new HashiCorpVaultSecretStore(HashiCorpTestOptions.Create(fake, Folder, o => o.MaxListItems = 3));
        await Assert.That((await roomy.ListSecretsAsync()).Value.Count).IsEqualTo(3);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1_000_001)]
    public async Task MaxListItems_out_of_range_fails_at_creation(int maxListItems)
    {
        var fake = new FakeHashiCorpVault();

        await Assert.That(() => new HashiCorpVaultSecretStore(HashiCorpTestOptions.Create(fake, Folder, o => o.MaxListItems = maxListItems)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients(configure: o => o.MaxListItems = maxListItems))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Azure_listing_above_MaxListItems_stops_paging()
    {
        var vault = new FakeKeyVault((request, _) => request.RequestUri!.Query.Contains("pagina2", StringComparison.Ordinal)
            ? (HttpStatusCode.OK, """{"value":[{"id":"https://kv-teste.vault.azure.net/secrets/c","attributes":{"enabled":true}}],"nextLink":null}""")
            : (HttpStatusCode.OK, """{"value":[{"id":"https://kv-teste.vault.azure.net/secrets/a","attributes":{"enabled":true}},{"id":"https://kv-teste.vault.azure.net/secrets/b","attributes":{"enabled":true}}],"nextLink":"https://kv-teste.vault.azure.net/secrets?api-version=7.6&pagina2=1"}"""));
        var limited = new TEC.Vault.AzureKeyVault.AzureKeyVaultSecretStore(vault.CreateClients(configure: o => o.MaxListItems = 1));
        var roomy = new TEC.Vault.AzureKeyVault.AzureKeyVaultSecretStore(vault.CreateClients(configure: o => o.MaxListItems = 3));

        var failed = await limited.ListSecretsAsync();
        bool secondPageRequested = vault.Requests.Any(r => r.Uri.Query.Contains("pagina2", StringComparison.Ordinal));
        var listed = await roomy.ListSecretsAsync();

        await Assert.That(failed.Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That(secondPageRequested).IsFalse();
        await Assert.That(listed.Value.Count).IsEqualTo(3);
    }

    [Test]
    public async Task HashiCorp_deleted_listings_use_standard_operation_names()
    {
        var fake = new FakeHashiCorpVault();
        using var logs = new CapturingLoggerProvider();
        using var loggerFactory = new LoggerFactory([logs]);
        using var secrets = new HashiCorpVaultSecretStore(HashiCorpTestOptions.Create(fake, Folder), loggerFactory.CreateLogger<HashiCorpVaultSecretStore>());
        using var certificates = new HashiCorpVaultCertificateStore(HashiCorpTestOptions.Create(fake, Folder),
            loggerFactory.CreateLogger<HashiCorpVaultCertificateStore>());

        await secrets.ListDeletedSecretsAsync();
        await certificates.ListDeletedCertificatesAsync();

        // Mesma dimensão vault.operation dos demais provedores (antes: secret.deleted / certificate.deleted)
        await Assert.That(logs.AllText).Contains("secret.list-deleted");
        await Assert.That(logs.AllText).Contains("certificate.list-deleted");
        await Assert.That(logs.AllText).DoesNotContain(".deleted de");
    }

    [Test]
    public async Task HashiCorp_case_insensitive_lookup_and_version_listings_respect_MaxListItems()
    {
        var fake = new FakeHashiCorpVault();
        using var store = new HashiCorpVaultSecretStore(HashiCorpTestOptions.Create(fake, Folder, o => o.MaxListItems = 2));
        foreach (var name in new[] { "a", "b", "c" })
            await store.SetSecretAsync(name, "v");
        await store.SetSecretAsync("a", "v2");
        await store.SetSecretAsync("a", "v3");

        // Nome sem correspondência exata: a busca sem diferenciar maiúsculas lista a pasta (3 itens > 2)
        var lookup = await store.GetSecretAsync("Z");
        var versions = await store.ListSecretVersionsAsync("a");

        await Assert.That(lookup.Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That(versions.Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That((await store.GetSecretAsync("b")).Value.Value).IsEqualTo("v");   // nome exato não lista a pasta
    }

    /// <summary>Devolve uma assinatura com Base64Url inválido no lugar da resposta do Transit.</summary>
    private sealed class SignatureTamperingHandler : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath.Contains("/sign/", StringComparison.Ordinal))
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("""{"data":{"signature":"vault:v1:@@@não-é-base64@@@"}}""", Encoding.UTF8, "application/json")
                };
            }

            return await base.SendAsync(request, cancellationToken);
        }
    }

    // ---------------------------------------------------------------- Infisical

    [Test]
    public async Task Infisical_malformed_metadata_does_not_break_listing()
    {
        var fake = new FakeInfisical();
        var handler = new MetadataListingHandler { InnerHandler = fake };
        using var store = InfisicalTestStore.Create(fake, Folder, o => o.Http.Handler = handler);

        var listed = await store.ListSecretsAsync();

        // Antes: chaves repetidas sem diferenciar maiúsculas (ou nula) lançavam no ToDictionary e a listagem inteira falhava
        await Assert.That(listed.IsSuccess).IsTrue();
        var tags = listed.Value.Single().Tags;
        await Assert.That(tags["env"]).IsEqualTo("prod");
        await Assert.That(tags["ENV"]).IsEqualTo("PROD");
        await Assert.That(tags.ContainsKey("secreto")).IsFalse();
        await Assert.That(tags.Count).IsEqualTo(2);
    }

    /// <summary>Lista um segredo com metadados malformados (chave repetida, chave nula, metadado criptografado).</summary>
    private sealed class MetadataListingHandler : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Get && request.RequestUri!.AbsolutePath == "/api/v4/secrets")
            {
                const string json = """
                    {"secrets":[{"secretKey":"db","version":1,"secretMetadata":[
                      {"key":"env","value":"prod"},{"key":"ENV","value":"PROD"},{"key":null,"value":"x"},
                      {"key":"secreto","value":"y","isEncrypted":true}]}]}
                    """;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }

            return await base.SendAsync(request, cancellationToken);
        }
    }

    // ---------------------------------------------------------------- Azure Key Vault

    [Test]
    public async Task Azure_write_validation_uses_injected_clock()
    {
        // Relógio da aplicação em 2000: expirar em 2001 está no futuro, embora já tenha passado no relógio real
        var time = new FixedTimeProvider(new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.ServiceUnavailable, """{"error":{"code":"ServiceUnavailable"}}"""));
        var store = new TEC.Vault.AzureKeyVault.AzureKeyVaultSecretStore(vault.CreateClients(configure: o =>
        {
            o.TimeProvider = time;
            o.MaxRetries = 0;
        }));

        var result = await store.SetSecretAsync("db", "valor", new SecretWriteOptions { ExpiresOn = new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero) });

        // Antes a validação usava DateTimeOffset.UtcNow: recusava como entrada inválida sem chegar ao cofre
        await Assert.That(result.Error!.Code).IsNotEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(vault.Requests.Any(r => r.Method == "PUT" && r.Authorized)).IsTrue();
    }

    // ---------------------------------------------------------------- Em memória

    [Test]
    public async Task InMemory_key_generation_does_not_block_other_operations()
    {
        var store = new InMemoryKeyStore(new InMemoryVaultOptions { AllowOutsideDevelopment = true });
        await store.CreateKeyAsync("existente", new CreateKeyOptions { KeyType = VaultKeyType.Ec });

        // RSA 4096 leva centenas de milissegundos para gerar; antes a geração acontecia dentro da trava do store
        var creations = Enumerable.Range(0, 3)
            .Select(i => Task.Run(() => store.CreateKeyAsync($"rsa-{i}", new CreateKeyOptions { KeySize = 4096 })))
            .ToArray();
        await Task.Delay(50);

        int readsWhileGenerating = 0;
        var watch = Stopwatch.StartNew();
        while (!creations.All(c => c.IsCompleted) && watch.Elapsed < TimeSpan.FromSeconds(30))
        {
            var read = await Task.Run(() => store.GetKeyAsync("existente"));
            await Assert.That(read.IsSuccess).IsTrue();
            if (!creations.All(c => c.IsCompleted))
                readsWhileGenerating++;
        }

        await Task.WhenAll(creations);
        await Assert.That(creations.All(c => c.Result.IsSuccess)).IsTrue();
        await Assert.That(readsWhileGenerating).IsGreaterThan(0);
    }

    [Test]
    public async Task InMemory_rotation_of_key_deleted_during_generation_is_not_added()
    {
        var store = new InMemoryKeyStore(new InMemoryVaultOptions { AllowOutsideDevelopment = true });
        await store.CreateKeyAsync("chave", new CreateKeyOptions { KeySize = 4096 });

        var rotation = Task.Run(() => store.RotateKeyAsync("chave"));
        await store.DeleteKeyAsync("chave");
        var rotated = await rotation;

        // A rotação terminou antes ou depois da exclusão: nunca deixa uma versão nova "viva" fora da lixeira
        var versions = await store.ListKeyVersionsAsync("chave");
        await Assert.That(versions.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
        await Assert.That(rotated.IsSuccess || rotated.Error!.Code is VaultErrors.ConflictCode or VaultErrors.NotFoundCode).IsTrue();
    }

    // ---------------------------------------------------------------- Núcleo

    [Test]
    public async Task Cache_keeps_name_and_version_apart_without_textual_collision()
    {
        using var cache = new CachingSecretReader(new EchoReader(), TimeSpan.FromMinutes(1));

        var first = await cache.GetSecretAsync("a\n", "b");
        var second = await cache.GetSecretAsync("a", "\nb");

        // Antes a chave era "nome\nversão": as duas leituras viravam "a\n\nb" e a segunda recebia o segredo da primeira
        await Assert.That(first.Value.Value).IsEqualTo("a\n|b");
        await Assert.That(second.Value.Value).IsEqualTo("a|\nb");
    }

    /// <summary>Leitor que devolve "nome|versão" como valor (aceita qualquer texto, para testar só o cache).</summary>
    private sealed class EchoReader : ISecretReader
    {
        public string ProviderName => "Echo";

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<VaultSecret>.Success(new VaultSecret(new SecretProperties { Name = name, Version = version, Enabled = true },
                $"{name}|{version}")));

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => Task.FromResult(Result<bool>.Success(true));

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<IReadOnlyList<SecretProperties>>.Success([]));

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<IReadOnlyList<SecretProperties>>.Success([]));
    }

    [Test]
    public async Task Name_validation_with_regex_timeout_is_rejected_without_exception()
    {
        // Padrão de terceiro com retrocesso catastrófico: o tempo limite vira entrada recusada, não exceção para o chamador
        var pattern = new Regex("^(a+)+$", RegexOptions.None, TimeSpan.FromMilliseconds(1));
        string hostile = new string('a', 40) + "!";

        var error = VaultInputRules.Name(hostile, pattern, "regra");
        var versionError = VaultInputRules.Version(hostile, pattern);

        await Assert.That(error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(versionError!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
    }

    [Test]
    public async Task Retry_after_beyond_limit_on_503_keeps_unavailable_status()
    {
        using var client = new VaultHttpClient(new Uri("https://cofre.teste/"),
            new VaultHttpSettings { Handler = new LongRetryAfterHandler(), MaxRetries = 2, MaxRetryDelay = TimeSpan.FromSeconds(1) });

        var exception = await Assert.That(async () =>
            {
                using var response = await client.SendAsync(() => new HttpRequestMessage(HttpMethod.Get, "v1/x"), idempotent: true, CancellationToken.None);
            })
            .Throws<VaultHttpException>();

        // Antes: qualquer Retry-After longo virava 429 (VAULT_LIMITE_EXCEDIDO), mesmo com o cofre fora do ar (503)
        await Assert.That(exception!.StatusCode).IsEqualTo(HttpStatusCode.ServiceUnavailable);
        await Assert.That(VaultHttpProviderBase.MapHttpException(exception)!.Value.Error.Code).IsEqualTo(VaultErrors.UnavailableCode);
    }

    [Test]
    public async Task Response_above_MaxResponseBytes_is_mapped_explicitly()
    {
        using var client = new VaultHttpClient(new Uri("https://cofre.teste/"),
            new VaultHttpSettings { Handler = new LargeBodyHandler(), MaxResponseBytes = 1024 });
        using var response = await client.SendAsync(() => new HttpRequestMessage(HttpMethod.Get, "v1/x"), idempotent: true, CancellationToken.None);

        var exception = await Assert.That(async () => { await client.ReadBytesAsync(response, CancellationToken.None); })
            .Throws<VaultResponseTooLargeException>();
        var failure = VaultHttpProviderBase.MapHttpException(exception!)!.Value;

        // Antes: VaultHttpException com status 200 caía por acaso no ramo padrão de MapStatus ("200 resposta acima do limite")
        await Assert.That(exception!.MaxBytes).IsEqualTo(1024);
        await Assert.That(failure.Error.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
        await Assert.That(failure.Detail).Contains("MaxResponseBytes");
    }

    private sealed class LargeBodyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new MemoryStream(new byte[4096])) });
    }

    [Test]
    public async Task InMemory_certificate_auto_renewal_returns_NotSupported()
    {
        var store = new InMemoryCertificateStore(new InMemoryVaultOptions { AllowOutsideDevelopment = true });

        var result = await store.CreateCertificateAsync("api", new TEC.Vault.Certificates.CreateCertificateOptions
        {
            Subject = "CN=api", KeySize = 2048, AutoRenewDaysBeforeExpiry = 30
        });

        // Antes: aceito e ignorado em silêncio
        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotSupportedCode);
    }

    [Test]
    public async Task Failed_manual_reload_is_logged_as_reload_not_initial_load()
    {
        var reader = new ToggleReader();
        using var logs = new CapturingLoggerProvider();
        using var loggerFactory = new LoggerFactory([logs]);
        var root = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddTecVault(reader, o => o.Optional = true, loggerFactory: loggerFactory)
            .Build();

        reader.Fail = true;
        root.Reload();

        await Assert.That(logs.AllText).Contains("falha na recarga");
        await Assert.That(logs.AllText).DoesNotContain("falha na carga inicial");
        await Assert.That(root["db"]).IsEqualTo("valor");   // valores anteriores mantidos
        (root as IDisposable)?.Dispose();
    }

    /// <summary>Leitor com um segredo que passa a falhar quando <see cref="Fail"/> é ligado.</summary>
    private sealed class ToggleReader : ISecretReader
    {
        public volatile bool Fail;

        public string ProviderName => "Toggle";

        private static SecretProperties Db => new() { Name = "db", Version = "1", Enabled = true };

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(Fail ? Result<VaultSecret>.Failure(VaultErrors.Unavailable()) : Result<VaultSecret>.Success(new VaultSecret(Db, "valor")));

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => Task.FromResult(Result<bool>.Success(true));

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Fail
                ? Result<IReadOnlyList<SecretProperties>>.Failure(VaultErrors.Unavailable())
                : Result<IReadOnlyList<SecretProperties>>.Success([Db]));

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            Task.FromResult(Result<IReadOnlyList<SecretProperties>>.Success([Db]));
    }

    [Test]
    public async Task DotEnv_space_hash_after_equals_starts_comment_but_quotes_keep_hash()
    {
        var pairs = TEC.Vault.Synced.Internal.SecretFileParsers.ParseDotEnv("A= # comentário\nB=x #y\nC=\"v #z\"\nD=#literal\nE='a #b'\n")
            .ToDictionary(p => p.Key, p => p.Value);

        // Antes: "A= # comentário" virava o valor "# comentário"
        await Assert.That(pairs["A"]).IsEqualTo(string.Empty);
        await Assert.That(pairs["B"]).IsEqualTo("x");
        await Assert.That(pairs["C"]).IsEqualTo("v #z");
        await Assert.That(pairs["D"]).IsEqualTo("#literal");
        await Assert.That(pairs["E"]).IsEqualTo("a #b");
    }

    private sealed class LongRetryAfterHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromHours(1));
            return Task.FromResult(response);
        }
    }

    [Test]
    public async Task Credential_file_is_read_bounded_and_without_utf8_bom()
    {
        var withBom = Path.Combine(Folder, "token-bom");
        File.WriteAllText(withBom, "token-123\n", new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        var huge = Path.Combine(Folder, "token-gigante");
        File.WriteAllText(huge, new string('x', VaultCredentialInput.MaxFileBytes + 1));

        await Assert.That(VaultCredentialInput.FromFile(withBom, "teste").Read()).IsEqualTo("token-123");
        await Assert.That(() => VaultCredentialInput.FromFile(huge, "teste").Read()).Throws<InvalidOperationException>();
    }
}
