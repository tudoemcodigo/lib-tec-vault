using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure;
using Azure.Core.Pipeline;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.AzureKeyVault.Internal;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.InMemory;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;
using TEC.Core.Text.Masking;
using SecretClient = Azure.Security.KeyVault.Secrets.SecretClient;
using SecretClientOptions = Azure.Security.KeyVault.Secrets.SecretClientOptions;

namespace TEC.Vault.Tests;

/// <summary>Regressões de segurança (Zero Trust): nenhuma delas acessa a rede.</summary>
public class SecurityTests
{
    private const string SecretValue = "VALOR-ULTRA-SECRETO-8f3a91";

    // ---------- Endereço do cofre: o token de acesso só pode ir para o Key Vault ----------

    [Test]
    [Arguments("http://kv-teste.vault.azure.net/")]                      // sem TLS
    [Arguments("https://kv-teste.vault.azure.net.evil.com/")]            // sufixo falso
    [Arguments("https://evil.com/")]                                     // outro domínio
    [Arguments("https://a.kv-teste.vault.azure.net/")]                   // subdomínio extra
    [Arguments("https://kv-teste.vault.azure.net:8443/")]                // porta
    [Arguments("https://user:pwd@kv-teste.vault.azure.net/")]            // credencial na URL
    [Arguments("https://kv-teste.vault.azure.net/secrets/")]             // caminho
    [Arguments("https://kv-teste.vault.azure.net/?x=1")]                 // query
    [Arguments("https://kv.vault.azure.net/")]                           // nome curto demais (mín. 3)
    public async Task VaultUri_outside_key_vault_pattern_is_rejected(string uri)
    {
        var options = new AzureKeyVaultOptions { VaultUri = new Uri(uri), Credential = new FakeCredential() };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("https://kv-exemplo.vault.azure.net/")]
    [Arguments("https://KV-EXEMPLO.vault.azure.net")]
    [Arguments("https://kv-teste.vault.azure.cn/")]
    [Arguments("https://kv-teste.vault.usgovcloudapi.net/")]
    public async Task Valid_VaultUri_is_accepted(string uri)
    {
        var options = new AzureKeyVaultOptions { VaultUri = new Uri(uri), Credential = new FakeCredential() };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
    }

    [Test]
    public async Task Missing_VaultUri_fails_at_startup() =>
        await Assert.That(() => AzureKeyVaultClients.Validate(new AzureKeyVaultOptions())).Throws<InvalidOperationException>();

    [Test]
    [Arguments("nao-e-guid", null)]
    [Arguments(null, "nao-e-guid")]
    public async Task TenantId_and_ClientId_must_be_guid(string? tenant, string? clientId)
    {
        var options = new AzureKeyVaultOptions
        {
            VaultUri = new Uri(FakeKeyVault.VaultUri),
            TenantId = tenant,
            ManagedIdentityClientId = clientId
        };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Developer_credential_outside_development_fails_closed()
    {
        Skip.When(VaultEnvironment.IsDevelopment(), "Processo de teste rodando com ambiente Development.");
        var options = new AzureKeyVaultOptions { VaultUri = new Uri(FakeKeyVault.VaultUri), Authentication = AzureKeyVaultAuthentication.Developer };

        await Assert.That(() => AzureKeyVaultClients.Validate(options)).Throws<InvalidOperationException>();

        options.AllowDeveloperCredentialsOutsideDevelopment = true;
        await Assert.That(() => AzureKeyVaultClients.Validate(options)).ThrowsNothing();
    }

    [Test]
    public async Task Token_is_not_sent_when_challenge_points_to_other_domain()
    {
        // Um servidor que responde ao desafio pedindo token para outro recurso não recebe token nenhum.
        // Host exclusivo: o SDK guarda o desafio em cache estático por host, e outro teste com o mesmo host faria o token
        // sair direto, sem passar pelo desafio (dependência de ordem de execução).
        var credential = new FakeCredential();
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("x", "y")), challengeResource: "https://evil.com");
        string host = $"https://kv-desafio-{Guid.NewGuid():N}"[..^24] + ".vault.azure.net/";
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(credential, host));

        var result = await store.GetSecretAsync("x");

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(credential.Calls).IsEqualTo(0);
        await Assert.That(vault.Requests.All(r => !r.Authorized)).IsTrue();
    }

    [Test]
    public async Task Token_is_requested_only_for_key_vault_scope()
    {
        var credential = new FakeCredential();
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("x", "y")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(credential));

        await store.GetSecretAsync("x");

        await Assert.That(credential.Scopes).IsEquivalentTo(new[] { "https://vault.azure.net/.default" });
        await Assert.That(vault.Requests.All(r => r.Uri.Host == "kv-teste.vault.azure.net")).IsTrue();
    }

    // ---------- Validação de entrada antes de qualquer chamada ----------

    [Test]
    [Arguments("")]
    [Arguments("../outro")]
    [Arguments("a/b")]
    [Arguments("a?b")]
    [Arguments("a b")]
    [Arguments("nome_com_underscore")]
    [Arguments("ção")]
    [Arguments("nome\n")]           // quebra de linha final: "$" aceitaria, "\z" não
    [Arguments("nome\r\n")]
    public async Task Invalid_name_is_rejected_without_calling_vault(string name)
    {
        var credential = new FakeCredential();
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(credential));

        var result = await store.GetSecretAsync(name);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(vault.Requests).IsEmpty();
        await Assert.That(credential.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task Name_longer_than_127_characters_is_rejected()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        var result = await store.GetSecretAsync(new string('a', 128));

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
    }

    [Test]
    public async Task Invalid_version_is_rejected()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        var result = await store.GetSecretAsync("nome", "../../keys/outra");

        await Assert.That(result.Error!.Field).IsEqualTo("version");
    }

    [Test]
    [Arguments("0123456789abcdef0123456789abcdef\n")]
    [Arguments("0123456789abcdef0123456789abcde\n")]
    public async Task Version_with_trailing_newline_is_rejected_without_calling_vault(string version)
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var secrets = new AzureKeyVaultSecretStore(vault.CreateClients());
        var keys = new AzureKeyVaultKeyStore(vault.CreateClients());

        var optional = await secrets.GetSecretAsync("nome", version);
        var required = await keys.DecryptAsync("nome", version, new byte[16]);

        await Assert.That(optional.Error!.Field).IsEqualTo("version");
        await Assert.That(required.Error!.Field).IsEqualTo("version");
        await Assert.That(vault.Requests).IsEmpty();
    }

    [Test]
    public async Task Trailing_newline_is_rejected_by_all_patterns()
    {
        var memory = Memory.Secrets();

        var name = await memory.GetSecretAsync("nome\n");
        var version = await memory.GetSecretAsync("nome", FakeKeyVault.Version + "\n");
        var dns = VaultCertificateRules.Create(new CreateCertificateOptions { Subject = "CN=api", DnsNames = ["api.exemplo.com\n"] });
        var issuer = AzureKeyVaultCertificateStore.ValidateCreate(new CreateCertificateOptions { Subject = "CN=api", Issuer = "MinhaCA\n" });

        await Assert.That(name.Error!.Field).IsEqualTo("name");
        await Assert.That(version.Error!.Field).IsEqualTo("version");
        await Assert.That(dns!.Field).IsEqualTo("dnsNames");
        await Assert.That(issuer!.Field).IsEqualTo("issuer");
        await Assert.That(VaultInputRules.HexVersionPattern().IsMatch(FakeKeyVault.Version)).IsTrue();
        await Assert.That(VaultInputRules.HexVersionPattern().IsMatch(FakeKeyVault.Version + "\n")).IsFalse();
    }

    [Test]
    public async Task Value_above_25KB_is_rejected_and_message_does_not_repeat_value()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());
        string value = SecretValue + new string('x', 26 * 1024);

        var result = await store.SetSecretAsync("nome", value);

        await Assert.That(result.Error!.Field).IsEqualTo("value");
        await Assert.That(result.Error.Message).DoesNotContain(SecretValue);
        await Assert.That(vault.Requests).IsEmpty();
    }

    [Test]
    public async Task Expiration_in_the_past_is_rejected()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());

        var result = await store.SetSecretAsync("nome", "v", new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddMinutes(-1) });

        await Assert.That(result.Error!.Field).IsEqualTo("expiresOn");
    }

    [Test]
    public async Task Tags_above_limit_or_with_control_characters_are_rejected()
    {
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients());
        var many = Enumerable.Range(0, 16).ToDictionary(i => $"t{i}", i => "v");
        var control = new Dictionary<string, string> { ["ok"] = "linha\nnova" };

        var r1 = await store.SetSecretAsync("nome", "v", new SecretWriteOptions { Tags = many });
        var r2 = await store.SetSecretAsync("nome", "v", new SecretWriteOptions { Tags = control });

        await Assert.That(r1.Error!.Field).IsEqualTo("tags");
        await Assert.That(r2.Error!.Field).IsEqualTo("tags");
    }

    [Test]
    public async Task Rsa_key_smaller_than_2048_is_rejected() =>
        await Assert.That(VaultKeyRules.Shape(VaultKeyType.Rsa, 1024, VaultKeyCurve.P256, null)!.Field).IsEqualTo("keySize");

    [Test]
    public async Task Ec_key_does_not_accept_encryption_operations() =>
        await Assert.That(VaultKeyRules.Shape(VaultKeyType.Ec, 0, VaultKeyCurve.P256, VaultKeyOperations.Encrypt)!.Field)
            .IsEqualTo("operations");

    [Test]
    public async Task Weak_algorithms_do_not_exist_in_api()
    {
        // RSA1_5 (padding oracle) e RSA-OAEP com SHA-1 não são representáveis
        await Assert.That(Enum.GetNames<VaultEncryptionAlgorithm>()).IsEquivalentTo(new[] { nameof(VaultEncryptionAlgorithm.RsaOaep256) });
    }

    [Test]
    [Arguments("")]
    [Arguments("CN=ok\n")]
    public async Task Invalid_certificate_subject_is_rejected(string subject) =>
        await Assert.That(AzureKeyVaultCertificateStore.ValidateCreate(new CreateCertificateOptions { Subject = subject })!.Field).IsEqualTo("subject");

    [Test]
    public async Task Malicious_dns_name_is_rejected()
    {
        var options = new CreateCertificateOptions { Subject = "CN=api", DnsNames = ["api.exemplo.com", "evil.com/../x"] };

        await Assert.That(AzureKeyVaultCertificateStore.ValidateCreate(options)!.Field).IsEqualTo("dnsNames");
    }

    [Test]
    public async Task Import_requires_private_key_and_correct_password()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=teste", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));
        byte[] pfx = cert.Export(X509ContentType.Pkcs12, "senha-correta");
        byte[] publicOnly = cert.Export(X509ContentType.Cert);

        var wrongPassword = VaultCertificateRules.InspectImport(pfx, "errada", CertificateContentFormat.Pkcs12, out _);
        var noKey = VaultCertificateRules.InspectImport(publicOnly, null, CertificateContentFormat.Pkcs12, out _);
        var ok = VaultCertificateRules.InspectImport(pfx, "senha-correta", CertificateContentFormat.Pkcs12, out var subject);

        await Assert.That(wrongPassword!.Field).IsEqualTo("certificate");
        await Assert.That(noKey!.Field).IsEqualTo("certificate");
        await Assert.That(ok).IsNull();
        await Assert.That(subject).IsEqualTo("CN=teste");
    }

    [Test]
    public async Task Import_rejects_rsa_1024()
    {
        using var rsa = RSA.Create(1024);
        var request = new CertificateRequest("CN=fraco", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1));

        var error = VaultCertificateRules.InspectImport(cert.Export(X509ContentType.Pkcs12, "s"), "s", CertificateContentFormat.Pkcs12, out _);

        await Assert.That(error!.Message).Contains("2048");
    }

    // ---------- O valor nunca vaza ----------

    [Test]
    public async Task VaultSecret_ToString_masks_value()
    {
        var secret = new VaultSecret(new SecretProperties { Name = "db" }, SecretValue);

        await Assert.That(secret.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{secret}").Contains("***");
    }

    [Test]
    public async Task ImportCertificateOptions_ToString_masks_password()
    {
        var options = new ImportCertificateOptions { Password = SecretValue, Exportable = true };
        var copy = options with { Enabled = false };

        await Assert.That(options.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{copy}").DoesNotContain(SecretValue);
        await Assert.That(options.ToString()).Contains("Password = ***");
        await Assert.That(new ImportCertificateOptions().ToString()).Contains("Password = null");
    }

    [Test]
    public async Task Name_rejected_by_validation_does_not_reach_log_raw()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}")).CreateClients(),
            factory.CreateLogger<AzureKeyVaultSecretStore>());
        string name = "nome invalido " + SecretValue;

        var result = await store.GetSecretAsync(name);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
        await Assert.That(logs.AllText).Contains($"{name.Length} caracteres");
        await Assert.That(logs.AllText).Contains("hmac:");
        await Assert.That(logs.AllText).DoesNotContain("sha256:");
    }

    [Test]
    public async Task Managed_secret_read_is_audited_at_Information_without_value()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        string json = FakeKeyVault.SecretJson("cert-api", SecretValue).Replace("\"tags\"", "\"managed\":true,\"tags\"", StringComparison.Ordinal);
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, json)).CreateClients(),
            factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("cert-api");

        await Assert.That(result.Value.Properties.ManagedBy).IsEqualTo("certificate");   // permitido...
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Information && e.Text.Contains("cert-api")
            && e.Text.Contains(AzureKeyVaultSecretStore.ManagedSecretAuditReason))).IsTrue();   // ...mas auditado
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
    }

    [Test]
    public async Task Regular_secret_read_does_not_audit_at_Information()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var store = new AzureKeyVaultSecretStore(new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("db", SecretValue))).CreateClients(),
            factory.CreateLogger<AzureKeyVaultSecretStore>());

        await store.GetSecretAsync("db");

        await Assert.That(logs.Entries.Any(e => e.Level >= LogLevel.Information)).IsFalse();
    }

    [Test]
    public async Task Firewall_forbidden_becomes_access_denied_with_error_log()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden",
            "Public network access is disabled and request is not from a trusted service nor via an approved private link.", "ForbiddenByConnection")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Error && e.Text.Contains("ForbiddenByConnection"))).IsTrue();
    }

    [Test]
    [Arguments("SecretDisabled")]
    [Arguments("KeyDisabled")]
    [Arguments("CertificateDisabled")]
    public async Task Structured_disabled_item_code_becomes_Disabled(string innerCode)
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "qualquer texto", innerCode)));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.DisabledCode);
    }

    [Test]
    public async Task Malformed_inner_code_does_not_reach_log()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "x", "<script>alert(1)</script>")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);
        await Assert.That(logs.AllText).DoesNotContain("<script>");
    }

    [Test]
    [Arguments("<script>alert(1)</script>")]
    [Arguments("codigo com espaco")]
    public async Task Malformed_error_code_does_not_reach_log(string code)
    {
        // error.code vem do corpo da resposta, como o innererror.code: passa pela mesma conferência (SafeCode)
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.BadRequest, FakeKeyVault.ErrorJson(code, "x")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var result = await store.GetSecretAsync("db");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.RejectedCode);
        await Assert.That(logs.AllText).DoesNotContain(code);
        await Assert.That(logs.AllText).Contains(AzureKeyVaultStoreBase.InvalidCodeMarker);
    }

    [Test]
    public async Task SafeCode_accepts_only_short_ascii_identifier()
    {
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("SecretNotFound")).IsEqualTo("SecretNotFound");
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("Forbidden_By-Rbac.1")).IsEqualTo("Forbidden_By-Rbac.1");
        await Assert.That(AzureKeyVaultStoreBase.SafeCode(null)).IsNull();
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("")).IsNull();
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("linha\nnova")).IsEqualTo(AzureKeyVaultStoreBase.InvalidCodeMarker);
        await Assert.That(AzureKeyVaultStoreBase.SafeCode("códigoAcentuado")).IsEqualTo(AzureKeyVaultStoreBase.InvalidCodeMarker);
        await Assert.That(AzureKeyVaultStoreBase.SafeCode(new string('a', 65))).IsEqualTo(AzureKeyVaultStoreBase.InvalidCodeMarker);
    }

    [Test]
    public async Task Rejected_name_is_described_with_process_keyed_hmac_not_plain_hash()
    {
        // Um SHA-256 puro permitiria confirmar, fora do processo, um palpite sobre o texto recusado (ex.: um valor colado no nome)
        string name = "nome invalido " + SecretValue;
        string sha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(name)), 0, 6);

        string first = SensitiveDataMasker.DescribeUntrusted(name);
        string second = SensitiveDataMasker.DescribeUntrusted(name);
        string other = SensitiveDataMasker.DescribeUntrusted(name + "x");

        await Assert.That(first).IsEqualTo(second);          // mesmo texto, mesmo identificador (correlação dentro do processo)
        await Assert.That(other).IsNotEqualTo(first);
        await Assert.That(first).Contains("hmac:");
        await Assert.That(first).DoesNotContain(sha256);
        await Assert.That(first).DoesNotContain(SecretValue);
    }

    [Test]
    public async Task Internal_records_with_secret_value_mask_ToString()
    {
        var version = new InMemorySecretStore.Version(new SecretProperties { Name = "db", Version = FakeKeyVault.Version }, SecretValue);
        var snapshot = new VaultConfigurationProvider.Snapshot(FakeKeyVault.Version, DateTimeOffset.UtcNow, "Db:Senha", SecretValue);

        await Assert.That(version.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{version with { Value = SecretValue + "2" }}").DoesNotContain(SecretValue);
        await Assert.That(version.ToString()).Contains("Value = ***");
        await Assert.That(snapshot.ToString()).DoesNotContain(SecretValue);
        await Assert.That($"{snapshot}").Contains("Value = ***");
    }

    [Test]
    public async Task Sdk_clients_do_not_create_spans_with_address_and_item_name()
    {
        // Os spans do SDK levam url.full/az.namespace (endereço do cofre + nome e versão do item) ao backend de rastreamento
        var started = new ConcurrentQueue<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.StartsWith("Azure.", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = started.Enqueue
        };
        ActivitySource.AddActivityListener(listener);

        // Controle: um cliente do SDK com as opções padrão gera spans (prova que o listener os enxerga)
        var control = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("item-controle", "v")));
        var sdk = new SecretClient(new Uri(FakeKeyVault.VaultUri), new FakeCredential(),
            new SecretClientOptions { Transport = new HttpClientTransport(new HttpClient(control)) });
        await sdk.GetSecretAsync("item-controle");
        await Assert.That(started.Any(a => Describe(a).Contains("item-controle", StringComparison.Ordinal))).IsTrue();

        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, FakeKeyVault.SecretJson("item-sem-span", "v")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());
        var result = await store.GetSecretAsync("item-sem-span");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(started.Any(a => Describe(a).Contains("item-sem-span", StringComparison.Ordinal))).IsFalse();

        static string Describe(Activity activity) =>
            activity.DisplayName + " " + string.Join(' ', activity.TagObjects.Select(t => $"{t.Key}={t.Value}"));
    }

    [Test]
    public async Task Write_and_failure_logs_do_not_contain_value()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((request, body) => request.Method == HttpMethod.Put
            ? (HttpStatusCode.OK, FakeKeyVault.SecretJson("db", SecretValue))
            : (HttpStatusCode.Forbidden, FakeKeyVault.ErrorJson("Forbidden", "Caller is not authorized.", "ForbiddenByRbac")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());

        var set = await store.SetSecretAsync("db", SecretValue);
        var get = await store.GetSecretAsync("db");

        await Assert.That(set.IsSuccess).IsTrue();
        await Assert.That(get.Error!.Code).IsEqualTo(VaultErrors.AccessDeniedCode);
        await Assert.That(logs.Entries).IsNotEmpty();
        await Assert.That(logs.AllText).DoesNotContain(SecretValue);
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Information && e.Text.Contains("secret.set"))).IsTrue();
    }

    // ---------- Conversão de erros: nada de infraestrutura chega ao cliente ----------

    [Test]
    [Arguments(400, "BadParameter", "detalhe-interno-do-servidor", VaultErrors.RejectedCode, ErrorType.Validation)]
    [Arguments(401, "Unauthorized", "detalhe-interno-do-servidor", VaultErrors.AuthenticationFailedCode, ErrorType.ExternalService)]
    // Sem código estruturado de item desabilitado, 403 é acesso negado: o texto da mensagem não decide mais nada
    [Arguments(403, "Forbidden", "Operation get is not allowed on a disabled secret.", VaultErrors.AccessDeniedCode, ErrorType.ExternalService)]
    [Arguments(403, "Forbidden", "Public network access is disabled and request is not from a trusted service.", VaultErrors.AccessDeniedCode, ErrorType.ExternalService)]
    [Arguments(403, "SecretDisabled", "x", VaultErrors.DisabledCode, ErrorType.BusinessRule)]
    [Arguments(403, "Forbidden", "Caller is not authorized. ForbiddenByRbac", VaultErrors.AccessDeniedCode, ErrorType.ExternalService)]
    [Arguments(404, "SecretNotFound", "detalhe-interno-do-servidor", VaultErrors.NotFoundCode, ErrorType.NotFound)]
    [Arguments(409, "Conflict", "detalhe-interno-do-servidor", VaultErrors.ConflictCode, ErrorType.Conflict)]
    [Arguments(429, "Throttled", "detalhe-interno-do-servidor", VaultErrors.ThrottledCode, ErrorType.ExternalService)]
    [Arguments(503, "ServiceUnavailable", "detalhe-interno-do-servidor", VaultErrors.UnavailableCode, ErrorType.ExternalService)]
    [Arguments(0, null, "DNS", VaultErrors.UnavailableCode, ErrorType.ExternalService)]
    public async Task RequestFailedException_is_converted(int status, string? code, string message, string expectedCode, ErrorType expectedType)
    {
        var mapped = AzureKeyVaultStoreBase.Map(new RequestFailedException(status, message, code, null));

        await Assert.That(mapped!.Value.Error.Code).IsEqualTo(expectedCode);
        await Assert.That(mapped.Value.Error.Type).IsEqualTo(expectedType);
        await Assert.That(mapped.Value.Error.Message).DoesNotContain(message);
    }

    [Test]
    public async Task Authentication_failure_is_converted_without_details()
    {
        var mapped = AzureKeyVaultStoreBase.Map(new AuthenticationFailedException("AADSTS700016: tenant 1234 ..."));

        await Assert.That(mapped!.Value.Error.Code).IsEqualTo(VaultErrors.AuthenticationFailedCode);
        await Assert.That(mapped.Value.Detail).DoesNotContain("AADSTS");
    }

    [Test]
    public async Task Unknown_exception_is_not_converted_by_map() =>
        await Assert.That(AzureKeyVaultStoreBase.Map(new InvalidCastException())).IsNull();

    [Test]
    public async Task Infrastructure_errors_are_not_exposed_to_client()
    {
        Error[] hidden = [VaultErrors.AccessDenied(), VaultErrors.AuthenticationFailed(), VaultErrors.Throttled(), VaultErrors.Unavailable(), VaultErrors.ProviderFailure()];

        foreach (var error in hidden)
            await Assert.That(error.Type.IsExposedToClient()).IsFalse();
    }
}
