using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>
/// Fuzzing com semente fixa (sem rede): entradas hostis nos parâmetros, respostas corrompidas do cofre e conteúdo adulterado
/// (PFX/PEM, backups, envelopes). Propriedades verificadas em todas as iterações: nenhuma exceção escapa (tudo vira
/// <see cref="Result"/>), entrada inválida nunca chega ao cofre, conteúdo adulterado nunca é aceito e nenhum valor vai para o log.
/// </summary>
public class FuzzTests
{
    private const string Canary = "CANARIO-FUZZ-5e0c7d";

    private static readonly HashSet<string> KnownCodes =
    [
        VaultErrors.InvalidInputCode, VaultErrors.NotFoundCode, VaultErrors.ConflictCode, VaultErrors.DisabledCode,
        VaultErrors.NotExportableCode, VaultErrors.RejectedCode, VaultErrors.AccessDeniedCode, VaultErrors.AuthenticationFailedCode,
        VaultErrors.ThrottledCode, VaultErrors.UnavailableCode, VaultErrors.NotSupportedCode, VaultErrors.ProviderFailureCode,
        VaultErrors.CircuitOpenCode
    ];

    [Test]
    public async Task Hostile_names_and_versions_reach_vault_only_when_valid()
    {
        var random = new Random(Fuzz.Seed);
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.NotFound, FakeKeyVault.ErrorJson("SecretNotFound", "x")));
        var store = new AzureKeyVaultSecretStore(vault.CreateClients());
        int expectedRequests = 0;

        for (int i = 0; i < Fuzz.Iterations; i++)
        {
            string name = Fuzz.Text(random);
            string? version = random.Next(3) == 0 ? Fuzz.Text(random, 6) : random.Next(2) == 0 ? null : Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
            bool valid = Fuzz.IsValidKeyVaultName(name) && (version is null || Fuzz.IsValidVersion(version));

            Result<VaultSecret> result;
            try
            {
                result = await store.GetSecretAsync(name, version);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Exceção com a semente {Fuzz.Seed}, iteração {i}: {ex.GetType().Name}", ex);
            }

            if (valid)
            {
                expectedRequests++;
                await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
            }
            else
            {
                await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
            }
        }

        // Só as entradas válidas geraram requisição (autenticada) ao cofre, e nenhuma URL saiu do caminho /secrets/<nome>
        var authorized = vault.Requests.Where(r => r.Authorized).ToList();
        await Assert.That(authorized.Count).IsEqualTo(expectedRequests);
        await Assert.That(authorized.All(r => r.Uri.Host == "kv-teste.vault.azure.net" && r.Uri.AbsolutePath.StartsWith("/secrets/", StringComparison.Ordinal)
            && r.Uri.AbsolutePath.Count(c => c == '/') <= 3 && !r.Uri.AbsolutePath.Contains("..", StringComparison.Ordinal))).IsTrue();
    }

    [Test]
    public async Task Hostile_tags_content_types_and_values_become_Result_without_log_leak()
    {
        var random = new Random(Fuzz.Seed + 1);
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var store = new TEC.Vault.InMemory.InMemorySecretStore(Memory.Options(), factory.CreateLogger<TEC.Vault.InMemory.InMemorySecretStore>());

        for (int i = 0; i < Fuzz.Iterations; i++)
        {
            var tags = new Dictionary<string, string>(StringComparer.Ordinal);
            for (int t = random.Next(0, 20); t > 0; t--)
                tags.TryAdd(Fuzz.Text(random, 5), Fuzz.Text(random, 5));
            var options = new SecretWriteOptions { ContentType = random.Next(2) == 0 ? Fuzz.Text(random, 10) : null, Tags = tags };
            string value = Canary + Fuzz.Text(random, 10);

            var result = await store.SetSecretAsync($"segredo-{i % 50}", value, options);

            if (result.IsFailure)
                await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
            await Assert.That(result.Error?.Message ?? string.Empty).DoesNotContain(Canary);
        }

        await Assert.That(logs.AllText).DoesNotContain(Canary);
    }

    [Test]
    public async Task Corrupted_vault_responses_become_Result_without_exception_or_body_leak()
    {
        // O cofre (ou algo no caminho) devolve qualquer coisa: status inesperado, JSON truncado, tipos trocados, aninhamento
        // profundo, campos gigantes. O provedor nunca lança e nunca registra o corpo da resposta
        var random = new Random(Fuzz.Seed + 2);
        string[] bodies =
        [
            "", "{", "null", "[]", "\"texto\"", "{\"value\":", $"{{\"value\":\"{Canary}\"}}",
            $"{{\"value\":\"{Canary}\",\"id\":\"não é uma uri\"}}",
            $"{{\"value\":123,\"id\":\"https://kv-teste.vault.azure.net/secrets/x/{FakeKeyVault.Version}\"}}",
            $"{{\"value\":\"{Canary}\",\"id\":\"https://outro-cofre.vault.azure.net/secrets/x/{FakeKeyVault.Version}\",\"attributes\":{{\"created\":\"ontem\"}}}}",
            // error.code e innererror.code vão para o log por projeto (identificadores do serviço, validados por SafeCode); a
            // mensagem, que pode ecoar a entrada, nunca
            $"{{\"error\":{{\"code\":\"Forbidden\",\"message\":\"{Canary}\",\"innererror\":{{\"code\":\"ForbiddenByPolicy\",\"message\":\"{Canary}\"}}}}}}",
            $"{{\"error\":{{\"code\":\"código com espaço {Canary}\",\"message\":\"x\",\"innererror\":{{\"code\":\"{new string('A', 200)}{Canary}\"}}}}}}",
            $"{{\"value\":[{{\"id\":\"{Canary}\"}}],\"nextLink\":\"{Canary}\"}}",
            new string('[', 5_000) + new string(']', 5_000),
            $"{{\"value\":\"{new string('x', 1_000_000)}{Canary}\"}}",
            (char)0xFEFF + "{\"value\":\"x\"}", "<html>" + Canary + "</html>"
        ];
        HttpStatusCode[] statuses =
        [
            HttpStatusCode.OK, HttpStatusCode.Created, HttpStatusCode.NoContent, HttpStatusCode.MovedPermanently, HttpStatusCode.BadRequest,
            HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden, HttpStatusCode.NotFound, HttpStatusCode.Conflict, (HttpStatusCode)418,
            HttpStatusCode.TooManyRequests, HttpStatusCode.InternalServerError, HttpStatusCode.BadGateway, (HttpStatusCode)599
        ];

        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var vault = new FakeKeyVault((_, _) => (statuses[random.Next(statuses.Length)], bodies[random.Next(bodies.Length)]));
        var secrets = new AzureKeyVaultSecretStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultSecretStore>());
        var keys = new AzureKeyVaultKeyStore(vault.CreateClients(), factory.CreateLogger<AzureKeyVaultKeyStore>());

        int iterations = Math.Min(Fuzz.Iterations, 600);
        for (int i = 0; i < iterations; i++)
        {
            Result result;
            try
            {
                result = (i % 5) switch
                {
                    0 => await secrets.GetSecretAsync("x"),
                    1 => await secrets.ListSecretsAsync(),
                    2 => await secrets.SetSecretAsync("x", "v"),
                    3 => await keys.GetKeyAsync("k"),
                    _ => await keys.DecryptAsync("k", FakeKeyVault.Version, new byte[256])
                };
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Exceção com a semente {Fuzz.Seed + 2}, iteração {i}: {ex.GetType().Name}", ex);
            }

            if (result.IsFailure)
                await Assert.That(KnownCodes).Contains(result.Error!.Code);
            await Assert.That(result.Error?.Message ?? string.Empty).DoesNotContain(Canary);
        }

        await Assert.That(logs.AllText).DoesNotContain(Canary);
    }

    [Test]
    public async Task Tampered_backups_are_rejected_without_exception()
    {
        var random = new Random(Fuzz.Seed + 3);
        var secrets = Memory.Secrets();
        var keys = await Memory.KeysWithKekAsync();
        await secrets.SetSecretAsync("origem", Canary);
        byte[] secretBackup = (await secrets.BackupSecretAsync("origem")).Value;
        byte[] keyBackup = (await keys.BackupKeyAsync("kek")).Value;
        await secrets.DeleteSecretAsync("origem");
        await secrets.PurgeDeletedSecretAsync("origem");

        int iterations = Math.Min(Fuzz.Iterations, 500);
        for (int i = 0; i < iterations; i++)
        {
            byte[] tampered = Fuzz.Bytes(random, i % 2 == 0 ? secretBackup : keyBackup);
            if (tampered.AsSpan().SequenceEqual(secretBackup) || tampered.AsSpan().SequenceEqual(keyBackup))
                continue;

            Result result = i % 2 == 0 ? await secrets.RestoreSecretBackupAsync(tampered) : await keys.RestoreKeyBackupAsync(tampered);

            await Assert.That(result.IsFailure).IsTrue();
            await Assert.That(KnownCodes).Contains(result.Error!.Code);
        }

        // Nenhum backup adulterado recriou o segredo
        await Assert.That((await secrets.GetSecretAsync("origem")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task Tampered_pfx_and_pem_certificates_are_rejected_without_exception()
    {
        var random = new Random(Fuzz.Seed + 4);
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=fuzz", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        byte[] pfx = certificate.Export(X509ContentType.Pkcs12, "senha");
        byte[] pem = Encoding.ASCII.GetBytes(certificate.ExportCertificatePem() + "\n" + rsa.ExportPkcs8PrivateKeyPem());
        var store = Memory.Certificates();

        int iterations = Math.Min(Fuzz.Iterations, 300);
        int accepted = 0;
        for (int i = 0; i < iterations; i++)
        {
            bool usePfx = i % 2 == 0;
            byte[] tampered = Fuzz.Bytes(random, usePfx ? pfx : pem, maxLength: 8192);
            var result = await store.ImportCertificateAsync($"fuzz-{i}", tampered, new ImportCertificateOptions { Password = usePfx ? "senha" : null });

            if (result.IsSuccess)
            {
                // Mutação que o parse tolera (ex.: byte fora dos blocos PEM, bit na assinatura do certificado autoassinado): a
                // garantia da importação é a chave privada casar com o certificado, então a chave pública tem de ser a original
                accepted++;
                using var imported = TEC.Vault.Providers.VaultCertificateLoader.LoadCertificate(result.Value.Cer);
                await Assert.That(imported.PublicKey.ExportSubjectPublicKeyInfo()).IsEquivalentTo(rsa.ExportSubjectPublicKeyInfo());
                continue;
            }

            await Assert.That(KnownCodes).Contains(result.Error!.Code);
        }

        await Assert.That(accepted).IsLessThan(iterations / 4);
    }

    [Test]
    public async Task Tampered_envelope_never_decrypts_to_other_content()
    {
        var random = new Random(Fuzz.Seed + 5);
        var keys = await Memory.KeysWithKekAsync();
        byte[] plaintext = Encoding.UTF8.GetBytes(Canary);
        byte[] context = "cliente-42"u8.ToArray();
        var envelope = (await keys.EncryptEnvelopeAsync("kek", plaintext, context)).Value;

        int iterations = Math.Min(Fuzz.Iterations, 300);
        for (int i = 0; i < iterations; i++)
        {
            var tampered = (i % 4) switch
            {
                0 => envelope with { Ciphertext = Fuzz.Bytes(random, envelope.Ciphertext) },
                1 => envelope with { WrappedKey = Fuzz.Bytes(random, envelope.WrappedKey) },
                2 => envelope with { KeyVersion = Fuzz.Text(random, 4) },
                _ => envelope
            };
            byte[] tamperedContext = i % 4 == 3 ? Fuzz.Bytes(random, context, 64) : context;
            if (ReferenceEquals(tampered, envelope) && tamperedContext.AsSpan().SequenceEqual(context))
                continue;

            var result = await keys.DecryptEnvelopeAsync(tampered, tamperedContext);

            // Ou falha, ou (mutação nula, ex.: versão reescrita igual) devolve exatamente o original: nunca outro conteúdo
            if (result.IsSuccess)
                await Assert.That(result.Value).IsEquivalentTo(plaintext);
            else
                await Assert.That(KnownCodes).Contains(result.Error!.Code);
        }
    }
}
