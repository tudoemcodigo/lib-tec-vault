using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Configuration;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.Caching;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Vault.Tests.Fakes;

namespace TEC.Vault.Tests;

/// <summary>
/// Abuso de recursos (DoS): conteúdo gigante recusado antes da rede e sem processamento caro, cancelamentos em massa que não
/// multiplicam chamadas ao cofre, cofre inflado que não é lido inteiro e paginação sem fim interrompida pelo cancelamento.
/// </summary>
public class ResourceAbuseTests
{
    [Test]
    public async Task Huge_content_is_rejected_fast_without_calling_vault()
    {
        var vault = new FakeKeyVault((_, _) => (HttpStatusCode.OK, "{}"));
        var secrets = new AzureKeyVaultSecretStore(vault.CreateClients());
        var keys = new AzureKeyVaultKeyStore(vault.CreateClients());
        var certificates = new AzureKeyVaultCertificateStore(vault.CreateClients());
        byte[] huge = new byte[50 * 1024 * 1024];
        string hugeText = new('x', 30 * 1024 * 1024);
        var manyTags = Enumerable.Range(0, 100_000).ToDictionary(i => $"t{i}", i => "v");
        var started = Stopwatch.GetTimestamp();

        var results = new[]
        {
            (await secrets.SetSecretAsync("s", hugeText)).Error,
            (await secrets.SetSecretAsync("s", "v", new() { Tags = manyTags })).Error,
            (await secrets.SetSecretAsync("s", "v", new() { ContentType = hugeText })).Error,
            (await secrets.RestoreSecretBackupAsync(huge)).Error,
            (await keys.RestoreKeyBackupAsync(huge)).Error,
            (await certificates.RestoreCertificateBackupAsync(huge)).Error,
            (await certificates.ImportCertificateAsync("c", huge)).Error,
            (await keys.DecryptAsync("k", FakeKeyVault.Version, huge)).Error,
            (await keys.UnwrapKeyAsync("k", FakeKeyVault.Version, huge)).Error,
            (await keys.EncryptAsync("k", huge, version: FakeKeyVault.Version)).Error,
            (await keys.VerifyDataAsync("k", FakeKeyVault.Version, [1], huge, VaultSignatureAlgorithm.RS256)).Error
        };
        var elapsed = Stopwatch.GetElapsedTime(started);

        await Assert.That(results.All(e => e?.Code == VaultErrors.InvalidInputCode)).IsTrue();
        await Assert.That(vault.Requests.Any(r => r.Authorized)).IsFalse();
        // Recusa por tamanho: sem parse de PFX, sem cópia do conteúdo, sem regex sobre 30 MB
        await Assert.That(elapsed).IsLessThan(TimeSpan.FromSeconds(2));
    }

    [Test]
    public async Task Huge_certificate_is_rejected_before_parsing()
    {
        var store = Memory.Certificates();
        // PEM com 2 MB de blocos repetidos: passaria pelo detector de formato, mas o limite de 1 MB vem antes de qualquer parse
        byte[] pem = System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", (2 * VaultCertificateRules.MaxCertificateBytes) / 54)));
        var started = Stopwatch.GetTimestamp();

        var result = await store.ImportCertificateAsync("pem-gigante", pem);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(Stopwatch.GetElapsedTime(started)).IsLessThan(TimeSpan.FromMilliseconds(500));
    }

    [Test]
    public async Task Mass_cancellations_do_not_multiply_vault_calls()
    {
        // 500 leitores do mesmo segredo, cofre lento (500 ms), todos cancelados em 50 ms: cada um é liberado na hora, a leitura
        // compartilhada continua sozinha (uma única chamada) e o resultado dela fica no cache para quem vier depois
        var inner = new ScriptedSecretStore(Memory.Secrets());
        await inner.SetSecretAsync("quente", "v");
        var slow = new TaskCompletionSource();
        inner.AfterGet = (_, _) => slow.Task;
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(5));

        var started = Stopwatch.GetTimestamp();
        var readers = Enumerable.Range(0, 500).Select(async _ =>
        {
            using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
            try
            {
                await cache.GetSecretAsync("quente", cancellationToken: cancellation.Token);
                return false;
            }
            catch (OperationCanceledException)
            {
                return true;
            }
        }).ToArray();
        bool[] canceled = await Task.WhenAll(readers);
        var releasedIn = Stopwatch.GetElapsedTime(started);

        slow.SetResult();
        await Task.Delay(50);   // a leitura compartilhada termina e grava no cache
        var after = await cache.GetSecretAsync("quente");

        await Assert.That(canceled.All(c => c)).IsTrue();
        await Assert.That(releasedIn).IsLessThan(TimeSpan.FromSeconds(5));
        await Assert.That(after.Value.Value).IsEqualTo("v");
        await Assert.That(inner.GetCalls).IsEqualTo(1);
    }

    [Test]
    public async Task Configuration_with_inflated_vault_fails_closed_without_reading_values()
    {
        // Prefixo errado ou cofre compartilhado com milhares de segredos: a carga recusa já na listagem, sem 1.000 leituras
        var inner = new ScriptedSecretStore(Memory.Secrets());
        for (int i = 0; i < 1_000; i++)
            await inner.SetSecretAsync($"App--Chave{i}", "v");

        await Assert.That(() => new ConfigurationBuilder().AddTecVault(inner, o => { o.Prefix = "App--"; o.MaxSecrets = 100; }).Build())
            .Throws<InvalidOperationException>();
        await Assert.That(inner.GetCalls).IsEqualTo(0);
    }

    [Test]
    public async Task Endless_vault_paging_is_stopped_by_cancellation_and_timeout()
    {
        // Resposta adulterada ou defeituosa: toda página aponta para mais uma. A listagem não pode ignorar o cancelamento,
        // e a carga do IConfiguration é limitada por LoadTimeout
        var vault = new FakeKeyVault((request, _) => (HttpStatusCode.OK,
            $$$"""{"value":[{"id":"{{{FakeKeyVault.VaultUri}}}secrets/App--x{{{Random.Shared.Next()}}}","attributes":{"enabled":true}}],"nextLink":"{{{FakeKeyVault.VaultUri}}}secrets?api-version=7.6&pagina={{{Random.Shared.Next()}}}"}"""));
        // Limite de itens alto: aqui o que se testa é o cancelamento e o LoadTimeout (o limite tem asserção própria no fim)
        var store = new AzureKeyVaultSecretStore(vault.CreateClients(configure: o => o.MaxListItems = 1_000_000));

        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        var started = Stopwatch.GetTimestamp();
        await Assert.That(async () => { await store.ListSecretsAsync(cancellation.Token); }).Throws<OperationCanceledException>();
        await Assert.That(Stopwatch.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));

        started = Stopwatch.GetTimestamp();
        await Assert.That(() => new ConfigurationBuilder()
                .AddTecVault(store, o => { o.Prefix = "App--"; o.LoadTimeout = TimeSpan.FromSeconds(1); o.MaxSecrets = 1_000_000; })
                .Build())
            .Throws<InvalidOperationException>();
        await Assert.That(Stopwatch.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(15));

        // Com MaxListItems (padrão 10.000; 50 aqui para ser rápido) a paginação sem fim para sozinha, sem depender de cancelamento
        var limited = new AzureKeyVaultSecretStore(vault.CreateClients(configure: o => o.MaxListItems = 50));
        await Assert.That((await limited.ListSecretsAsync()).Error!.Code).IsEqualTo(TEC.Vault.Common.VaultErrors.TooManyItemsCode);
    }
}
