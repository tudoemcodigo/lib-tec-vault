using System.Collections;
using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using TEC.Vault.Abstractions;
using TEC.Vault.Caching;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.DependencyInjection;
using TEC.Vault.InMemory;
using TEC.Vault.Providers.Http;
using TEC.Vault.Secrets;
using TEC.Vault.Synced;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests;

/// <summary>
/// Correções da auditoria no núcleo e no Synced: tempo limite na leitura do corpo e no login, teto da leitura compartilhada do
/// cache, chave do cache conforme o provedor, prefixo obrigatório na fonte de IConfiguration, invalidação do arquivo de segredos,
/// leitura direta na pasta e listagem acima do limite.
/// </summary>
public class ProviderHardeningTests : TempFolderTest
{
    // ---------- VaultHttpClient ----------

    [Test]
    public async Task Http_client_body_read_has_its_own_timeout()
    {
        var settings = new VaultHttpSettings { Handler = new StallingBodyHandler(), MaxRetries = 0, NetworkTimeout = TimeSpan.FromMilliseconds(300) };
        using var client = new VaultHttpClient(new Uri("https://cofre.teste/"), settings);
        using var response = await client.SendAsync(() => new HttpRequestMessage(HttpMethod.Get, "segredo"), idempotent: true, CancellationToken.None);

        var started = TimeProvider.System.GetTimestamp();
        await Assert.That(async () => { await client.ReadBytesAsync(response, CancellationToken.None); }).Throws<TimeoutException>();
        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));
    }

    [Test]
    public async Task Http_client_error_status_mapper_retries_mapped_429_and_keeps_the_body()
    {
        var handler = new SequenceHandler(
            (HttpStatusCode.BadRequest, """{"__type":"ThrottlingException"}"""),
            (HttpStatusCode.BadRequest, """{"__type":"OutroErro"}"""));
        var settings = new VaultHttpSettings { Handler = handler, MaxRetries = 1, MaxRetryDelay = TimeSpan.FromSeconds(5) };
        using var client = new VaultHttpClient(new Uri("https://cofre.teste/"), settings)
        {
            ErrorStatusMapper = (status, body) => Encoding.UTF8.GetString(body.Span).Contains("Throttling", StringComparison.Ordinal)
                ? HttpStatusCode.TooManyRequests
                : status
        };

        using var response = await client.SendAsync(() => new HttpRequestMessage(HttpMethod.Get, "x"), idempotent: true, CancellationToken.None);
        var body = Encoding.UTF8.GetString(await client.ReadBytesAsync(response, CancellationToken.None));

        await Assert.That(handler.Calls).IsEqualTo(2);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadRequest);
        await Assert.That(body).Contains("OutroErro");
    }

    // ---------- VaultTokenSource ----------

    [Test]
    public async Task Login_that_never_finishes_times_out_and_waits_the_cooldown()
    {
        var logins = 0;
        using var tokens = new VaultTokenSource(_ =>
        {
            Interlocked.Increment(ref logins);
            return new TaskCompletionSource<VaultToken>().Task;   // ignora o cancelamento e nunca termina
        }, loginTimeout: TimeSpan.FromSeconds(1));

        var started = TimeProvider.System.GetTimestamp();
        await Assert.That(async () => { await tokens.GetAsync(CancellationToken.None); }).Throws<TimeoutException>();
        await Assert.That(async () => { await tokens.GetAsync(CancellationToken.None); }).Throws<TimeoutException>();

        // Antes: o login pendente ficava compartilhado para sempre e toda chamada seguinte esperava por ele
        await Assert.That(TimeProvider.System.GetElapsedTime(started)).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That(logins).IsEqualTo(1);
    }

    [Test]
    [Arguments(0)]
    [Arguments(3600)]
    public async Task Login_timeout_out_of_range_is_rejected(int seconds) =>
        await Assert.That(() => new VaultTokenSource(_ => Task.FromResult(new VaultToken("t", null)), loginTimeout: TimeSpan.FromSeconds(seconds)))
            .Throws<ArgumentOutOfRangeException>();

    // ---------- Cache ----------

    [Test]
    public async Task Cache_shared_read_has_a_ceiling_and_the_next_read_tries_again()
    {
        var inner = new NeverEndingReader();
        using var cache = new CachingSecretReader(inner, TimeSpan.FromMinutes(1), fetchTimeout: TimeSpan.FromMilliseconds(200));

        var first = await cache.GetSecretAsync("db");
        var second = await cache.GetSecretAsync("db");

        // Antes: a leitura compartilhada usava CancellationToken.None, sem teto: quem chegasse depois esperava para sempre
        await Assert.That(first.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(second.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
        await Assert.That(inner.Calls).IsEqualTo(2);
    }

    [Test]
    public async Task Cache_key_ignores_case_only_when_the_provider_does()
    {
        var memory = new InMemorySecretStore(new InMemoryVaultOptions { AllowOutsideDevelopment = true });
        await memory.SetSecretAsync("Db", "valor");
        using var insensitive = new CachingSecretReader(memory, TimeSpan.FromMinutes(1));
        var counting = new ScriptedSecretStore(memory);   // não deriva de VaultProviderBase: diferencia maiúsculas por segurança
        using var sensitive = new CachingSecretReader(counting, TimeSpan.FromMinutes(1));

        foreach (var name in new[] { "Db", "DB", "db" })
        {
            await insensitive.GetSecretAsync(name);
            await sensitive.GetSecretAsync(name);
        }

        await Assert.That(insensitive.Count).IsEqualTo(1);
        await Assert.That(sensitive.Count).IsEqualTo(3);
        await Assert.That(counting.GetCalls).IsEqualTo(3);
    }

    [Test]
    public async Task Providers_declare_how_they_compare_names()
    {
        var directory = new DirectorySecretStore(new DirectorySecretsOptions { Path = Folder });
        var environment = new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "APP_" }, () => new Hashtable());

        await Assert.That(new InMemorySecretStore(new InMemoryVaultOptions { AllowOutsideDevelopment = true }).NameComparer)
            .IsEqualTo(StringComparer.OrdinalIgnoreCase);
        await Assert.That(environment.NameComparer).IsEqualTo(StringComparer.OrdinalIgnoreCase);
        await Assert.That(directory.NameComparer).IsEqualTo(StringComparer.Ordinal);
    }

    // ---------- Prefixo obrigatório na fonte de IConfiguration ----------

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments("   ")]
    public async Task Configuration_source_requires_a_prefix(string? prefix)
    {
        var store = Memory.Secrets();
        await store.SetSecretAsync("Logging--LogLevel--Default", "None");

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecVault(store, o => o.Prefix = prefix).Build())
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Prefix");
    }

    [Test]
    public async Task Configuration_source_by_selection_requires_a_prefix_and_disposes_the_store()
    {
        var disposed = 0;
        var registration = new VaultProviderRegistration("Descartavel", VaultStores.Secrets, (_, _, _) => { },
            (_, _) => new DisposableReader(() => Interlocked.Increment(ref disposed)));
        var section = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Vault:Provider"] = "Descartavel" })
            .Build().GetSection("Vault");

        var exception = await Assert.That(() => new ConfigurationBuilder().AddTecVault(section, p => p.Add(registration)))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:Configuration:Prefix");
        await Assert.That(disposed).IsEqualTo(1);
    }

    // ---------- Synced ----------

    [Test]
    public async Task Secrets_file_rewritten_with_same_size_and_timestamp_is_read_again()
    {
        var path = Write("segredos.json", """{"Senha":"aaaa"}""");
        var store = new FileSecretStore(new SecretsFileOptions { Path = path });
        await Assert.That((await store.GetSecretAsync("Senha")).Value.Value).IsEqualTo("aaaa");
        var timestamp = File.GetLastWriteTimeUtc(path);

        File.WriteAllText(path, """{"Senha":"bbbb"}""");   // mesmo tamanho
        File.SetLastWriteTimeUtc(path, timestamp);         // e mesma data (ex.: cp -p, troca no mesmo instante)

        // Antes: tamanho e data iguais deixavam o valor antigo em uso
        await Assert.That((await store.GetSecretAsync("Senha")).Value.Value).IsEqualTo("bbbb");
    }

    [Test]
    public async Task Directory_reads_an_exact_name_without_listing_the_folder()
    {
        Write("a", "valor-a");
        Write("b", "valor-b");
        var store = new DirectorySecretStore(new DirectorySecretsOptions { Path = Folder, MaxItems = 1 });

        // Com MaxItems = 1, qualquer listagem da pasta falha: a leitura do nome exato não lista
        await Assert.That((await store.GetSecretAsync("a")).Value.Value).IsEqualTo("valor-a");
        await Assert.That((await store.ListSecretsAsync()).Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
    }

    [Test]
    public async Task Directory_follows_relative_links_inside_the_folder_and_ignores_the_ones_that_leave_it()
    {
        Write("..2026_10_29_x/db-senha", "segredo\n");
        var outside = Path.Combine(Path.GetDirectoryName(Folder)!, "fora-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(outside, "nao-pode-vazar");
        try
        {
            // Formato do Kubernetes com destinos relativos: db-senha -> ..data/db-senha ; ..data -> ..2026_10_29_x
            if (!TryLink(Path.Combine(Folder, "..data"), "..2026_10_29_x", directory: true) ||
                !TryLink(Path.Combine(Folder, "db-senha"), Path.Combine("..data", "db-senha")) ||
                !TryLink(Path.Combine(Folder, "vazamento"), Path.Combine("..", Path.GetFileName(outside))))
                Skip.Test("Sem permissão para criar links simbólicos nesta máquina.");

            var store = new DirectorySecretStore(new DirectorySecretsOptions { Path = Folder });

            await Assert.That((await store.GetSecretAsync("db-senha")).Value.Value).IsEqualTo("segredo");
            await Assert.That((await store.GetSecretAsync("vazamento")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
            await Assert.That((await store.ListSecretsAsync()).Value.Select(p => p.Name)).IsEquivalentTo(["db-senha"]);
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Test]
    public async Task Environment_and_file_above_MaxItems_fail_with_TooManyItems()
    {
        var variables = new Hashtable { ["APP_A"] = "1", ["APP_B"] = "2", ["APP_C"] = "3" };
        var environment = new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "APP_", MaxItems = 2 }, () => variables);
        var file = new FileSecretStore(new SecretsFileOptions { Path = Write("muitos.env", "A=1\nB=2\nC=3\n"), MaxItems = 2 });

        // Antes: VAULT_FALHA (erro de formato), como se o arquivo estivesse corrompido
        await Assert.That((await environment.ListSecretsAsync()).Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
        await Assert.That((await file.ListSecretsAsync()).Error!.Code).IsEqualTo(VaultErrors.TooManyItemsCode);
    }

    private static bool TryLink(string link, string target, bool directory = false)
    {
        try
        {
            if (directory)
                Directory.CreateSymbolicLink(link, target);
            else
                File.CreateSymbolicLink(link, target);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;   // Windows sem modo desenvolvedor não cria links simbólicos
        }
    }

    // ---------- Dublês ----------

    /// <summary>Responde, em ordem, os status e corpos informados (o último se repete).</summary>
    private sealed class SequenceHandler(params (HttpStatusCode Status, string Body)[] responses) : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var index = Math.Min(Interlocked.Increment(ref Calls), responses.Length) - 1;
            var (status, body) = responses[index];
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    /// <summary>Leitor que nunca responde e ignora o cancelamento.</summary>
    private sealed class NeverEndingReader : ISecretReader
    {
        public int Calls;

        public string ProviderName => "Travado";

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Calls);
            return new TaskCompletionSource<Result<VaultSecret>>().Task;
        }

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => Task.FromResult<Result<bool>>(false);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(Array.Empty<SecretProperties>());

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(VaultErrors.NotFound());
    }

    /// <summary>Leitor descartável criado pela fonte de configuração (conta o descarte).</summary>
    private sealed class DisposableReader(Action onDispose) : ISecretReader, IDisposable
    {
        public string ProviderName => "Descartavel";

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<VaultSecret>>(VaultErrors.NotFound());

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => Task.FromResult<Result<bool>>(false);

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(Array.Empty<SecretProperties>());

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(VaultErrors.NotFound());

        public void Dispose() => onDispose();
    }
}
