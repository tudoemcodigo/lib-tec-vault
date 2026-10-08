using System.Collections;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Configuration;
using TEC.Vault.DependencyInjection;
using TEC.Vault.InMemory;
using TEC.Vault.Synced;
using TEC.Vault.Tests.Contracts;

namespace TEC.Vault.Tests;

/// <summary>Pasta temporária por teste (removida no fim).</summary>
public abstract class TempFolderTest : IDisposable
{
    protected TempFolderTest()
    {
        Folder = Path.Combine(Path.GetTempPath(), "tec-vault-testes", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Folder);
    }

    protected string Folder { get; }

    protected string Write(string relativePath, string content)
    {
        var path = Path.Combine(Folder, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, content, new UTF8Encoding(false));
        return path;
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Folder, recursive: true);
        }
        catch (IOException)
        {
        }

        GC.SuppressFinalize(this);
    }
}

// ---------- Contrato de leitura nos três formatos e no provedor em memória ----------

[InheritsTests]
public class InMemorySecretStoreContractTests : SecretStoreContract
{
    protected override Task<ISecretStore> CreateStoreAsync() =>
        Task.FromResult<ISecretStore>(new InMemorySecretStore(new InMemoryVaultOptions { AllowOutsideDevelopment = true }));
}

[InheritsTests]
public class DirectorySecretStoreContractTests : SecretReaderContract, IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "tec-vault-testes", Guid.NewGuid().ToString("N"));

    protected override Task<ISecretReader> CreateReaderAsync(IReadOnlyDictionary<string, string> secrets)
    {
        Directory.CreateDirectory(_folder);
        foreach (var (name, value) in secrets)
            File.WriteAllText(Path.Combine(_folder, name), value + "\n");
        return Task.FromResult<ISecretReader>(new DirectorySecretStore(new DirectorySecretsOptions { Path = _folder }));
    }

    protected override Task<bool> ChangeValueAsync(ISecretReader reader, string name, string value)
    {
        File.WriteAllText(Path.Combine(_folder, name), value);
        return Task.FromResult(true);
    }

    public void Dispose()
    {
        if (Directory.Exists(_folder))
            Directory.Delete(_folder, recursive: true);
        GC.SuppressFinalize(this);
    }
}

[InheritsTests]
public class EnvironmentSecretStoreContractTests : SecretReaderContract
{
    private readonly Hashtable _variables = new(StringComparer.Ordinal);

    protected override Task<ISecretReader> CreateReaderAsync(IReadOnlyDictionary<string, string> secrets)
    {
        _variables["PATH"] = "/usr/bin";
        _variables["OUTRO_db-senha"] = "nao-deve-aparecer";
        foreach (var (name, value) in secrets)
            _variables["TECVAULT_" + name.Replace("--", "__", StringComparison.Ordinal)] = value;
        return Task.FromResult<ISecretReader>(new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "TECVAULT_" }, () => _variables));
    }

    protected override Task<bool> ChangeValueAsync(ISecretReader reader, string name, string value)
    {
        _variables["TECVAULT_" + name] = value;
        return Task.FromResult(true);
    }
}

[InheritsTests]
public class JsonFileSecretStoreContractTests : SecretReaderContract, IDisposable
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), "tec-vault-testes", Guid.NewGuid().ToString("N") + ".json");

    private void Save(IReadOnlyDictionary<string, string> secrets)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        var json = System.Text.Json.JsonSerializer.Serialize(secrets.ToDictionary(), SyncedTestJson.Default.DictionaryStringString);
        File.WriteAllText(_file, json);
    }

    protected override Task<ISecretReader> CreateReaderAsync(IReadOnlyDictionary<string, string> secrets)
    {
        Save(secrets);
        return Task.FromResult<ISecretReader>(new FileSecretStore(new SecretsFileOptions { Path = _file }));
    }

    protected override Task<bool> ChangeValueAsync(ISecretReader reader, string name, string value)
    {
        var secrets = Seed.ToDictionary(StringComparer.OrdinalIgnoreCase);
        secrets[name] = value + " ";   // tamanho diferente: a releitura não depende da resolução do relógio do sistema de arquivos
        Save(secrets);
        secrets[name] = value;
        Save(secrets);
        File.SetLastWriteTimeUtc(_file, DateTime.UtcNow.AddSeconds(5));
        return Task.FromResult(true);
    }

    public void Dispose()
    {
        File.Delete(_file);
        GC.SuppressFinalize(this);
    }
}

[InheritsTests]
public class DotEnvFileSecretStoreContractTests : SecretReaderContract, IDisposable
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), "tec-vault-testes", Guid.NewGuid().ToString("N") + ".env");

    protected override Task<ISecretReader> CreateReaderAsync(IReadOnlyDictionary<string, string> secrets)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_file)!);
        File.WriteAllLines(_file, secrets.Select(kv => $"{kv.Key.Replace("--", "__", StringComparison.Ordinal)}=\"{kv.Value}\""));
        return Task.FromResult<ISecretReader>(new FileSecretStore(new SecretsFileOptions { Path = _file }));
    }

    public void Dispose()
    {
        File.Delete(_file);
        GC.SuppressFinalize(this);
    }
}

[System.Text.Json.Serialization.JsonSerializable(typeof(Dictionary<string, string>))]
internal sealed partial class SyncedTestJson : System.Text.Json.Serialization.JsonSerializerContext;

// ---------- Comportamento específico ----------

/// <summary>Provedor Directory: formato do Kubernetes, links simbólicos e limites.</summary>
public class DirectorySecretStoreTests : TempFolderTest
{
    private DirectorySecretStore Store(Action<DirectorySecretsOptions>? configure = null)
    {
        var options = new DirectorySecretsOptions { Path = Folder };
        configure?.Invoke(options);
        return new DirectorySecretStore(options);
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

    [Test]
    public async Task Kubernetes_volume_layout_is_read()
    {
        // /mnt/secrets/db-senha -> ..data/db-senha ; ..data -> ..2026_10_07_x
        Write("..2026_10_07_x/db-senha", "segredo\n");
        if (!TryLink(Path.Combine(Folder, "..data"), Path.Combine(Folder, "..2026_10_07_x"), directory: true) ||
            !TryLink(Path.Combine(Folder, "db-senha"), Path.Combine(Folder, "..data", "db-senha")))
            Skip.Test("Sem permissão para criar links simbólicos nesta máquina.");

        var store = Store();

        await Assert.That((await store.GetSecretAsync("db-senha")).Value.Value).IsEqualTo("segredo");
        await Assert.That((await store.ListSecretsAsync()).Value.Select(p => p.Name)).IsEquivalentTo(["db-senha"]);
    }

    [Test]
    public async Task Symbolic_link_outside_folder_is_ignored()
    {
        var outside = Path.Combine(Path.GetTempPath(), "tec-vault-testes", "fora-" + Guid.NewGuid().ToString("N"));
        File.WriteAllText(outside, "nao-pode-vazar");
        try
        {
            if (!TryLink(Path.Combine(Folder, "vazamento"), outside))
                Skip.Test("Sem permissão para criar links simbólicos nesta máquina.");

            var store = Store();

            await Assert.That((await store.GetSecretAsync("vazamento")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
            await Assert.That((await store.ListSecretsAsync()).Value).IsEmpty();
        }
        finally
        {
            File.Delete(outside);
        }
    }

    [Test]
    public async Task Hidden_files_subfolders_and_invalid_names_are_ignored()
    {
        Write(".oculto", "x");
        Write("sub/dentro", "x");
        Write("com espaco", "x");
        Write("valido", "ok");

        var list = await Store().ListSecretsAsync();

        await Assert.That(list.Value.Select(p => p.Name)).IsEquivalentTo(["valido"]);
    }

    [Test]
    public async Task Requested_name_never_becomes_path()
    {
        Write("sub/alvo", "x");

        var result = await Store().GetSecretAsync("sub/alvo");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
    }

    [Test]
    public async Task File_above_limit_fails_without_truncating()
    {
        Write("grande", new string('x', 200));

        var result = await Store(o => o.MaxFileBytes = 100).GetSecretAsync("grande");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    [Test]
    public async Task Listing_above_MaxItems_fails()
    {
        for (var i = 0; i < 3; i++)
            Write("s" + i, "x");

        var result = await Store(o => o.MaxItems = 2).ListSecretsAsync();

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    [Test]
    public async Task Non_utf8_content_fails()
    {
        File.WriteAllBytes(Path.Combine(Folder, "binario"), [0xC3, 0x28]);

        var result = await Store().GetSecretAsync("binario");

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    [Test]
    public async Task Trailing_newline_is_kept_only_if_requested()
    {
        Write("linha", "valor\r\n");

        await Assert.That((await Store().GetSecretAsync("linha")).Value.Value).IsEqualTo("valor");
        await Assert.That((await Store(o => o.TrimTrailingNewline = false).GetSecretAsync("linha")).Value.Value).IsEqualTo("valor\r\n");
    }

    [Test]
    public async Task Missing_folder_responds_unavailable_in_probe()
    {
        var store = new DirectorySecretStore(new DirectorySecretsOptions { Path = Path.Combine(Folder, "nao-existe") });

        var result = await store.CheckAccessAsync();

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
    }

    [Test]
    public async Task Version_is_not_a_reproducible_hash_of_value()
    {
        Write("senha", "123456");

        var first = (await Store().GetSecretAsync("senha")).Value.Version;
        var second = (await Store().GetSecretAsync("senha")).Value.Version;

        await Assert.That(first).IsNotEqualTo(second);   // chave do HMAC por instância
        await Assert.That(first).IsNotEqualTo(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData("123456"u8))[..32].ToLowerInvariant());
    }

    [Test]
    public async Task Invalid_options_fail_on_creation()
    {
        await Assert.That(() => new DirectorySecretStore(new DirectorySecretsOptions())).Throws<InvalidOperationException>();
        await Assert.That(() => new DirectorySecretStore(new DirectorySecretsOptions { Path = Folder, MaxFileBytes = 0 })).Throws<InvalidOperationException>();
    }
}

/// <summary>Provedor EnvironmentVariables.</summary>
public class EnvironmentSecretStoreTests
{
    [Test]
    public async Task Prefix_is_required()
    {
        await Assert.That(() => new EnvironmentSecretStore(new EnvironmentSecretsOptions())).Throws<InvalidOperationException>();
        await Assert.That(() => new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "A" })).Throws<InvalidOperationException>();
        await Assert.That(() => new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "A-B" })).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Variables_without_prefix_are_not_exposed()
    {
        var variables = new Hashtable { ["PATH"] = "/bin", ["HOME"] = "/root", ["APP_Senha"] = "x" };
        var store = new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "APP_" }, () => variables);

        var list = await store.ListSecretsAsync();

        await Assert.That(list.Value.Select(p => p.Name)).IsEquivalentTo(["Senha"]);
        await Assert.That((await store.GetSecretAsync("PATH")).Error!.Code).IsEqualTo(VaultErrors.NotFoundCode);
    }

    [Test]
    public async Task Double_underscore_becomes_section_separator()
    {
        var variables = new Hashtable { ["APP_ConnectionStrings__Db"] = "Server=x" };
        var store = new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "APP_" }, () => variables);

        await Assert.That((await store.GetSecretAsync("ConnectionStrings--Db")).Value.Value).IsEqualTo("Server=x");
    }

    [Test]
    public async Task Reads_from_real_process_environment()
    {
        var variable = "TECVAULTTESTE_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(variable, "do-processo");
        try
        {
            var store = new EnvironmentSecretStore(new EnvironmentSecretsOptions { Prefix = "TECVAULTTESTE_" });
            var result = await store.GetSecretAsync(variable["TECVAULTTESTE_".Length..]);

            await Assert.That(result.Value.Value).IsEqualTo("do-processo");
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }
}

/// <summary>Provedor SecretsFile: formatos JSON e .env.</summary>
public class FileSecretStoreTests : TempFolderTest
{
    private async Task<IReadOnlyDictionary<string, string>> ReadAll(string fileName, string content, SecretsFileFormat format = SecretsFileFormat.Auto)
    {
        var path = Write(fileName, content);
        var store = new FileSecretStore(new SecretsFileOptions { Path = path, Format = format });
        var result = new Dictionary<string, string>();
        var list = await store.ListSecretsAsync();
        if (!list.IsSuccess)
            throw new InvalidOperationException(list.Error!.Code);
        foreach (var item in list.Value)
            result[item.Name] = (await store.GetSecretAsync(item.Name)).Value.Value;
        return result;
    }

    private async Task<string?> FailureCode(string fileName, string content)
    {
        var path = Write(fileName, content);
        var store = new FileSecretStore(new SecretsFileOptions { Path = path });
        return (await store.ListSecretsAsync()).Error?.Code;
    }

    [Test]
    public async Task Nested_json_becomes_names_with_separator()
    {
        var secrets = await ReadAll("app.json", """{ "Db": { "Senha": "x", "Porta": 1433 }, "Ligado": true, "Api": "k" }""");

        await Assert.That(secrets["Db--Senha"]).IsEqualTo("x");
        await Assert.That(secrets["Db--Porta"]).IsEqualTo("1433");
        await Assert.That(secrets["Ligado"]).IsEqualTo("true");
        await Assert.That(secrets["Api"]).IsEqualTo("k");
    }

    [Test]
    [Arguments("""[1, 2]""")]
    [Arguments("""{ "a": null }""")]
    [Arguments("""{ "a": [1] }""")]
    [Arguments("""{ "a": "x", "A": "y" }""")]
    [Arguments("""{ "com espaco": "x" }""")]
    [Arguments("""{ "a": """)]
    public async Task Malformed_json_fails(string content)
    {
        await Assert.That(await FailureCode("ruim.json", content)).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    [Test]
    public async Task DotEnv_accepts_comments_export_quotes_and_multiple_lines()
    {
        var content = """
            # comentário
            export SIMPLES=valor simples  # comentário no fim
            ASPAS="com \"escape\" e\nquebra"
            LITERAL='$NAO_EXPANDE \n literal'
            VAZIO=
            Db__Senha=abc#nao-e-comentario
            PEM="-----BEGIN-----
            linha2
            -----END-----"
            """;

        var secrets = await ReadAll("app.env", content);

        await Assert.That(secrets["SIMPLES"]).IsEqualTo("valor simples");
        await Assert.That(secrets["ASPAS"]).IsEqualTo("com \"escape\" e\nquebra");
        await Assert.That(secrets["LITERAL"]).IsEqualTo("$NAO_EXPANDE \\n literal");
        await Assert.That(secrets["VAZIO"]).IsEqualTo("");
        await Assert.That(secrets["Db--Senha"]).IsEqualTo("abc#nao-e-comentario");
        await Assert.That(secrets["PEM"]).IsEqualTo("-----BEGIN-----\nlinha2\n-----END-----");
    }

    [Test]
    [Arguments("SEM_IGUAL\n")]
    [Arguments("A=\"sem fechar\n")]
    [Arguments("A='sem fechar\n")]
    [Arguments("A=\"x\" sobra\n")]
    [Arguments("CHAVE INVALIDA=x\n")]
    [Arguments("A=\"\\q\"\n")]
    public async Task Malformed_dotenv_fails(string content)
    {
        await Assert.That(await FailureCode("ruim.env", content)).IsEqualTo(VaultErrors.ProviderFailureCode);
    }

    [Test]
    public async Task Format_error_does_not_put_value_in_message()
    {
        var path = Write("vaza.env", "A=\"segredo-que-nao-pode-vazar\n");
        var logs = new Fakes.CapturingLoggerProvider();
        using var factory = Microsoft.Extensions.Logging.LoggerFactory.Create(b => b.AddProvider(logs));
        var store = new FileSecretStore(new SecretsFileOptions { Path = path }, factory.CreateLogger<FileSecretStore>());

        var result = await store.ListSecretsAsync();

        await Assert.That(result.IsSuccess).IsFalse();
        await Assert.That(result.Error!.Message).DoesNotContain("segredo-que-nao-pode-vazar");
        await Assert.That(logs.AllText).DoesNotContain("segredo-que-nao-pode-vazar");
    }

    [Test]
    public async Task Unknown_extension_requires_format()
    {
        await Assert.That(() => new FileSecretStore(new SecretsFileOptions { Path = Path.Combine(Folder, "segredos.txt") }))
            .Throws<InvalidOperationException>();

        var secrets = await ReadAll("segredos.txt", "A=1", SecretsFileFormat.DotEnv);
        await Assert.That(secrets["A"]).IsEqualTo("1");
    }

    [Test]
    public async Task Missing_file_responds_unavailable()
    {
        var store = new FileSecretStore(new SecretsFileOptions { Path = Path.Combine(Folder, "nao-existe.json") });

        await Assert.That((await store.GetSecretAsync("a")).Error!.Code).IsEqualTo(VaultErrors.UnavailableCode);
    }
}

/// <summary>Seleção por configuração dos provedores sincronizados.</summary>
public class SyncedConfigurationTests : TempFolderTest
{
    [Test]
    public async Task Directory_chosen_by_configuration_with_keys_from_another_provider()
    {
        Write("segredos/db", "valor");
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "InMemory",
            ["Vault:Secrets:Provider"] = "Directory",
            ["Vault:Directory:Path"] = Path.Combine(Folder, "segredos")
        }).Build();

        var services = new ServiceCollection();
        services.AddTecVault(config.GetSection("Vault"), p => p.AddSynced().AddInMemory(o => o.AllowOutsideDevelopment = true));
        using var sp = services.BuildServiceProvider();

        await Assert.That(sp.GetRequiredService<ISecretReader>()).IsTypeOf<DirectorySecretStore>();
        await Assert.That(sp.GetRequiredService<IKeyCryptography>()).IsTypeOf<InMemoryKeyStore>();
        await Assert.That((await sp.GetRequiredService<ISecretReader>().GetSecretAsync("db")).Value.Value).IsEqualTo("valor");
    }

    [Test]
    public async Task Synced_as_default_provider_leaves_keys_and_certificates_without_provider()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "EnvironmentVariables",
            ["Vault:EnvironmentVariables:Prefix"] = "APP_"
        }).Build();

        var services = new ServiceCollection();
        services.AddTecVault(config.GetSection("Vault"), p => p.AddSynced());
        using var sp = services.BuildServiceProvider();

        await Assert.That(sp.GetService<ISecretReader>()).IsTypeOf<EnvironmentSecretStore>();
        await Assert.That(sp.GetService<IKeyReader>()).IsNull();
        await Assert.That(sp.GetService<ISecretStore>()).IsNull();
    }

    [Test]
    public async Task IConfiguration_source_from_env_file()
    {
        var file = Write("app.env", "MinhaApi__ConnectionStrings__Db=Server=x\nOutra__Coisa=y\n");
        var bootstrap = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "SecretsFile",
            ["Vault:SecretsFile:Path"] = file,
            ["Vault:Configuration:Prefix"] = "MinhaApi--"
        }).Build();

        var configuration = new ConfigurationBuilder()
            .AddConfiguration(bootstrap)
            .AddTecVault(bootstrap.GetSection("Vault"), p => p.AddSynced())
            .Build();

        await Assert.That(configuration["ConnectionStrings:Db"]).IsEqualTo("Server=x");
        await Assert.That(configuration["Outra:Coisa"]).IsNull();
    }

    [Test]
    public async Task Unknown_provider_option_is_rejected()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Vault:Provider"] = "Directory",
            ["Vault:Directory:Path"] = Folder,
            ["Vault:Directory:Pth"] = Folder
        }).Build();

        var exception = await Assert.That(() => new ServiceCollection().AddTecVault(config.GetSection("Vault"), p => p.AddSynced()))
            .Throws<InvalidOperationException>();

        await Assert.That(exception!.Message).Contains("Vault:Directory:Pth");
    }
}
