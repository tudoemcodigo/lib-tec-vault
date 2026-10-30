using TEC.Core.Common.Results;
using TEC.Vault.Abstractions;
using TEC.Vault.AwsSecretsManager;
using TEC.Vault.Common;
using TEC.Vault.GoogleSecretManager;
using TEC.Vault.Secrets;

namespace TEC.Vault.Tests;

public class VaultIssueRegressionTests
{
    private sealed class StubReader(string providerName, Func<string, string?, Result<VaultSecret>> getSecretFunc, Func<Result<IReadOnlyList<SecretProperties>>>? listFunc = null)
        : ISecretReader, IDisposable
    {
        public bool Disposed { get; private set; }
        public string ProviderName => providerName;

        public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
            => Task.FromResult(getSecretFunc(name, version));

        public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default)
        {
            var res = getSecretFunc(name, null);
            if (res.IsSuccess) return Task.FromResult(Result<bool>.Success(true));
            if (res.Error?.Code is VaultErrors.NotFoundCode or VaultErrors.InvalidInputCode) return Task.FromResult(Result<bool>.Success(false));
            return Task.FromResult(Result<bool>.Failure(res.Error!));
        }

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(listFunc != null ? listFunc() : Result<IReadOnlyList<SecretProperties>>.Success([]));

        public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default)
            => Task.FromResult(Result<IReadOnlyList<SecretProperties>>.Success([]));

        public void Dispose() => Disposed = true;
    }

    [Test]
    public async Task Issue7_ChainedSecretReader_FallsBack_WhenFirstReader_Returns_InvalidInput()
    {
        // Camada 1 recusa com InvalidInput (ex: caracteres não aceitos no provedor 1)
        var reader1 = new StubReader("Layer1", (name, v) => Result<VaultSecret>.Failure(VaultErrors.InvalidInput("name", "Formato inválido no cofre 1")));
        // Camada 2 aceita e tem o segredo
        var reader2 = new StubReader("Layer2", (name, v) => Result<VaultSecret>.Success(new VaultSecret(new SecretProperties { Name = "chave", Version = "1" }, "valor-segredo")));

        var chained = new ChainedSecretReader([reader1, reader2]);
        var result = await chained.GetSecretAsync("chave");

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Value).IsEqualTo("valor-segredo");
    }

    [Test]
    public async Task Issue8_ChainedSecretReader_FailsClosed_WhenRemoteReaderFails()
    {
        // Camada 1 tem sucesso
        var reader1 = new StubReader("Layer1", (name, v) => Result<VaultSecret>.Success(new VaultSecret(new SecretProperties { Name = "k1", Version = "1" }, "v1")),
            () => Result<IReadOnlyList<SecretProperties>>.Success([new SecretProperties { Name = "k1", Enabled = true }]));

        // Camada 2 falha com erro grave de rede/indisponibilidade
        var reader2 = new StubReader("Layer2", (name, v) => Result<VaultSecret>.Failure(VaultErrors.Unavailable()),
            () => Result<IReadOnlyList<SecretProperties>>.Failure(VaultErrors.Unavailable()));

        var chained = new ChainedSecretReader([reader1, reader2]);
        var listResult = await chained.ListSecretsAsync();

        // Não pode falhar aberto devolvendo só a lista parcial (o que apagaria chaves do IConfiguration)
        await Assert.That(listResult.IsFailure).IsTrue();
        await Assert.That(listResult.Error?.Code).IsEqualTo(VaultErrors.UnavailableCode);
    }

    [Test]
    public async Task Issue12_ChainedSecretReader_Disposes_Internal_Readers()
    {
        var reader1 = new StubReader("L1", (n, v) => Result<VaultSecret>.Failure(VaultErrors.NotFound()));
        var reader2 = new StubReader("L2", (n, v) => Result<VaultSecret>.Failure(VaultErrors.NotFound()));

        var chained = new ChainedSecretReader([reader1, reader2]);
        chained.Dispose();

        await Assert.That(reader1.Disposed).IsTrue();
        await Assert.That(reader2.Disposed).IsTrue();
    }

    [Test]
    public async Task Issue6_Aws_And_Google_VersionPatterns_Accept_Their_Native_Formats()
    {
        // Cofres simulados: sem rede real (antes o teste chamava a AWS e o Google de verdade)
        using var awsStore = new AwsSecretsManagerSecretStore(Fakes.AwsTestOptions.Create(new Fakes.FakeAws()));

        // UUID com hífens é nativo da AWS
        var awsResult = await awsStore.GetSecretAsync("meu-segredo", "c0a80101-0000-0000-0000-000000000001");
        // Não deve falhar na validação de entrada (InvalidInput)
        await Assert.That(awsResult.Error?.Code != VaultErrors.InvalidInputCode).IsTrue();

        using var gcpStore = new GoogleSecretManagerSecretStore(Fakes.GoogleTestOptions.Create(new Fakes.FakeGoogle()));

        // Dígitos ou 'latest' são nativos do Google
        var gcpResult = await gcpStore.GetSecretAsync("meu-segredo", "1");
        await Assert.That(gcpResult.Error?.Code != VaultErrors.InvalidInputCode).IsTrue();
    }
}
