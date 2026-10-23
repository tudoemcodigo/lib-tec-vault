using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.InMemory;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.Tests.Fakes;

/// <summary>Relógio fixo (controlado pelo teste).</summary>
internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;

    // Relógio monotônico (GetTimestamp/GetElapsedTime) acompanha o mesmo instante controlado pelo teste
    public override long GetTimestamp() => Now.UtcTicks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;
}

/// <summary>Provedor em memória pronto para testes (o processo de teste não roda em Development).</summary>
internal static class Memory
{
    public static InMemoryVaultOptions Options(TimeProvider? time = null) => new() { AllowOutsideDevelopment = true, TimeProvider = time };

    public static InMemorySecretStore Secrets(TimeProvider? time = null) => new(Options(time));

    public static InMemoryKeyStore Keys(TimeProvider? time = null) => new(Options(time));

    public static InMemoryCertificateStore Certificates(TimeProvider? time = null) => new(Options(time));

    /// <summary>Cofre de chaves com uma chave RSA "kek" (wrap/unwrap) pronta.</summary>
    public static async Task<InMemoryKeyStore> KeysWithKekAsync()
    {
        var keys = Keys();
        await keys.CreateKeyAsync("kek", new CreateKeyOptions { KeySize = 2048 });
        return keys;
    }
}

/// <summary>
/// Decorator com ganchos para testes de concorrência, falhas e tempo: o valor é lido do cofre interno <b>antes</b> de
/// <see cref="AfterGet"/>, então um teste consegue "segurar" uma leitura com o valor antigo enquanto uma escrita acontece.
/// </summary>
internal sealed class ScriptedSecretStore(ISecretStore inner) : ISecretStore
{
    /// <summary>Executado antes da listagem (ex.: atraso infinito para testar tempo limite).</summary>
    public Func<CancellationToken, Task>? BeforeList { get; set; }

    /// <summary>Executado depois de ler o valor do cofre interno e antes de devolvê-lo.</summary>
    public Func<string, CancellationToken, Task>? AfterGet { get; set; }

    /// <summary>Erro a devolver na leitura do segredo informado (<c>null</c> = lê normalmente).</summary>
    public Func<string, Error?>? GetFailure { get; set; }

    /// <summary>Simula falha do cofre ao alterar a versão informada (ex.: rotação com falha parcial).</summary>
    public Func<string?, bool>? FailUpdateFor { get; set; }

    /// <summary>Lança esta exceção na leitura (simula provedor que viola o contrato).</summary>
    public Exception? ThrowOnGet { get; set; }

    public int GetCalls;

    public string ProviderName => inner.ProviderName;

    public async Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref GetCalls);
        if (GetFailure?.Invoke(name) is { } failure)
            return failure;

        var result = await inner.GetSecretAsync(name, version, cancellationToken);
        if (AfterGet is { } after)
            await after(name, cancellationToken);
        if (ThrowOnGet is { } exception)
            throw exception;
        return result;
    }

    /// <summary>Se informado, a listagem falha com este erro.</summary>
    public Error? ListFailure { get; set; }

    public async Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default)
    {
        if (BeforeList is { } before)
            await before(cancellationToken);
        if (ListFailure is { } failure)
            return failure;
        return await inner.ListSecretsAsync(cancellationToken);
    }

    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => inner.ExistsAsync(name, cancellationToken);

    /// <summary>Executado depois de uma gravação bem-sucedida no cofre interno (ex.: cancelar o token do chamador).</summary>
    public Func<Task>? AfterSet { get; set; }

    public async Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null, CancellationToken cancellationToken = default)
    {
        var result = await inner.SetSecretAsync(name, value, options, cancellationToken);
        if (result.IsSuccess && AfterSet is { } after)
            await after();
        return result;
    }

    public Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default) =>
        FailUpdateFor?.Invoke(version) == true
            ? Task.FromResult<Result<SecretProperties>>(VaultErrors.Unavailable())
            : inner.UpdateSecretPropertiesAsync(name, update, version, cancellationToken);

    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        inner.ListSecretVersionsAsync(name, cancellationToken);

    public Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default) => inner.DeleteSecretAsync(name, cancellationToken);
}

/// <summary>Provedor de chaves só de leitura, sem sonda própria, com construtor público (ativação pelo DI): conta as listagens.</summary>
internal sealed class KeyReaderStub : IKeyReader
{
    public int ListKeysCalls;

    public string ProviderName => "Stub";

    public Task<Result<VaultKey>> GetKeyAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        Task.FromResult<Result<VaultKey>>(VaultErrors.NotFound());

    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeysAsync(CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref ListKeysCalls);
        return Task.FromResult<Result<IReadOnlyList<KeyProperties>>>(Array.Empty<KeyProperties>());
    }

    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeyVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        Task.FromResult<Result<IReadOnlyList<KeyProperties>>>(VaultErrors.NotFound());
}

/// <summary>Provedor de segredos mínimo (só leitura), com construtor público, para testar o registro por tipo no DI.</summary>
internal sealed class SecretReaderStub : ISecretReader
{
    public string ProviderName => "Stub";

    public Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        Task.FromResult<Result<VaultSecret>>(VaultErrors.NotFound());

    public Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default) => Task.FromResult<Result<bool>>(false);

    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(Array.Empty<SecretProperties>());

    public Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        Task.FromResult<Result<IReadOnlyList<SecretProperties>>>(VaultErrors.NotFound());
}
