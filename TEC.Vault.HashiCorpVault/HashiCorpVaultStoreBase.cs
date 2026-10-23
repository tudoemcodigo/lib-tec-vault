using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.HashiCorpVault.Internal;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.HashiCorpVault;

/// <summary>
/// Base dos stores do HashiCorp Vault: o mesmo cliente (endereço, login e token) para segredos, chaves e certificados.
/// Não pode ser derivada fora deste pacote.
/// </summary>
public abstract partial class HashiCorpVaultStoreBase : VaultHttpProviderBase, IDisposable
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "HashiCorpVault";

    /// <summary>Tamanho máximo de um valor de segredo: 512 KB (o Vault limita o corpo da requisição a 32 MB; KV costuma ter limite menor).</summary>
    public const int MaxSecretValueBytes = 512 * 1024;

    internal const string NameRule = "use de 1 a 255 caracteres: letras, números, hífen, sublinhado e ponto, começando por letra ou número.";

    /// <summary>Regras de entrada (limites de <c>custom_metadata</c> do KV v2: 64 chaves, chave até 128 e valor até 512 bytes).</summary>
    internal static VaultProviderRules Rules { get; } = new(NamePattern(), NameRule)
    {
        VersionPattern = VersionPattern(),
        MaxSecretValueBytes = MaxSecretValueBytes,
        MaxTags = 60,
        MaxTagKeyLength = 128,
        MaxTagValueLength = 512,
        MaxBackupBytes = 1
    };

    private readonly bool _ownsClient;

    private protected HashiCorpVaultStoreBase(HashiCorpVaultClient client, bool ownsClient, ILogger? logger)
        : base(Provider, logger ?? NullLogger.Instance, client?.CircuitBreaker)
    {
        ArgumentNullException.ThrowIfNull(client);
        Client = client;
        _ownsClient = ownsClient;
    }

    private protected HashiCorpVaultClient Client { get; }

    private protected TimeProvider Time => Client.Time;

    // \z e não $: $ aceitaria uma quebra de linha no final do nome. Sem barra: o nome nunca vira caminho
    [GeneratedRegex(@"^[0-9a-zA-Z][0-9a-zA-Z._-]{0,254}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    // Até 9 dígitos: o número da versão é um int (10 dígitos passariam na validação e estourariam o int.Parse)
    [GeneratedRegex(@"^[1-9][0-9]{0,8}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VersionPattern();

    private protected static int? ParseVersion(string? version) =>
        version is null ? null : int.Parse(version, NumberStyles.None, CultureInfo.InvariantCulture);

    private protected static string Text(int version) => version.ToString(CultureInfo.InvariantCulture);

    /// <summary>Operação sem retorno executada pela base (validação, auditoria, métricas).</summary>
    private protected async Task<TEC.Core.Common.Results.Result> RunAsync(string operation, string? itemName, TEC.Core.Common.Results.Error? inputError,
        bool isWrite, Func<CancellationToken, Task<TEC.Core.Common.Results.Result>> action, CancellationToken cancellationToken)
    {
        var result = await ExecuteAsync<bool>(operation, itemName, inputError, isWrite, async ct =>
        {
            var outcome = await action(ct).ConfigureAwait(false);
            return outcome.IsSuccess ? true : outcome.ToFailure<bool>();
        }, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? TEC.Core.Common.Results.Result.Success() : result.ToFailure();
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_ownsClient)
            Client.Dispose();
        GC.SuppressFinalize(this);
    }
}
