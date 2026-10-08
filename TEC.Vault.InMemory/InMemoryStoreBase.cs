using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Providers;
using TEC.Core.Common.Results;

namespace TEC.Vault.InMemory;

/// <summary>
/// Base dos stores em memória: trava de ambiente, regras de entrada e conversão de exceções. Não pode ser derivada fora deste pacote.
/// </summary>
/// <remarks>
/// Os stores passam por <see cref="VaultProviderBase"/> como os provedores reais: validação antes da operação, <see cref="Result"/>,
/// auditoria em log (sem valores), <c>Activity</c> e métricas. Cada instância tem os próprios dados; o conteúdo some quando o
/// processo termina.
/// </remarks>
public abstract partial class InMemoryStoreBase : VaultProviderBase
{
    /// <summary>Nome do provedor (<see cref="VaultProviderBase.ProviderName"/>).</summary>
    public const string Provider = "InMemory";

    /// <summary>Retenção informada em <see cref="DeletedVaultItem.ScheduledPurgeDate"/> (não há remoção automática).</summary>
    internal static readonly TimeSpan RetentionPeriod = TimeSpan.FromDays(90);

    internal const int MaxTags = 50;
    internal const int MaxTagLength = 256;
    internal const int MaxBackupBytes = 64;

    internal const string NameRule = "use de 1 a 127 caracteres: letras, números, hífen, sublinhado, ponto e barra, começando por letra ou número.";

    private protected InMemoryStoreBase(InMemoryVaultOptions? options, ILogger? logger)
        : base(Provider, logger ?? NullLogger.Instance)
    {
        Options = options ?? new InMemoryVaultOptions();
        InMemoryEnvironment.EnsureAllowed(Options);
        Time = Options.TimeProvider ?? TimeProvider.System;
    }

    private protected InMemoryVaultOptions Options { get; }

    private protected TimeProvider Time { get; }

    // \z e não $: $ aceitaria uma quebra de linha no final do nome
    [GeneratedRegex(@"^[0-9a-zA-Z][0-9a-zA-Z._/-]{0,126}\z", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex NamePattern();

    /// <summary>Regras de entrada do provedor em memória: os limites acima + as validações comuns a todos os provedores.</summary>
    internal static VaultProviderRules Rules { get; } = new(NamePattern(), NameRule)
    {
        MaxSecretValueBytes = InMemorySecretStore.MaxSecretValueBytes,
        MaxTags = MaxTags,
        MaxTagKeyLength = MaxTagLength,
        MaxTagValueLength = MaxTagLength,
        MaxBackupBytes = MaxBackupBytes
    };

    /// <summary>Nova versão: 32 caracteres hexadecimais (mesmo formato do Azure Key Vault).</summary>
    private protected static string NewVersion() => Guid.NewGuid().ToString("N");

    /// <summary>Operação síncrona sobre os dados em memória, executada pela base (validação, log, métricas).</summary>
    private protected Task<Result<T>> Run<T>(string operation, string? itemName, Error? inputError, bool isWrite, Func<Result<T>> action,
        CancellationToken cancellationToken) =>
        ExecuteAsync(operation, itemName, inputError, isWrite, _ => Task.FromResult(action()), cancellationToken);

    /// <summary>Operação síncrona sem retorno.</summary>
    private protected async Task<Result> RunVoid(string operation, string? itemName, Error? inputError, bool isWrite, Func<Result> action,
        CancellationToken cancellationToken)
    {
        var result = await Run<bool>(operation, itemName, inputError, isWrite, () =>
        {
            var outcome = action();
            return outcome.IsSuccess ? true : outcome.ToFailure<bool>();
        }, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? Result.Success() : result.ToFailure();
    }

    /// <inheritdoc />
    protected override VaultFailure? MapException(Exception exception) => exception switch
    {
        // Dados recusados pela criptografia (texto cifrado inválido, tamanho acima do suportado pela chave...)
        CryptographicException => new VaultFailure(VaultErrors.Rejected(), exception.GetType().Name),
        _ => null
    };
}
