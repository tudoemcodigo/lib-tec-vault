using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Internal;
using TEC.Vault.Providers;
using TEC.Core.Common.Results;
using TEC.Core.Cryptography.Generators;

namespace TEC.Vault.Secrets;

/// <summary>Operações de segredo que funcionam com qualquer provedor.</summary>
public static class SecretStoreExtensions
{
    /// <summary>
    /// Gera um segredo forte (gerador criptográfico do TEC.Core) e grava no cofre. O valor gerado <b>não</b> é retornado:
    /// quem precisar dele lê do cofre, com a própria identidade e permissão (Zero Trust).
    /// </summary>
    /// <example>
    /// <code>
    /// var result = await vault.GenerateSecretAsync("api-parceiro-token",
    ///     new SecretGenerationOptions { Kind = SecretGenerationKind.Token },
    ///     new SecretWriteOptions { ExpiresOn = DateTimeOffset.UtcNow.AddDays(90) });
    /// </code>
    /// </example>
    public static Task<Result<SecretProperties>> GenerateSecretAsync(this ISecretStore store, string name,
        SecretGenerationOptions? generation = null, SecretWriteOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);

        var generated = Generate(generation ?? new SecretGenerationOptions());
        if (generated.IsFailure)
            return Task.FromResult(generated.ToFailure<SecretProperties>());

        return store.SetSecretAsync(name, generated.Value, options, cancellationToken);
    }

    /// <summary>
    /// Rotaciona o segredo: grava uma nova versão gerada aleatoriamente, mantendo o tipo de conteúdo e as tags da versão atual.
    /// </summary>
    /// <param name="store">Cofre.</param>
    /// <param name="name">Nome do segredo (precisa existir).</param>
    /// <param name="generation">Parâmetros de geração.</param>
    /// <param name="validity">Validade da nova versão (recomendado). <c>null</c> = sem expiração.</param>
    /// <param name="disablePreviousVersions">
    /// Desabilita as versões anteriores após gravar a nova. Use somente quando nenhum consumidor depende mais delas;
    /// caso contrário, deixe expirarem.
    /// </param>
    /// <param name="timeProvider">Relógio usado para calcular a expiração. Padrão: <see cref="TimeProvider.System"/>.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    /// <returns>
    /// Falha se nada foi gravado. Sucesso assim que a nova versão é gravada; se alguma versão anterior não pôde ser
    /// desabilitada, <see cref="SecretRotationResult.IsComplete"/> é <c>false</c> (veja <see cref="SecretRotationResult"/>).
    /// </returns>
    /// <remarks>
    /// Cancelamento antes da gravação lança <see cref="OperationCanceledException"/> (nada mudou). Depois da gravação o
    /// cancelamento <b>não</b> lança: a nova versão já existe e precisa chegar ao chamador. As versões que faltava desabilitar
    /// vão para <see cref="SecretRotationResult.FailedVersions"/> com <see cref="VaultErrors.CanceledCode"/>
    /// (<see cref="SecretRotationResult.IsComplete"/> = <c>false</c>); conclua com <see cref="DisablePreviousSecretVersionsAsync"/>.
    /// Para registrar a rotação incompleta em log, use a sobrecarga com <see cref="ILogger"/>.
    /// </remarks>
    public static Task<Result<SecretRotationResult>> RotateSecretAsync(this ISecretStore store, string name,
        SecretGenerationOptions? generation = null, TimeSpan? validity = null, bool disablePreviousVersions = false,
        TimeProvider? timeProvider = null, CancellationToken cancellationToken = default) =>
        RotateSecretAsync(store, name, generation, validity, disablePreviousVersions, timeProvider, NullLogger.Instance, cancellationToken);

    /// <summary>
    /// Como <see cref="RotateSecretAsync(ISecretStore, string, SecretGenerationOptions?, TimeSpan?, bool, TimeProvider?, CancellationToken)"/>,
    /// registrando em <paramref name="logger"/> (<c>Warning</c>, evento 2009) a rotação que gravou a nova versão mas não
    /// desabilitou todas as anteriores (falha do cofre ou cancelamento).
    /// </summary>
    /// <param name="store">Cofre.</param>
    /// <param name="name">Nome do segredo (precisa existir).</param>
    /// <param name="generation">Parâmetros de geração.</param>
    /// <param name="validity">Validade da nova versão (recomendado). <c>null</c> = sem expiração.</param>
    /// <param name="disablePreviousVersions">Desabilita as versões anteriores após gravar a nova.</param>
    /// <param name="timeProvider">Relógio usado para calcular a expiração. Padrão: <see cref="TimeProvider.System"/>.</param>
    /// <param name="logger">Logger da rotação incompleta (registra nome, versões e código de erro; nunca o valor).</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    public static async Task<Result<SecretRotationResult>> RotateSecretAsync(this ISecretStore store, string name,
        SecretGenerationOptions? generation, TimeSpan? validity, bool disablePreviousVersions,
        TimeProvider? timeProvider, ILogger logger, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(logger);
        if (validity is { } v && v <= TimeSpan.Zero)
            return VaultErrors.InvalidInput(nameof(validity), "A validade deve ser maior que zero.");

        var versions = await store.ListSecretVersionsAsync(name, cancellationToken).ConfigureAwait(false);
        if (versions.IsFailure)
            return versions.ToFailure<SecretRotationResult>();

        var current = await CurrentVersionAsync(store, name, versions.Value, cancellationToken).ConfigureAwait(false);
        if (current.IsFailure)
            return current.ToFailure<SecretRotationResult>();
        if (current.Value.IsManaged)
            return VaultErrors.InvalidInput(nameof(name), "Segredos gerenciados pelo provedor (ex.: de certificados) não podem ser rotacionados diretamente.");

        var generated = Generate(generation ?? new SecretGenerationOptions());
        if (generated.IsFailure)
            return generated.ToFailure<SecretRotationResult>();

        var now = (timeProvider ?? TimeProvider.System).GetUtcNow();
        var written = await store.SetSecretAsync(name, generated.Value, new SecretWriteOptions
        {
            ContentType = current.Value.ContentType,
            Tags = current.Value.Tags,
            ExpiresOn = validity is null ? null : now.Add(validity.Value)
        }, cancellationToken).ConfigureAwait(false);

        if (written.IsFailure)
            return written.ToFailure<SecretRotationResult>();
        if (!disablePreviousVersions)
            return new SecretRotationResult { Current = written.Value };

        // A nova versão já está no cofre: daqui em diante o cancelamento não pode fazer o chamador perdê-la
        var result = await DisableOthersAsync(store, name, written.Value, versions.Value, stopOnCancel: true, cancellationToken)
            .ConfigureAwait(false);
        if (!result.IsComplete)
        {
            VaultLog.RotationIncomplete(logger, store.ProviderName, name, written.Value.Version ?? "-",
                result.FailedVersions.Count, result.Errors.Count > 0 ? result.Errors[0].Code : "-");
        }

        return result;
    }

    /// <summary>
    /// Desabilita todas as versões habilitadas do segredo, exceto <paramref name="currentVersion"/>. Idempotente: use para
    /// concluir uma rotação cujo <see cref="SecretRotationResult.IsComplete"/> veio <c>false</c>, sem criar nova versão.
    /// </summary>
    /// <param name="store">Cofre.</param>
    /// <param name="name">Nome do segredo.</param>
    /// <param name="currentVersion">Versão que continua habilitada (precisa existir).</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    public static async Task<Result<SecretRotationResult>> DisablePreviousSecretVersionsAsync(this ISecretStore store, string name,
        string currentVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (string.IsNullOrEmpty(currentVersion))
            return VaultErrors.InvalidInput(nameof(currentVersion), "A versão atual é obrigatória.");

        var versions = await store.ListSecretVersionsAsync(name, cancellationToken).ConfigureAwait(false);
        if (versions.IsFailure)
            return versions.ToFailure<SecretRotationResult>();

        var current = versions.Value.FirstOrDefault(p => string.Equals(p.Version, currentVersion, StringComparison.OrdinalIgnoreCase));
        if (current is null)
            return VaultErrors.NotFound();

        return await DisableOthersAsync(store, name, current, versions.Value, stopOnCancel: false, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<SecretRotationResult> DisableOthersAsync(ISecretStore store, string name, SecretProperties current,
        IReadOnlyList<SecretProperties> versions, bool stopOnCancel, CancellationToken cancellationToken)
    {
        var disabledVersions = new List<string>();
        var failedVersions = new List<string>();
        var errors = new List<Error>();

        var pending = versions.Where(p => p.Enabled && p.Version is not null
            && !string.Equals(p.Version, current.Version, StringComparison.OrdinalIgnoreCase)).ToList();

        // Tenta todas, mesmo após uma falha: deixa o mínimo possível de versões antigas habilitadas
        for (int i = 0; i < pending.Count; i++)
        {
            var old = pending[i];
            Result<SecretProperties> disabled;
            try
            {
                disabled = await store.UpdateSecretPropertiesAsync(name, new SecretPropertiesUpdate { Enabled = false }, old.Version,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stopOnCancel && cancellationToken.IsCancellationRequested)
            {
                // Cancelado pelo chamador: esta versão e as seguintes ficam pendentes (o estado desta no cofre é incerto;
                // desabilitar de novo é idempotente)
                foreach (var remaining in pending.Skip(i))
                {
                    failedVersions.Add(remaining.Version!);
                    errors.Add(VaultErrors.Canceled());
                }

                break;
            }

            if (disabled.IsSuccess)
            {
                disabledVersions.Add(old.Version!);
            }
            else
            {
                failedVersions.Add(old.Version!);
                errors.Add(disabled.Error!);
            }
        }

        return new SecretRotationResult { Current = current, DisabledVersions = disabledVersions, FailedVersions = failedVersions, Errors = errors };
    }

    /// <summary>
    /// Versão atual do segredo: a de maior <see cref="Common.VaultItemProperties.CreatedOn"/>. Os provedores costumam ter
    /// resolução de 1 segundo; em empate a listagem não diz qual é a atual, então o provedor é consultado (leitura sem versão,
    /// que retorna a atual; o valor é descartado). Se a atual estiver desabilitada, desempata por <c>UpdatedOn</c> e versão.
    /// </summary>
    internal static async Task<Result<SecretProperties>> CurrentVersionAsync(ISecretReader store, string name,
        IReadOnlyList<SecretProperties> versions, CancellationToken cancellationToken)
    {
        if (versions.Count == 0)
            return VaultErrors.NotFound();

        var newest = VaultVersionRules.Newest(versions, p => p.CreatedOn);
        if (newest.Count == 1)
            return newest[0];

        var read = await store.GetSecretAsync(name, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (read.IsSuccess)
        {
            return versions.FirstOrDefault(p => string.Equals(p.Version, read.Value.Version, StringComparison.OrdinalIgnoreCase))
                ?? read.Value.Properties;
        }

        if (read.Error!.Code != VaultErrors.DisabledCode)
            return read.ToFailure<SecretProperties>();

        return VaultVersionRules.BreakTie(newest, p => p.UpdatedOn, p => p.Version);
    }

    internal static Result<string> Generate(SecretGenerationOptions options)
    {
        if (options.Length is < 16 or > 1024)
            return VaultErrors.InvalidInput(nameof(options.Length), "O tamanho deve estar entre 16 e 1024.");

        return options.Kind switch
        {
            SecretGenerationKind.Password => SecureRandomGenerator.GeneratePassword(options.Length, includeSpecial: options.IncludeSpecialCharacters),
            SecretGenerationKind.Token => SecureRandomGenerator.GenerateToken(options.Length),
            SecretGenerationKind.Hex => SecureRandomGenerator.GenerateHex(options.Length),
            _ => VaultErrors.InvalidInput(nameof(options.Kind), "Formato de geração inválido.")
        };
    }
}
