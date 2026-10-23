using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Core.Common.Results;

namespace TEC.Vault.Secrets;

/// <summary>
/// Leitor de segredos em camadas (fallback): consulta uma lista ordenada de leitores.
/// Permite sobrescrever segredos em variáveis de ambiente com fallback transparente para cofre remoto (Azure, HashiCorp, etc.).
/// </summary>
public sealed class ChainedSecretReader : ISecretReader, IVaultHealthProbe
{
    /// <summary>Nome do provedor.</summary>
    public const string Provider = "Chained";

    private readonly IReadOnlyList<ISecretReader> _readers;
    private readonly ILogger _logger;

    /// <inheritdoc />
    public string ProviderName => Provider;

    /// <summary>
    /// Cria o leitor em camadas com a lista de leitores ordenada por prioridade (o primeiro tem precedência).
    /// </summary>
    /// <param name="readers">Lista ordenada de leitores (mínimo de 1 leitor).</param>
    /// <param name="logger">Logger opcional.</param>
    /// <exception cref="ArgumentException">Se a lista for nula ou vazia.</exception>
    public ChainedSecretReader(IEnumerable<ISecretReader> readers, ILogger<ChainedSecretReader>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(readers);
        _readers = readers.Where(r => r is not null).ToList();
        if (_readers.Count == 0)
            throw new ArgumentException("ChainedSecretReader exige ao menos um leitor de segredos.", nameof(readers));

        _logger = logger ?? (ILogger)NullLogger.Instance;
    }

    /// <inheritdoc />
    public async Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(name))
            return VaultErrors.InvalidInput("name", "o nome do segredo é obrigatório.");

        Error? lastError = null;

        for (int i = 0; i < _readers.Count; i++)
        {
            var reader = _readers[i];
            var result = await reader.GetSecretAsync(name, version, cancellationToken).ConfigureAwait(false);

            if (result.IsSuccess)
            {
                if (i > 0)
                    _logger.LogDebug("Segredo encontrado pelo leitor de fallback #{Index} ({Type}).", i, reader.GetType().Name);

                return result;
            }

            lastError = result.Error;

            // Se for item não encontrado, continua no próximo provedor da cadeia
            if (result.Error?.Code == VaultErrors.NotFoundCode)
                continue;

            // Falha grave de autorização ou indisponibilidade interrompe a busca
            return result;
        }

        return lastError ?? VaultErrors.NotFound();
    }

    /// <inheritdoc />
    public async Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(name))
            return VaultErrors.InvalidInput("name", "o nome do segredo é obrigatório.");

        for (int i = 0; i < _readers.Count; i++)
        {
            var reader = _readers[i];
            var result = await reader.ExistsAsync(name, cancellationToken).ConfigureAwait(false);

            if (result.IsSuccess && result.Value)
                return Result<bool>.Success(true);

            if (result.IsFailure && result.Error?.Code != VaultErrors.NotFoundCode)
                return result;
        }

        return Result<bool>.Success(false);
    }

    /// <inheritdoc />
    public async Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var aggregated = new Dictionary<string, SecretProperties>(StringComparer.OrdinalIgnoreCase);
        bool anySuccess = false;
        Error? lastError = null;

        foreach (var reader in _readers)
        {
            var result = await reader.ListSecretsAsync(cancellationToken).ConfigureAwait(false);
            if (result.IsSuccess)
            {
                anySuccess = true;
                foreach (var props in result.Value)
                {
                    if (props.Name is not null && !aggregated.ContainsKey(props.Name))
                        aggregated[props.Name] = props;
                }
            }
            else
            {
                lastError = result.Error;
            }
        }

        if (anySuccess)
        {
            var sortedList = aggregated.Values.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToArray();
            return Result<IReadOnlyList<SecretProperties>>.Success(sortedList);
        }

        return lastError ?? VaultErrors.NotFound();
    }

    /// <inheritdoc />
    public async Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(name))
            return VaultErrors.InvalidInput("name", "o nome do segredo é obrigatório.");

        for (int i = 0; i < _readers.Count; i++)
        {
            var reader = _readers[i];
            var result = await reader.ListSecretVersionsAsync(name, cancellationToken).ConfigureAwait(false);

            if (result.IsSuccess)
                return result;

            if (result.Error?.Code == VaultErrors.NotFoundCode)
                continue;

            return result;
        }

        return VaultErrors.NotFound();
    }

    /// <inheritdoc />
    public async Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        foreach (var reader in _readers)
        {
            if (reader is IVaultHealthProbe probe)
            {
                var result = await probe.CheckAccessAsync(cancellationToken).ConfigureAwait(false);
                if (result.IsFailure)
                    return result;
            }
        }

        return Result.Success();
    }
}
