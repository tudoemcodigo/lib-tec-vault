using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using TEC.Vault.Common;
using TEC.Vault.Diagnostics;
using TEC.Vault.Internal;
using TEC.Core.Common.Results;
using TEC.Core.Cryptography.Hashing;
using TEC.Core.Text.Masking;

namespace TEC.Vault.Providers;

/// <summary>Falha do provedor já convertida: o erro padronizado e um detalhe técnico seguro para log (ex.: "403 ForbiddenByRbac").</summary>
/// <param name="Error">Erro padronizado (<see cref="VaultErrors"/>).</param>
/// <param name="Detail">Detalhe para log. Nunca inclua valores, tokens ou corpo de resposta.</param>
public readonly record struct VaultFailure(Error Error, string Detail);

/// <summary>
/// Listagem acima do limite de itens do provedor (uso pelos provedores, também por classes auxiliares que não derivam de
/// <see cref="VaultProviderBase"/>). Lançada dentro de uma operação, é convertida por <see cref="VaultProviderBase"/> em
/// <see cref="VaultErrors.TooManyItems"/>; nunca chega ao consumidor.
/// </summary>
/// <param name="maxItems">Limite configurado no provedor.</param>
public sealed class VaultListLimitExceededException(int maxItems) : Exception($"Listagem acima do limite de {maxItems} itens.")
{
    /// <summary>Limite configurado no provedor.</summary>
    public int MaxItems { get; } = maxItems;
}

/// <summary>
/// Base para implementar um provedor de cofre (Azure Key Vault, AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Infisical...).
/// Garante o mesmo comportamento em todos: validação de entrada antes da chamada, <see cref="Result"/> em vez de exceção,
/// trilha de auditoria em log (sem valores), <see cref="Activity"/> e métricas para OpenTelemetry (<see cref="VaultDiagnostics"/>).
/// </summary>
public abstract class VaultProviderBase
{
    /// <summary>Valor de <c>error.type</c> nas métricas quando o chamador cancela a operação.</summary>
    internal const string CanceledErrorType = "canceled";

    private readonly ILogger _logger;

    /// <summary>Cria a base.</summary>
    /// <param name="providerName">Nome do provedor (ex.: "AzureKeyVault").</param>
    /// <param name="logger">Logger do provedor.</param>
    protected VaultProviderBase(string providerName, ILogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentNullException.ThrowIfNull(logger);
        ProviderName = providerName;
        _logger = logger;
    }

    /// <summary>Nome do provedor.</summary>
    public string ProviderName { get; }

    /// <summary>
    /// Converte uma exceção do SDK do provedor. Retorne <c>null</c> para exceções desconhecidas: elas são registradas com
    /// a pilha e convertidas em <see cref="VaultErrors.ProviderFailure"/>.
    /// </summary>
    protected abstract VaultFailure? MapException(Exception exception);

    /// <summary>Executa uma operação com retorno.</summary>
    /// <param name="operation">Nome da operação (ex.: "secret.get").</param>
    /// <param name="itemName">Nome do item (para auditoria).</param>
    /// <param name="inputError">Erro de validação de entrada; se informado, a operação não é executada.</param>
    /// <param name="isWrite">Operação de escrita (auditada em Information).</param>
    /// <param name="action">Chamada ao SDK.</param>
    /// <param name="cancellationToken">Cancelamento. Cancelamento solicitado pelo chamador lança <see cref="OperationCanceledException"/>.</param>
    protected async Task<Result<T>> ExecuteAsync<T>(string operation, string? itemName, Error? inputError, bool isWrite,
        Func<CancellationToken, Task<Result<T>>> action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        cancellationToken.ThrowIfCancellationRequested();
        var item = itemName ?? "*";

        if (inputError is not null)
        {
            // Entrada recusada: o nome não é registrado como veio (pode ser lixo, texto de ataque ou até um valor colado por engano)
            VaultLog.InvalidInput(_logger, ProviderName, operation, SensitiveDataMasker.DescribeUntrusted(itemName), inputError.Field ?? "-");
            VaultDiagnostics.RecordOperation(ProviderName, operation, 0, inputError.Code);
            return Result<T>.Failure(inputError);
        }

        using var activity = VaultDiagnostics.ActivitySource.StartActivity($"Cofre {operation}", ActivityKind.Client);
        activity?.SetTag("vault.provider", ProviderName);
        activity?.SetTag("vault.operation", operation);
        long start = Stopwatch.GetTimestamp();

        Result<T> result;
        string detail;
        try
        {
            result = await action(cancellationToken).ConfigureAwait(false);
            detail = result.IsSuccess ? string.Empty : "validação do provedor";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            activity?.SetTag(VaultDiagnostics.ErrorTypeTag, CanceledErrorType);
            activity?.SetStatus(ActivityStatusCode.Error, "cancelado");
            VaultDiagnostics.RecordOperation(ProviderName, operation, Stopwatch.GetElapsedTime(start).TotalSeconds, CanceledErrorType);
            throw;
        }
        catch (Exception ex)
        {
            var mapped = ex is VaultListLimitExceededException limit
                ? new VaultFailure(VaultErrors.TooManyItems(), $"listagem acima de {limit.MaxItems} itens")
                : MapException(ex);
            if (mapped is null)
            {
                var error = VaultErrors.ProviderFailure();
                VaultLog.UnexpectedException(_logger, ex, ProviderName, operation, item, ex.GetType().Name, error.Code);
                Complete(activity, error);
                VaultDiagnostics.RecordOperation(ProviderName, operation, Stopwatch.GetElapsedTime(start).TotalSeconds, error.Code);
                return Result<T>.Failure(error);
            }

            result = Result<T>.Failure(mapped.Value.Error);
            detail = mapped.Value.Detail;
        }

        var elapsedTime = Stopwatch.GetElapsedTime(start);
        long elapsed = (long)elapsedTime.TotalMilliseconds;
        Complete(activity, result.Error);
        VaultDiagnostics.RecordOperation(ProviderName, operation, elapsedTime.TotalSeconds, result.Error?.Code);

        if (result.IsSuccess)
        {
            if (isWrite)
                VaultLog.WriteSucceeded(_logger, ProviderName, operation, item, elapsed);
            else
                VaultLog.ReadSucceeded(_logger, ProviderName, operation, item, elapsed);
        }
        else
        {
            var error = result.Error!;
            if (error.Type is ErrorType.ExternalService or ErrorType.Failure)
                VaultLog.InfrastructureFailure(_logger, ProviderName, operation, item, error.Code, detail);
            else if (isWrite)
                VaultLog.WriteFailure(_logger, ProviderName, operation, item, error.Code, detail);
            else
                VaultLog.ExpectedFailure(_logger, ProviderName, operation, item, error.Code, detail);
        }

        return result;
    }

    /// <summary>Executa uma operação sem retorno.</summary>
    protected async Task<Result> ExecuteAsync(string operation, string? itemName, Error? inputError, bool isWrite,
        Func<CancellationToken, Task> action, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(action);
        var result = await ExecuteAsync<bool>(operation, itemName, inputError, isWrite, async ct =>
        {
            await action(ct).ConfigureAwait(false);
            return true;
        }, cancellationToken).ConfigureAwait(false);

        return result.IsSuccess ? Result.Success() : result.ToFailure();
    }

    /// <summary>
    /// Cópia das tags para os modelos (o chamador e o SDK não alteram o que foi devolvido ou guardado); sem tags, a instância
    /// vazia compartilhada.
    /// </summary>
    /// <remarks>
    /// Tolerante a dados do provedor fora do esperado: chave nula é ignorada, valor nulo vira vazio e chave repetida fica com o
    /// último valor (uma tag malformada não pode derrubar a leitura nem a listagem inteira).
    /// </remarks>
    /// <param name="tags">Tags de origem (<c>null</c> = nenhuma).</param>
    /// <returns>Cópia independente, ou a instância vazia compartilhada.</returns>
    protected static IReadOnlyDictionary<string, string> CopyTags(IEnumerable<KeyValuePair<string, string>>? tags)
    {
        if (tags is null)
            return VaultItemProperties.EmptyTags;

        var copy = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, value) in tags)
        {
            if (key is not null)
                copy[key] = value ?? string.Empty;
        }

        return copy.Count == 0 ? VaultItemProperties.EmptyTags : copy;
    }

    /// <summary>
    /// Registra em <c>Information</c> (trilha de auditoria) uma leitura sensível bem-sucedida que não é escrita, por exemplo a
    /// leitura de um segredo gerenciado que contém a chave privada de um certificado. Nunca inclua valores em <paramref name="reason"/>.
    /// </summary>
    /// <param name="operation">Nome da operação (ex.: "secret.get").</param>
    /// <param name="itemName">Nome do item (já validado).</param>
    /// <param name="reason">Motivo da auditoria (texto fixo).</param>
    protected void AuditSensitiveRead(string operation, string itemName, string reason) =>
        VaultLog.SensitiveRead(_logger, ProviderName, operation, itemName, reason);

    /// <summary>
    /// Limite de itens de uma listagem (uso pelos provedores): chame antes de incluir cada item (ou com o total já conhecido).
    /// Acima de <paramref name="maxItems"/> a operação em andamento é interrompida e devolve <see cref="VaultErrors.TooManyItems"/>
    /// (sem ler o restante da listagem).
    /// </summary>
    /// <param name="count">Quantidade de itens que a listagem teria com o item atual.</param>
    /// <param name="maxItems">Limite configurado no provedor.</param>
    protected static void EnsureListLimit(int count, int maxItems)
    {
        if (count > maxItems)
            throw new VaultListLimitExceededException(maxItems);
    }

    private static void Complete(Activity? activity, Error? error)
    {
        if (activity is null)
            return;

        activity.SetTag("vault.success", error is null);
        if (error is not null)
        {
            activity.SetTag("vault.error_code", error.Code);
            // Mesmo atributo da métrica vault.operation.duration (convenção do OpenTelemetry)
            activity.SetTag(VaultDiagnostics.ErrorTypeTag, error.Code);
            activity.SetStatus(ActivityStatusCode.Error, error.Code);
        }
    }
}
