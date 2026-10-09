using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace TEC.Vault.Diagnostics;

/// <summary>Rastreamento e métricas (OpenTelemetry) do cofre.</summary>
/// <remarks>
/// Segurança: nenhum trace ou métrica leva o nome do item (traces e métricas costumam ser enviados a terceiros); o nome fica
/// apenas no log de auditoria. As dimensões são de baixa cardinalidade: provedor, operação e código do erro.
/// </remarks>
/// <example>
/// <code>
/// // Com o TEC.Observability nada é preciso: o AddTecObservability exporta as fontes "TEC.*". Sem ele:
/// builder.Services.AddOpenTelemetry()
///     .WithTracing(t => t.AddSource(VaultDiagnostics.ActivitySourceName))
///     .WithMetrics(m => m.AddMeter(VaultDiagnostics.MeterName));
/// </code>
/// </example>
public static class VaultDiagnostics
{
    /// <summary>
    /// Nome do <see cref="System.Diagnostics.ActivitySource"/>. Cada operação gera uma <c>Activity</c> (Client) com as tags
    /// <c>vault.provider</c>, <c>vault.operation</c>, <c>vault.success</c>, <c>vault.error_code</c> e, em falha,
    /// <c>error.type</c> (o mesmo valor da métrica).
    /// </summary>
    public const string ActivitySourceName = "TEC.Vault";

    /// <summary>
    /// Nome do <see cref="System.Diagnostics.Metrics.Meter"/>. Instrumentos:
    /// <list type="bullet">
    /// <item><description><see cref="OperationDurationName"/> (histograma, segundos): toda operação de provedor, com
    /// <c>vault.provider</c>, <c>vault.operation</c> (ex.: <c>secret.get</c>) e, em falha, <c>error.type</c> (código de
    /// <c>VaultErrors</c>, ou <c>canceled</c>). A contagem por tipo/resultado vem do próprio histograma.</description></item>
    /// <item><description><see cref="CacheRequestsName"/> (contador): leituras do cache de segredos, com <c>vault.provider</c> e
    /// <c>vault.cache.result</c> = <c>hit</c>, <c>miss</c> (consultou o cofre) ou <c>coalesced</c> (aguardou uma leitura
    /// simultânea da mesma chave).</description></item>
    /// <item><description><see cref="CircuitStateChangesName"/> (contador): mudanças de estado do circuit breaker, com
    /// <c>vault.provider</c> e <c>vault.circuit.state</c> = <c>open</c>, <c>half_open</c> ou <c>closed</c>. Chamadas recusadas com o
    /// circuito aberto aparecem em <see cref="OperationDurationName"/> com <c>error.type</c> = <c>VAULT_CIRCUITO_ABERTO</c>.</description></item>
    /// </list>
    /// Exportado sem configuração pelo <c>AddTecObservability</c> do TEC.Observability (prefixo <c>TEC.*</c>).
    /// </summary>
    public const string MeterName = "TEC.Vault";

    /// <summary>Histograma da duração das operações (segundos).</summary>
    public const string OperationDurationName = "vault.operation.duration";

    /// <summary>Contador de leituras do cache de segredos.</summary>
    public const string CacheRequestsName = "vault.cache.requests";

    /// <summary>Contador de mudanças de estado do circuit breaker.</summary>
    public const string CircuitStateChangesName = "vault.circuit.state_changes";

    internal const string ProviderTag = "vault.provider";
    internal const string OperationTag = "vault.operation";
    internal const string ErrorTypeTag = "error.type";
    internal const string CacheResultTag = "vault.cache.result";
    internal const string CircuitStateTag = "vault.circuit.state";
    internal const string CircuitOpen = "open";
    internal const string CircuitHalfOpen = "half_open";
    internal const string CircuitClosed = "closed";

    internal static readonly ActivitySource ActivitySource = new(ActivitySourceName);

    internal static readonly Meter Meter = new(MeterName, typeof(VaultDiagnostics).Assembly.GetName().Version?.ToString());

    internal static readonly Histogram<double> OperationDuration = Meter.CreateHistogram<double>(
        OperationDurationName, unit: "s", description: "Duração das operações do cofre.");

    internal static readonly Counter<long> CacheRequests = Meter.CreateCounter<long>(
        CacheRequestsName, unit: "{request}", description: "Leituras do cache de segredos por resultado.");

    internal static readonly Counter<long> CircuitStateChanges = Meter.CreateCounter<long>(
        CircuitStateChangesName, unit: "{change}", description: "Mudanças de estado do circuit breaker do cofre.");

    /// <summary>Registra a duração de uma operação. <paramref name="errorType"/> só em falha.</summary>
    internal static void RecordOperation(string provider, string operation, double seconds, string? errorType)
    {
        if (!OperationDuration.Enabled)
            return;

        var tags = new TagList
        {
            { ProviderTag, provider },
            { OperationTag, operation }
        };
        if (errorType is not null)
            tags.Add(ErrorTypeTag, errorType);
        OperationDuration.Record(seconds, tags);
    }

    /// <summary>Registra uma leitura do cache (<c>hit</c>, <c>miss</c> ou <c>coalesced</c>).</summary>
    internal static void RecordCache(string provider, string result)
    {
        if (CacheRequests.Enabled)
            CacheRequests.Add(1, new KeyValuePair<string, object?>(ProviderTag, provider), new KeyValuePair<string, object?>(CacheResultTag, result));
    }

    /// <summary>Registra uma mudança de estado do circuito (<c>open</c>, <c>half_open</c> ou <c>closed</c>).</summary>
    internal static void RecordCircuitState(string provider, string state)
    {
        if (CircuitStateChanges.Enabled)
            CircuitStateChanges.Add(1, new KeyValuePair<string, object?>(ProviderTag, provider), new KeyValuePair<string, object?>(CircuitStateTag, state));
    }
}
