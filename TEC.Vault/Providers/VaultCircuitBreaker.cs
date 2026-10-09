using Microsoft.Extensions.Logging;
using Polly;
using Polly.CircuitBreaker;
using TEC.Vault.Common;
using TEC.Vault.Diagnostics;
using TEC.Vault.Internal;
using TEC.Core.Common.Results;

namespace TEC.Vault.Providers;

/// <summary>
/// Circuit breaker de um destino (um cofre), compartilhado por todos os stores que falam com ele (segredos, chaves e
/// certificados do mesmo cofre abrem e fecham juntos). Criado pelo provedor e entregue a <see cref="VaultProviderBase"/>.
/// </summary>
/// <remarks>Regras e limites em <see cref="VaultCircuitBreakerOptions"/>. Thread-safe.</remarks>
public sealed class VaultCircuitBreaker
{
    private static readonly ResiliencePropertyKey<ILogger> LoggerKey = new("TEC.Vault.Logger");

    private readonly ResiliencePipeline _pipeline;
    private readonly CircuitBreakerStateProvider _state = new();

    /// <summary>Cria o circuit breaker.</summary>
    /// <param name="providerName">Nome do provedor (métricas e log).</param>
    /// <param name="options">Opções (validadas aqui; <see cref="VaultCircuitBreakerOptions.Enabled"/> é ignorado: para respeitá-lo use <see cref="Create"/>).</param>
    /// <param name="timeProvider">Relógio. Padrão: <see cref="TimeProvider.System"/>.</param>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public VaultCircuitBreaker(string providerName, VaultCircuitBreakerOptions options, TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentNullException.ThrowIfNull(options);
        options.ValidateValues("CircuitBreaker");

        ProviderName = providerName;
        _pipeline = new ResiliencePipelineBuilder { TimeProvider = timeProvider ?? TimeProvider.System }
            .AddCircuitBreaker(new CircuitBreakerStrategyOptions
            {
                FailureRatio = options.FailureRatio,
                MinimumThroughput = options.MinimumThroughput,
                SamplingDuration = options.SamplingDuration,
                BreakDuration = options.BreakDuration,
                StateProvider = _state,
                ShouldHandle = args => ValueTask.FromResult(IsFailure(args.Outcome.Result as IVaultOutcome, args.Outcome.Exception)),
                OnOpened = args =>
                {
                    VaultDiagnostics.RecordCircuitState(ProviderName, VaultDiagnostics.CircuitOpen);
                    if (args.Context.Properties.TryGetValue(LoggerKey, out var logger))
                        VaultLog.CircuitOpened(logger, ProviderName, args.BreakDuration.TotalSeconds);
                    return default;
                },
                OnHalfOpened = args =>
                {
                    VaultDiagnostics.RecordCircuitState(ProviderName, VaultDiagnostics.CircuitHalfOpen);
                    if (args.Context.Properties.TryGetValue(LoggerKey, out var logger))
                        VaultLog.CircuitHalfOpened(logger, ProviderName);
                    return default;
                },
                OnClosed = args =>
                {
                    VaultDiagnostics.RecordCircuitState(ProviderName, VaultDiagnostics.CircuitClosed);
                    if (args.Context.Properties.TryGetValue(LoggerKey, out var logger))
                        VaultLog.CircuitClosed(logger, ProviderName);
                    return default;
                }
            })
            .Build();
    }

    /// <summary>Nome do provedor.</summary>
    public string ProviderName { get; }

    /// <summary>Indica se o circuito está aberto (chamadas recusadas sem consultar o cofre).</summary>
    public bool IsOpen => _state.CircuitState is CircuitState.Open or CircuitState.Isolated;

    /// <summary>
    /// Cria o circuit breaker conforme as opções, ou <c>null</c> quando <see cref="VaultCircuitBreakerOptions.Enabled"/> é
    /// <c>false</c> (ou as opções não foram informadas).
    /// </summary>
    /// <param name="providerName">Nome do provedor.</param>
    /// <param name="options">Opções; <c>null</c> = desligado.</param>
    /// <param name="timeProvider">Relógio.</param>
    /// <param name="optionPrefix">Prefixo do nome da opção nas mensagens de validação.</param>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public static VaultCircuitBreaker? Create(string providerName, VaultCircuitBreakerOptions? options, TimeProvider? timeProvider,
        string optionPrefix)
    {
        if (options is null || !options.Enabled)
            return null;
        options.Validate(optionPrefix);
        return new VaultCircuitBreaker(providerName, options, timeProvider);
    }

    /// <summary>
    /// Desfecho que conta como falha. Para o Polly, o que não é falha conta como <b>sucesso</b> (e, na meia-abertura, fecha o
    /// circuito). Por isso, na chamada de teste (meia-abertura), só uma resposta do cofre fecha o circuito: cancelamento e
    /// exceção inesperada (<c>VAULT_FALHA</c>) contam como falha da chamada de teste e o circuito volta a abrir.
    /// </summary>
    private bool IsFailure(IVaultOutcome? outcome, Exception? exception)
    {
        if (outcome is { Error: { } error } && CountsAsFailure(error))
            return true;
        bool definitive = exception is null && outcome is { Unexpected: false };
        return !definitive && _state.CircuitState == CircuitState.HalfOpen;
    }

    /// <summary>Falhas que abrem o circuito: cofre indisponível ou limitando requisições.</summary>
    internal static bool CountsAsFailure(Error error) => error.Code is VaultErrors.UnavailableCode or VaultErrors.ThrottledCode;

    /// <summary>
    /// Executa a chamada pelo circuito. Circuito aberto: devolve <c>null</c> sem executar. Cancelamento e exceções da chamada
    /// são propagados (não contam como falha).
    /// </summary>
    internal async Task<TOutcome?> ExecuteAsync<TOutcome>(Func<CancellationToken, Task<TOutcome>> call, ILogger logger,
        CancellationToken cancellationToken) where TOutcome : class, IVaultOutcome
    {
        var context = ResilienceContextPool.Shared.Get(cancellationToken);
        try
        {
            context.Properties.Set(LoggerKey, logger);
            return await _pipeline.ExecuteAsync(static async (ctx, state) => await state(ctx.CancellationToken).ConfigureAwait(false),
                context, call).ConfigureAwait(false);
        }
        catch (BrokenCircuitException)
        {
            return null;
        }
        finally
        {
            ResilienceContextPool.Shared.Return(context);
        }
    }
}

/// <summary>Resultado de uma chamada visto pelo circuit breaker.</summary>
internal interface IVaultOutcome
{
    /// <summary>Erro da chamada; <c>null</c> = sucesso.</summary>
    Error? Error { get; }

    /// <summary>Exceção não reconhecida pelo provedor (não prova que o cofre respondeu).</summary>
    bool Unexpected { get; }
}
