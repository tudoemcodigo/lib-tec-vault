using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Internal;
using TEC.Vault.Secrets;
using TEC.Core.Common.Guards;

namespace TEC.Vault.Configuration;

/// <summary>Opções do provedor de configuração do cofre.</summary>
public sealed class VaultConfigurationOptions
{
    /// <summary>
    /// Carrega apenas segredos cujo nome começa com este prefixo (sem diferenciar maiúsculas), removendo-o da chave.
    /// Recomendado: um prefixo por aplicação (ex.: "MinhaApi--"), para que cada aplicação só carregue o que é seu.
    /// </summary>
    public string? Prefix { get; set; }

    /// <summary>Separador de seções no nome do segredo. Padrão: "--" ("ConnectionStrings--Default" → "ConnectionStrings:Default").</summary>
    public string SectionSeparator
    {
        get;
        set
        {
            Guard.Against(string.IsNullOrEmpty(value), "Informe o separador.", nameof(SectionSeparator));
            field = value;
        }
    } = "--";

    /// <summary>
    /// Intervalo de recarga (mínimo 1 minuto). <c>null</c> (padrão) = carrega só na inicialização.
    /// Falhas na recarga mantêm os valores anteriores (e são registradas em log).
    /// </summary>
    /// <remarks>
    /// A recarga é incremental: só são lidos os segredos cuja versão (ou data de atualização) mudou desde a última carga.
    /// A cada <see cref="FullReloadEvery"/> recargas, todos são relidos (cobre mudanças no mesmo segundo da carga anterior).
    /// </remarks>
    public TimeSpan? ReloadInterval
    {
        get;
        set => field = value is null || value >= TimeSpan.FromMinutes(1)
            ? value
            : throw new ArgumentOutOfRangeException(nameof(ReloadInterval), "A recarga deve ser de no mínimo 1 minuto.");
    }

    /// <summary>
    /// Se <c>true</c>, falha ao acessar o cofre na inicialização não impede a aplicação de subir (configuração vazia).
    /// Vale para qualquer falha: erro do cofre, tempo limite, limite de segredos e exceção lançada pelo leitor (registrada em log,
    /// evento 2106). Padrão: <c>false</c> (fail closed: sem os segredos a aplicação não sobe).
    /// </summary>
    /// <remarks>
    /// Depois de uma carga bem-sucedida, uma nova carga que falhe (ex.: <c>IConfigurationRoot.Reload()</c> com o cofre fora
    /// do ar) mantém os valores anteriores, como a recarga periódica: os segredos já carregados não são apagados.
    /// </remarks>
    public bool Optional { get; set; }

    /// <summary>Máximo de segredos carregados (proteção contra carga acidental do cofre inteiro). Padrão: 500.</summary>
    public int MaxSecrets
    {
        get;
        set => field = Guard.Positive(value, nameof(MaxSecrets));
    } = 500;

    /// <summary>
    /// Tempo máximo de cada carga (inicial ou recarga), somando a listagem e todas as leituras. Padrão: 30 segundos (máximo 10 minutos).
    /// A carga inicial bloqueia a inicialização da aplicação: sem limite, um cofre lento a travaria indefinidamente.
    /// </summary>
    public TimeSpan LoadTimeout
    {
        get;
        set => field = value > TimeSpan.Zero && value <= TimeSpan.FromMinutes(10)
            ? value
            : throw new ArgumentOutOfRangeException(nameof(LoadTimeout), "O tempo limite deve ser maior que zero e no máximo 10 minutos.");
    } = TimeSpan.FromSeconds(30);

    /// <summary>Máximo de leituras simultâneas de segredos durante a carga (1 a 16). Padrão: 4 (evita throttling do cofre).</summary>
    public int MaxConcurrentReads
    {
        get;
        set => field = Guard.InRange(value, 1, 16, nameof(MaxConcurrentReads));
    } = 4;

    /// <summary>A cada quantas recargas incrementais é feita uma releitura completa.</summary>
    public const int FullReloadEvery = 12;
}

internal sealed class VaultConfigurationSource(ISecretReader store, VaultConfigurationOptions options, TimeProvider time, ILoggerFactory? loggerFactory)
    : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder) =>
        new VaultConfigurationProvider(store, options, time, loggerFactory?.CreateLogger<VaultConfigurationProvider>());
}

/// <summary>
/// Carrega segredos habilitados e dentro da validade como configuração. Segredos gerenciados (de certificados) são ignorados.
/// </summary>
/// <remarks>
/// Cargas simultâneas (<c>IConfigurationRoot.Reload()</c> durante a recarga do timer) são ordenadas por geração: cada carga
/// recebe um número ao começar e só é aplicada se nenhuma carga iniciada depois já tiver sido aplicada. Assim uma carga
/// antiga e lenta nunca grava valores antigos por cima de uma mais nova.
/// </remarks>
internal sealed class VaultConfigurationProvider : ConfigurationProvider, IDisposable
{
    private readonly ISecretReader _store;
    private readonly VaultConfigurationOptions _options;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private ITimer? _timer;
    private int _reloading;
    private int _reloadsSinceFull;

    // Protege a aplicação de uma carga (Data, _snapshot, _appliedGeneration, _loaded)
    private readonly Lock _apply = new();

    // Geração da última carga iniciada (Interlocked) e da última aplicada (sob _apply)
    private long _startedGeneration;
    private long _appliedGeneration;

    // Última carga aplicada: nome do segredo → versão/atualização e valor, para a recarga incremental
    private Dictionary<string, Snapshot> _snapshot = new(StringComparer.OrdinalIgnoreCase);

    private bool _loaded;

    /// <summary>Segredo da última carga. <see cref="ToString"/> e o depurador mascaram o valor (o gerado pelo <c>record</c> o imprimiria).</summary>
    [DebuggerDisplay("{ToString(),nq}")]
    internal readonly record struct Snapshot(string? Version, DateTimeOffset? UpdatedOn, string Key, string Value)
    {
        public override string ToString() => $"Snapshot {{ Version = {Version}, UpdatedOn = {UpdatedOn:O}, Key = {Key}, Value = *** }}";
    }

    public VaultConfigurationProvider(ISecretReader store, VaultConfigurationOptions options, TimeProvider time, ILogger? logger = null)
    {
        _store = store;
        _options = options;
        _time = time;
        _logger = logger ?? NullLogger.Instance;
    }

    /// <summary>Timer da recarga periódica (testes).</summary>
    internal ITimer? Timer => _timer;

    public override void Load()
    {
        // O pipeline de configuração é síncrono: a carga inicial bloqueia até ler o cofre (mesmo comportamento do provedor
        // oficial do Azure), limitada por LoadTimeout
        long generation = Interlocked.Increment(ref _startedGeneration);
        LoadOutcome outcome;
        try
        {
            outcome = WaitInitialLoad(LoadDataAsync(incremental: false));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Exceção do leitor (provedor que viola o contrato de Result, falha de rede não convertida...): com Optional a
            // aplicação sobe como em qualquer outra falha de carga; sem Optional a exceção original segue para quem chamou
            VaultLog.ConfigurationLoadException(_logger, ex, _store.ProviderName, ex.GetType().Name);
            if (!_options.Optional)
                throw;
            outcome = new LoadOutcome(null, null, ExceptionCode);
        }

        if (outcome.Data is null)
        {
            // Load() também é chamado por IConfigurationRoot.Reload(): depois de uma carga aplicada, a falha é de recarga
            bool reload;
            lock (_apply)
                reload = _loaded;
            if (reload)
                VaultLog.ConfigurationReloadFailed(_logger, _store.ProviderName, outcome.ErrorCode);
            else
                VaultLog.ConfigurationLoadFailed(_logger, _store.ProviderName, outcome.ErrorCode);
            if (!_options.Optional)
            {
                throw new InvalidOperationException(
                    $"Não foi possível carregar a configuração do cofre ({outcome.ErrorCode}). Verifique o log e as permissões da identidade da aplicação.");
            }

            // Optional: sobe com configuração vazia só se nunca houve carga. Depois de uma carga bem-sucedida (Reload() do
            // IConfigurationRoot), a falha mantém os valores anteriores, como a recarga do timer: um cofre fora do ar não
            // pode apagar os segredos já carregados
            lock (_apply)
            {
                if (!_loaded)
                    Data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            }
        }
        else
        {
            TryApply(generation, outcome, out _);
        }

        if (_options.ReloadInterval is { } interval && _timer is null)
            _timer = _time.CreateTimer(_ => _ = ReloadAsync(), null, interval, interval);
    }

    internal async Task ReloadAsync()
    {
        if (Interlocked.Exchange(ref _reloading, 1) == 1)
            return;

        try
        {
            bool incremental = ++_reloadsSinceFull < VaultConfigurationOptions.FullReloadEvery;
            if (!incremental)
                _reloadsSinceFull = 0;

            long generation = Interlocked.Increment(ref _startedGeneration);
            var outcome = await LoadDataAsync(incremental).ConfigureAwait(false);
            if (outcome.Data is null)
            {
                if (outcome.ErrorCode == TimeoutCode)
                    VaultLog.ConfigurationTimeout(_logger, _store.ProviderName, _options.LoadTimeout.TotalSeconds);
                VaultLog.ConfigurationReloadFailed(_logger, _store.ProviderName, outcome.ErrorCode);
                return;
            }

            if (TryApply(generation, outcome, out bool changed) && changed)
                OnReload();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Mantém os valores atuais (exceção vinda do provedor ou do OnReload de um assinante)
            VaultLog.ConfigurationReloadException(_logger, ex, _store.ProviderName, ex.GetType().Name);
        }
        finally
        {
            Volatile.Write(ref _reloading, 0);
        }
    }

    /// <summary>
    /// Aplica a carga se nenhuma carga iniciada depois dela já foi aplicada. <paramref name="changed"/> indica se os valores
    /// mudaram (o aviso de mudança é disparado por quem chamou, fora da trava).
    /// </summary>
    private bool TryApply(long generation, LoadOutcome outcome, out bool changed)
    {
        lock (_apply)
        {
            changed = false;
            if (generation < _appliedGeneration)
            {
                VaultLog.ConfigurationStaleLoadDiscarded(_logger, _store.ProviderName);
                return false;
            }

            _appliedGeneration = generation;
            Volatile.Write(ref _snapshot, outcome.Snapshot!);
            _loaded = true;
            if (!HasSameData(outcome.Data!))
            {
                Data = outcome.Data!;
                changed = true;
            }

            return true;
        }
    }

    /// <summary>Código lógico (não é de <see cref="VaultErrors"/>) para carga interrompida pelo tempo limite.</summary>
    internal const string TimeoutCode = "TEMPO_LIMITE";

    /// <summary>Código lógico para filtro acima de <see cref="VaultConfigurationOptions.MaxSecrets"/>.</summary>
    internal const string TooManySecretsCode = "LIMITE_MAX_SECRETS";

    /// <summary>Código lógico para carga interrompida por exceção do leitor (só com <see cref="VaultConfigurationOptions.Optional"/>).</summary>
    internal const string ExceptionCode = "EXCECAO_NA_CARGA";

    private readonly record struct LoadOutcome(Dictionary<string, string?>? Data, Dictionary<string, Snapshot>? Snapshot, string ErrorCode);

    /// <summary>Folga sobre <see cref="VaultConfigurationOptions.LoadTimeout"/> para a espera síncrona da carga inicial.</summary>
    internal static readonly TimeSpan InitialLoadGrace = TimeSpan.FromSeconds(2);

    /// <summary>
    /// Espera a carga inicial no próprio thread, limitada a <see cref="VaultConfigurationOptions.LoadTimeout"/> mais
    /// <see cref="InitialLoadGrace"/>.
    /// </summary>
    /// <remarks>
    /// O cancelamento por tempo limite é cooperativo e a continuação dele precisa de uma thread livre do pool: com o pool
    /// saturado (muitas requisições ou testes em paralelo bloqueando threads), ou com um leitor que ignore o
    /// <see cref="CancellationToken"/>, a subida esperaria muito além do limite ou para sempre. A espera direta no handle
    /// da tarefa não depende do pool. A carga que terminar depois é descartada (a recarga periódica a refaz) e uma falha
    /// tardia é observada, sem virar exceção não observada.
    /// </remarks>
    private LoadOutcome WaitInitialLoad(Task<LoadOutcome> loading)
    {
        if (((IAsyncResult)loading).AsyncWaitHandle.WaitOne(_options.LoadTimeout + InitialLoadGrace))
        {
            var outcome = loading.GetAwaiter().GetResult();
            if (outcome.ErrorCode == TimeoutCode)
                VaultLog.ConfigurationTimeout(_logger, _store.ProviderName, _options.LoadTimeout.TotalSeconds);
            return outcome;
        }

        _ = loading.ContinueWith(
            static task => _ = task.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
        VaultLog.ConfigurationTimeout(_logger, _store.ProviderName, _options.LoadTimeout.TotalSeconds);
        return new LoadOutcome(null, null, TimeoutCode);
    }

    /// <summary>Carga com tempo limite; o log do tempo esgotado fica com quem chama (uma única vez por carga).</summary>
    private async Task<LoadOutcome> LoadDataAsync(bool incremental)
    {
        long start = Stopwatch.GetTimestamp();
        using var timeout = new CancellationTokenSource(_options.LoadTimeout, _time);
        try
        {
            return await LoadDataCoreAsync(incremental, start, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            return new LoadOutcome(null, null, TimeoutCode);
        }
    }

    private async Task<LoadOutcome> LoadDataCoreAsync(bool incremental, long start, CancellationToken cancellationToken)
    {
        var list = await _store.ListSecretsAsync(cancellationToken).ConfigureAwait(false);
        if (list.IsFailure)
            return new LoadOutcome(null, null, list.Error!.Code);

        var now = _time.GetUtcNow();
        var prefix = _options.Prefix ?? string.Empty;
        var candidates = list.Value
            .Where(p => !p.IsManaged && p.IsActive(now) && p.Name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && p.Name.Length > prefix.Length)
            .ToList();

        if (candidates.Count > _options.MaxSecrets)
        {
            VaultLog.ConfigurationTooManySecrets(_logger, _store.ProviderName, candidates.Count, _options.MaxSecrets);
            return new LoadOutcome(null, null, TooManySecretsCode);
        }

        var previous = Volatile.Read(ref _snapshot);   // base da recarga incremental: a última carga aplicada
        var snapshot = new Dictionary<string, Snapshot>(StringComparer.OrdinalIgnoreCase);
        var toRead = new List<SecretProperties>();
        foreach (var properties in candidates)
        {
            if (incremental && previous.TryGetValue(properties.Name, out var known) && IsUnchanged(properties, known))
                snapshot[properties.Name] = known;
            else
                toRead.Add(properties);
        }

        // Leituras em paralelo limitado; a primeira falha cancela as demais
        string? failure = null;
        var read = new System.Collections.Concurrent.ConcurrentDictionary<string, Snapshot>(StringComparer.OrdinalIgnoreCase);
        using var abort = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            await Parallel.ForEachAsync(toRead, new ParallelOptions { MaxDegreeOfParallelism = _options.MaxConcurrentReads, CancellationToken = abort.Token },
                async (properties, ct) =>
                {
                    var secret = await _store.GetSecretAsync(properties.Name, cancellationToken: ct).ConfigureAwait(false);
                    if (secret.IsFailure)
                    {
                        Interlocked.CompareExchange(ref failure, secret.Error!.Code, null);
                        await abort.CancelAsync().ConfigureAwait(false);
                        return;
                    }

                    string key = properties.Name[prefix.Length..].Replace(_options.SectionSeparator, ConfigurationPath.KeyDelimiter, StringComparison.Ordinal);
                    read[properties.Name] = new Snapshot(properties.Version, properties.UpdatedOn, key, secret.Value.Value);
                }).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (failure is not null && !cancellationToken.IsCancellationRequested)
        {
            // Cancelamento provocado pela primeira falha: tratado abaixo
        }

        if (failure is not null)
            return new LoadOutcome(null, null, failure);

        foreach (var (name, item) in read)
            snapshot[name] = item;

        var data = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in snapshot.Values)
            data[item.Key] = item.Value;

        VaultLog.ConfigurationLoaded(_logger, _store.ProviderName, data.Count, read.Count, (long)Stopwatch.GetElapsedTime(start).TotalMilliseconds);
        return new LoadOutcome(data, snapshot, string.Empty);
    }

    /// <summary>
    /// Inalterado se a versão listada é a mesma (versão identifica o valor) ou, quando o provedor não informa a versão na
    /// listagem, se a data de atualização é a mesma. Sem nenhuma das duas, relê sempre.
    /// </summary>
    private static bool IsUnchanged(SecretProperties properties, Snapshot known) =>
        properties.Version is not null
            ? string.Equals(properties.Version, known.Version, StringComparison.OrdinalIgnoreCase)
            : properties.UpdatedOn is not null && properties.UpdatedOn == known.UpdatedOn;

    private bool HasSameData(Dictionary<string, string?> data) =>
        data.Count == Data.Count && data.All(kv => Data.TryGetValue(kv.Key, out var value) && string.Equals(value, kv.Value, StringComparison.Ordinal));

    public void Dispose() => _timer?.Dispose();
}

/// <summary>Registro do cofre como fonte de configuração.</summary>
public static class VaultConfigurationBuilderExtensions
{
    /// <summary>
    /// Adiciona os segredos do cofre à configuração (<c>IConfiguration</c>), com precedência sobre as fontes adicionadas antes.
    /// </summary>
    /// <remarks>
    /// Os valores ficam em memória no <c>IConfiguration</c> durante toda a vida da aplicação. Para segredos de alto valor,
    /// prefira ler sob demanda com <see cref="ISecretReader"/>. A carga falha se o filtro encontrar mais de
    /// <see cref="VaultConfigurationOptions.MaxSecrets"/> segredos ou se passar de <see cref="VaultConfigurationOptions.LoadTimeout"/>.
    /// O <c>IConfiguration</c> é montado antes do container de DI: informe <paramref name="loggerFactory"/> para que as falhas
    /// de carga e recarga sejam registradas (sem ele, só a exceção da carga inicial informa o motivo).
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Configuration.AddTecVault(secretStore, o => { o.Prefix = "MinhaApi--"; o.ReloadInterval = TimeSpan.FromMinutes(30); },
    ///     loggerFactory: LoggerFactory.Create(l => l.AddConsole()));
    /// </code>
    /// </example>
    public static IConfigurationBuilder AddTecVault(this IConfigurationBuilder builder, ISecretReader store,
        Action<VaultConfigurationOptions>? configure = null, TimeProvider? timeProvider = null, ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(store);

        var options = new VaultConfigurationOptions();
        configure?.Invoke(options);
        return builder.Add(new VaultConfigurationSource(store, options, timeProvider ?? TimeProvider.System, loggerFactory));
    }
}

/// <summary>Fonte de configuração com o provedor de segredos escolhido pela configuração.</summary>
public static class VaultConfigurationSelectionExtensions
{
    /// <summary>
    /// Adiciona os segredos do cofre à configuração, escolhendo o provedor pela seção <paramref name="vaultSection"/>
    /// (<c>Secrets:Provider</c> ou <c>Provider</c>, como em <c>IServiceCollection.AddTecVault(IConfiguration, ...)</c>). As opções da
    /// fonte vêm de <c>Configuration</c> na mesma seção (<c>Prefix</c>, <c>SectionSeparator</c>, <c>ReloadInterval</c>,
    /// <c>Optional</c>, <c>MaxSecrets</c>, <c>LoadTimeout</c>, <c>MaxConcurrentReads</c>) e <paramref name="configure"/> roda depois delas.
    /// </summary>
    /// <remarks>
    /// <paramref name="vaultSection"/> normalmente vem do próprio <paramref name="builder"/> (fontes adicionadas antes, como o
    /// <c>appsettings.json</c>): os segredos carregados aqui não influenciam a escolha do provedor. Veja também
    /// <see cref="VaultConfigurationBuilderExtensions.AddTecVault"/>.
    /// </remarks>
    /// <example>
    /// <code>
    /// builder.Configuration.AddTecVault(builder.Configuration.GetSection("Vault"), p => p.AddAzureKeyVault().AddSynced(),
    ///     loggerFactory: LoggerFactory.Create(l => l.AddConsole()));
    /// </code>
    /// </example>
    /// <exception cref="InvalidOperationException">Configuração inválida, nenhum provedor de segredos escolhido, ou provedor que não pode ser fonte de configuração.</exception>
    public static IConfigurationBuilder AddTecVault(this IConfigurationBuilder builder, IConfiguration vaultSection,
        Action<DependencyInjection.VaultProviderCatalog> providers, Action<VaultConfigurationOptions>? configure = null,
        ILoggerFactory? loggerFactory = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(vaultSection);
        ArgumentNullException.ThrowIfNull(providers);

        var catalog = DependencyInjection.VaultProviderCatalog.Create(providers);
        var selection = DependencyInjection.VaultProviderSelection.Resolve(new DependencyInjection.VaultSettings(vaultSection), catalog);
        var root = selection.Root;

        var provider = selection.SecretsProvider
            ?? throw new InvalidOperationException("Nenhum provedor de segredos escolhido (Vault:Secrets:Provider ou Vault:Provider).");
        if (provider.CreateSecretReader is null)
            throw new InvalidOperationException($"O provedor '{provider.Name}' não pode ser usado como fonte de configuração.");

        var options = ReadOptions(root.GetSection(DependencyInjection.VaultProviderSelection.ConfigurationKey));
        configure?.Invoke(options);

        // Outras famílias e o cache só valem no container: aqui são aceitas sem validar o conteúdo
        foreach (var group in selection.Groups.Where(g => g.Provider != provider))
            root.Ignore(group.Provider.Name);
        root.Ignore(DependencyInjection.VaultProviderSelection.CacheKey);

        var store = provider.CreateSecretReader(root.GetSection(provider.Name), loggerFactory);
        root.EnsureNoUnknownKeys();

        return builder.AddTecVault(store, o => Copy(options, o), loggerFactory: loggerFactory);
    }

    private static VaultConfigurationOptions ReadOptions(DependencyInjection.VaultSettings settings)
    {
        var options = new VaultConfigurationOptions();
        Set(settings, "Prefix", () => options.Prefix = settings.GetString("Prefix"));
        Set(settings, "SectionSeparator", () =>
        {
            if (settings.GetString("SectionSeparator") is { } separator)
                options.SectionSeparator = separator;
        });
        Set(settings, "ReloadInterval", () => options.ReloadInterval = settings.GetTimeSpan("ReloadInterval"));
        Set(settings, "Optional", () => options.Optional = settings.GetBoolean("Optional") ?? false);
        Set(settings, "MaxSecrets", () => options.MaxSecrets = settings.GetInt32("MaxSecrets", 1) ?? options.MaxSecrets);
        Set(settings, "LoadTimeout", () => options.LoadTimeout = settings.GetTimeSpan("LoadTimeout") ?? options.LoadTimeout);
        Set(settings, "MaxConcurrentReads", () => options.MaxConcurrentReads = settings.GetInt32("MaxConcurrentReads", 1, 16) ?? options.MaxConcurrentReads);
        return options;
    }

    private static void Set(DependencyInjection.VaultSettings settings, string key, Action apply)
    {
        try
        {
            apply();
        }
        catch (ArgumentException exception)
        {
            throw new InvalidOperationException($"Configuração inválida em {settings.Path}:{key}: {exception.Message}", exception);
        }
    }

    private static void Copy(VaultConfigurationOptions from, VaultConfigurationOptions to)
    {
        to.Prefix = from.Prefix;
        to.SectionSeparator = from.SectionSeparator;
        to.ReloadInterval = from.ReloadInterval;
        to.Optional = from.Optional;
        to.MaxSecrets = from.MaxSecrets;
        to.LoadTimeout = from.LoadTimeout;
        to.MaxConcurrentReads = from.MaxConcurrentReads;
    }
}
