using System.Diagnostics;
using System.Globalization;
using System.Text;
using TEC.Core.Common.Results;

namespace TEC.Vault.LoadGenerator;

/// <summary>Cenário de carga: uma operação no cofre e o critério de sucesso.</summary>
/// <param name="Name">Nome exibido no relatório.</param>
/// <param name="Weight">Peso relativo na mistura de operações (0 desliga o cenário).</param>
/// <param name="Execute">
/// Executa uma operação (o <see cref="Random"/> é exclusivo do worker). Devolve <c>null</c> em caso de sucesso ou o tipo do erro
/// (ex.: o código de <see cref="Error"/>), que vai para o relatório agrupado.
/// </param>
public sealed record LoadScenario(string Name, int Weight, Func<Random, CancellationToken, Task<string?>> Execute)
{
    /// <summary>Cenário a partir de uma operação que devolve <see cref="Result"/>: sucesso ou o código do erro.</summary>
    public static LoadScenario FromResult(string name, int weight, Func<Random, CancellationToken, Task<Result>> operation) =>
        new(name, weight, async (random, ct) => (await operation(random, ct).ConfigureAwait(false)).Error?.Code);

    /// <inheritdoc cref="FromResult(string, int, Func{Random, CancellationToken, Task{Result}})"/>
    public static LoadScenario FromResult<T>(string name, int weight, Func<Random, CancellationToken, Task<Result<T>>> operation) =>
        new(name, weight, async (random, ct) => (await operation(random, ct).ConfigureAwait(false)).Error?.Code);
}

/// <summary>Configuração de uma execução de carga.</summary>
public sealed record LoadOptions
{
    /// <summary>Operações em paralelo (workers).</summary>
    public int Concurrency { get; init; } = 32;

    /// <summary>Duração da medição (sem contar o aquecimento).</summary>
    public TimeSpan Duration { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Aquecimento: operações feitas mas fora das estatísticas (JIT, pools de conexão, caches).</summary>
    public TimeSpan WarmUp { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Semente dos sorteios (cenários e dados), para execuções reproduzíveis.</summary>
    public int Seed { get; init; } = 2026;

    /// <summary>
    /// Limite de operações por segundo somando todos os workers (<c>null</c> = sem limite, malha fechada pura). Use contra o
    /// cofre real: o Key Vault limita as operações por cofre e devolveria 429.
    /// </summary>
    public double? MaxOperationsPerSecond { get; init; }

    /// <summary>Cenários e pesos.</summary>
    public required IReadOnlyList<LoadScenario> Scenarios { get; init; }
}

/// <summary>Estatísticas de latência (milissegundos).</summary>
public sealed record LatencyStats(double Mean, double P50, double P95, double P99, double Max)
{
    internal static LatencyStats From(List<double> samples)
    {
        if (samples.Count == 0)
            return new LatencyStats(0, 0, 0, 0, 0);

        samples.Sort();
        return new LatencyStats(samples.Average(), Percentile(samples, 0.50), Percentile(samples, 0.95), Percentile(samples, 0.99), samples[^1]);
    }

    // Nearest-rank: o menor valor que cobre a fração pedida das amostras
    private static double Percentile(List<double> sorted, double fraction) =>
        sorted[Math.Clamp((int)Math.Ceiling(fraction * sorted.Count) - 1, 0, sorted.Count - 1)];
}

/// <summary>Resultado de um cenário.</summary>
public sealed record ScenarioReport(string Name, long Operations, long Errors, LatencyStats Latency);

/// <summary>Resultado da execução.</summary>
public sealed record LoadReport(
    TimeSpan Duration,
    int Concurrency,
    long Operations,
    long Errors,
    LatencyStats Latency,
    IReadOnlyList<ScenarioReport> Scenarios,
    IReadOnlyDictionary<string, long> ErrorsByKind)
{
    /// <summary>Operações por segundo na janela medida.</summary>
    public double OperationsPerSecond => Duration.TotalSeconds > 0 ? Operations / Duration.TotalSeconds : 0;

    /// <summary>Fração de operações com erro (0 a 1).</summary>
    public double ErrorRate => Operations > 0 ? (double)Errors / Operations : 0;

    /// <summary>Cenário pelo nome.</summary>
    public ScenarioReport Scenario(string name) => Scenarios.Single(s => s.Name == name);

    /// <summary>Relatório em texto (console, saída de teste e resumo do CI).</summary>
    public string ToText()
    {
        var ci = CultureInfo.InvariantCulture;
        var text = new StringBuilder();
        text.AppendLine(ci, $"Duração: {Duration.TotalSeconds:F1} s · concorrência: {Concurrency} · operações: {Operations} · ops/s: {OperationsPerSecond:F0} · erros: {Errors} ({ErrorRate:P2})");
        text.AppendLine(ci, $"Latência (ms): média {Latency.Mean:F2} · p50 {Latency.P50:F2} · p95 {Latency.P95:F2} · p99 {Latency.P99:F2} · máx {Latency.Max:F2}");
        text.AppendLine("| Cenário | Operações | Erros | p50 (ms) | p95 (ms) | p99 (ms) | máx (ms) |");
        text.AppendLine("|---|---:|---:|---:|---:|---:|---:|");
        foreach (var s in Scenarios)
            text.AppendLine(ci, $"| {s.Name} | {s.Operations} | {s.Errors} | {s.Latency.P50:F2} | {s.Latency.P95:F2} | {s.Latency.P99:F2} | {s.Latency.Max:F2} |");
        foreach (var (kind, count) in ErrorsByKind.OrderByDescending(e => e.Value))
            text.AppendLine(ci, $"Erro '{kind}': {count}");
        return text.ToString();
    }
}

/// <summary>
/// Gerador de carga em malha fechada: cada worker executa uma operação, espera o resultado e executa a próxima (com
/// <see cref="LoadOptions.MaxOperationsPerSecond"/>, cada worker também respeita o seu intervalo mínimo entre operações).
/// </summary>
public static class LoadRunner
{
    /// <summary>Executa a carga e devolve as estatísticas da janela medida (após o aquecimento).</summary>
    /// <param name="options">Configuração da execução.</param>
    /// <param name="cancellationToken">Interrompe a execução (o relatório parcial é devolvido).</param>
    public static async Task<LoadReport> RunAsync(LoadOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentOutOfRangeException.ThrowIfLessThan(options.Concurrency, 1);
        if (options.MaxOperationsPerSecond is <= 0)
            throw new ArgumentOutOfRangeException(nameof(options), "MaxOperationsPerSecond deve ser maior que zero.");

        var scenarios = options.Scenarios.Where(s => s.Weight > 0).ToArray();
        if (scenarios.Length == 0)
            throw new ArgumentException("Informe ao menos um cenário com peso maior que zero.", nameof(options));

        int[] cumulative = new int[scenarios.Length];
        for (int i = 0, sum = 0; i < scenarios.Length; i++)
            cumulative[i] = sum += scenarios[i].Weight;

        // Ritmo por worker: o limite global dividido igualmente entre os workers
        TimeSpan pace = options.MaxOperationsPerSecond is { } rate
            ? TimeSpan.FromSeconds(options.Concurrency / rate)
            : TimeSpan.Zero;

        long start = Stopwatch.GetTimestamp();
        long measureFrom = start + (long)(options.WarmUp.TotalSeconds * Stopwatch.Frequency);
        long stopAt = measureFrom + (long)(options.Duration.TotalSeconds * Stopwatch.Frequency);

        var workers = Enumerable.Range(0, options.Concurrency)
            .Select(id => Task.Run(() => RunWorkerAsync(scenarios, cumulative, new Random(options.Seed + id), pace, measureFrom, stopAt, cancellationToken)))
            .ToArray();
        var results = await Task.WhenAll(workers).ConfigureAwait(false);

        double measured = Stopwatch.GetElapsedTime(measureFrom, Math.Min(Stopwatch.GetTimestamp(), stopAt)).TotalSeconds;
        return BuildReport(scenarios, results, TimeSpan.FromSeconds(Math.Max(measured, 0)), options.Concurrency);
    }

    private static async Task<WorkerResult> RunWorkerAsync(LoadScenario[] scenarios, int[] cumulative, Random random, TimeSpan pace,
        long measureFrom, long stopAt, CancellationToken cancellationToken)
    {
        var result = new WorkerResult(scenarios.Length);
        for (long iteration = 1; !cancellationToken.IsCancellationRequested; iteration++)
        {
            // Operações que terminam de forma síncrona (acerto no cache, provedor em memória) nunca devolvem a thread: sem
            // ceder de tempos em tempos, poucos workers monopolizariam o pool e os demais esperariam segundos para começar
            if (iteration % 64 == 0)
                await Task.Yield();

            long begin = Stopwatch.GetTimestamp();
            if (begin >= stopAt)
                break;

            int index = Array.BinarySearch(cumulative, random.Next(cumulative[^1]) + 1);
            if (index < 0)
                index = ~index;
            var scenario = scenarios[index];

            string? error;
            try
            {
                error = await scenario.Execute(random, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                // Os provedores devolvem Result: exceção aqui já é um defeito, contado à parte pelo tipo
                error = "exceção " + ex.GetType().Name;
            }

            long end = Stopwatch.GetTimestamp();
            if (begin >= measureFrom && end <= stopAt)
                result.Record(index, Stopwatch.GetElapsedTime(begin, end).TotalMilliseconds, error);

            if (pace > TimeSpan.Zero)
            {
                var wait = pace - Stopwatch.GetElapsedTime(begin, end);
                if (wait > TimeSpan.Zero)
                {
                    try
                    {
                        await Task.Delay(wait, cancellationToken).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }
            }
        }

        return result;
    }

    private static LoadReport BuildReport(LoadScenario[] scenarios, WorkerResult[] results, TimeSpan duration, int concurrency)
    {
        var perScenario = new List<ScenarioReport>();
        for (int i = 0; i < scenarios.Length; i++)
        {
            int index = i;
            perScenario.Add(new ScenarioReport(scenarios[i].Name, results.Sum(r => r.Count[index]), results.Sum(r => r.Errors[index]),
                Stats(results.Select(r => r.Scenario(index)))));
        }

        var errorsByKind = results.SelectMany(r => r.ErrorsByKind)
            .GroupBy(e => e.Key)
            .ToDictionary(g => g.Key, g => g.Sum(e => e.Value));

        return new LoadReport(duration, concurrency, perScenario.Sum(s => s.Operations), perScenario.Sum(s => s.Errors),
            Stats(results.SelectMany(r => Enumerable.Range(0, scenarios.Length).Select(r.Scenario))), perScenario, errorsByKind);
    }

    // Média e máximo exatos; percentis sobre as amostras guardadas (todas, ou o reservatório quando passou do limite)
    private static LatencyStats Stats(IEnumerable<(long Count, double Sum, double Max, List<double> Samples)> parts)
    {
        var list = parts.ToList();
        long count = list.Sum(p => p.Count);
        var percentiles = LatencyStats.From([.. list.SelectMany(p => p.Samples)]);
        return count == 0
            ? percentiles
            : percentiles with { Mean = list.Sum(p => p.Sum) / count, Max = list.Max(p => p.Max) };
    }

    /// <summary>Amostras de latência guardadas por cenário e por worker (acima disso, amostragem por reservatório).</summary>
    internal const int MaxSamplesPerWorker = 50_000;

    // Estado de um worker: sem compartilhamento entre threads (só é lido no fim). Operações síncronas (cache, em memória) passam
    // de milhões por segundo: guardar toda amostra consumiria centenas de MB e distorceria o próprio processo medido
    private sealed class WorkerResult(int scenarioCount)
    {
        private readonly Random _sampling = new(scenarioCount);

        public List<double>[] Latencies { get; } = [.. Enumerable.Range(0, scenarioCount).Select(_ => new List<double>())];
        public long[] Count { get; } = new long[scenarioCount];
        public double[] Sum { get; } = new double[scenarioCount];
        public double[] Max { get; } = new double[scenarioCount];
        public long[] Errors { get; } = new long[scenarioCount];
        public Dictionary<string, long> ErrorsByKind { get; } = [];

        public (long Count, double Sum, double Max, List<double> Samples) Scenario(int index) =>
            (Count[index], Sum[index], Max[index], Latencies[index]);

        public void Record(int scenario, double milliseconds, string? error)
        {
            long seen = ++Count[scenario];
            Sum[scenario] += milliseconds;
            Max[scenario] = Math.Max(Max[scenario], milliseconds);

            // Algoritmo R: cada amostra tem a mesma chance de ficar no reservatório
            var samples = Latencies[scenario];
            if (samples.Count < MaxSamplesPerWorker)
                samples.Add(milliseconds);
            else if (_sampling.NextInt64(seen) is var slot && slot < MaxSamplesPerWorker)
                samples[(int)slot] = milliseconds;

            if (error is null)
                return;

            Errors[scenario]++;
            ErrorsByKind[error] = ErrorsByKind.GetValueOrDefault(error) + 1;
        }
    }
}
