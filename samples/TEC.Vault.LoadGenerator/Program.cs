using System.Globalization;
using TEC.Vault.LoadGenerator;

// Gerador de carga do TEC.Vault (opções em samples/README.md). Exemplos:
//   dotnet run --project samples/TEC.Vault.LoadGenerator -f net10.0 -- --backend simulated --mix misto --cache 30
//   dotnet run --project samples/TEC.Vault.LoadGenerator -f net10.0 -- --backend azure --vault https://<cofre-de-testes>.vault.azure.net/ --rate 50

var arguments = ParseArguments(args);
if (arguments.ContainsKey("help") || arguments.ContainsKey("h"))
{
    Console.WriteLine("""
        Uso: TEC.Vault.LoadGenerator [opções]
          --backend inmemory|simulated|azure   provedor alvo (padrão: simulated)
          --mix leitura|escrita|cripto|misto    mistura de operações (padrão: misto)
          --concurrency N                       workers em paralelo (padrão: 32)
          --duration S                          segundos medidos (padrão: 30)
          --warmup S                            segundos de aquecimento (padrão: 5)
          --secrets N                           segredos semeados (padrão: 100)
          --cache S                             liga o cache de segredos por S segundos (padrão: desligado)
          --latency MS                          latência simulada por requisição (só simulated; padrão: 0)
          --faults F                            fração de requisições com 429 (só simulated; 0 a 1; padrão: 0)
          --rate N                              limite de operações/s (recomendado com azure)
          --vault URI                           cofre de TESTES (azure; padrão: TEC_TESTES_VAULT_URI)
          --tenant ID                           tenant do login (azure; padrão: TEC_TESTES_TENANT_ID)
        """);
    return 0;
}

var backend = Enum.Parse<VaultBackend>(Option("backend", "simulated"), ignoreCase: true);
string mix = Option("mix", "misto");
Uri? vaultUri = backend == VaultBackend.Azure
    ? new Uri(Option("vault", Environment.GetEnvironmentVariable("TEC_TESTES_VAULT_URI") ?? throw new InvalidOperationException(
        "Informe --vault ou TEC_TESTES_VAULT_URI (cofre exclusivo de testes).")))
    : null;

using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cancellation.Cancel();
};

await using var target = await VaultTarget.CreateAsync(backend, Number("secrets", 100), vaultUri,
    Option("tenant", Environment.GetEnvironmentVariable("TEC_TESTES_TENANT_ID") ?? string.Empty) is { Length: > 0 } tenant ? tenant : null,
    cancellation.Token);

if (arguments.TryGetValue("cache", out var cacheSeconds))
    target.EnableCache(TimeSpan.FromSeconds(double.Parse(cacheSeconds, CultureInfo.InvariantCulture)));
if (target.Simulated is { } simulated)
{
    simulated.Latency = TimeSpan.FromMilliseconds(Number("latency", 0));
    simulated.FaultRate = double.Parse(Option("faults", "0"), CultureInfo.InvariantCulture);
}

var options = new LoadOptions
{
    Concurrency = Number("concurrency", 32),
    Duration = TimeSpan.FromSeconds(Number("duration", 30)),
    WarmUp = TimeSpan.FromSeconds(Number("warmup", 5)),
    MaxOperationsPerSecond = arguments.TryGetValue("rate", out var rate) ? double.Parse(rate, CultureInfo.InvariantCulture) : null,
    Scenarios = VaultScenarios.Mix(mix, target)
};

Console.WriteLine($"Backend: {backend} · mistura: {mix} · cache: {(target.Cache is null ? "desligado" : "ligado")}");
var report = await LoadRunner.RunAsync(options, cancellation.Token);
Console.WriteLine(report.ToText());
if (target.Simulated is { } vault)
    Console.WriteLine($"Requisições ao cofre simulado: {vault.TotalRequests}");

return report.Errors == 0 ? 0 : 1;

string Option(string name, string fallback) => arguments.TryGetValue(name, out var value) ? value : fallback;

int Number(string name, int fallback) => int.Parse(Option(name, fallback.ToString(CultureInfo.InvariantCulture)), CultureInfo.InvariantCulture);

static Dictionary<string, string> ParseArguments(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (int i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith('-'))
            throw new ArgumentException($"Argumento inesperado: '{args[i]}'. Use --help.");
        string key = args[i].TrimStart('-');
        result[key] = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "true";
    }

    return result;
}
