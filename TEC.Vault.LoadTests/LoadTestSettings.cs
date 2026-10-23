using System.Globalization;
using TEC.Vault.LoadGenerator;
using TEC.Vault.Tests.Integration;

namespace TEC.Vault.LoadTests;

/// <summary>Duração das execuções, cofre de testes real e relatórios para o CI.</summary>
/// <remarks>
/// Não há variável liga/desliga: a seleção é pela categoria (<see cref="TestCategories.LoadCi"/> em todo pull request,
/// <see cref="TestCategories.LoadHeavy"/> no <c>performance.yml</c> e na release).
/// </remarks>
internal static class LoadTestSettings
{
    /// <summary>Variável com o fator de duração (ex.: <c>3</c> triplica cada medição; padrão 1).</summary>
    public const string DurationFactorVariable = "TEC_CARGA_FATOR";

    /// <summary>Pasta onde cada suíte grava o seu relatório Markdown; o CI publica os <c>*.md</c> no resumo da execução.</summary>
    public const string ReportsFolderVariable = "TEC_CARGA_RELATORIOS";

    /// <summary>Nome do arquivo de relatório desta suíte, dentro de <see cref="ReportsFolderVariable"/>.</summary>
    public const string ReportFileName = "TEC.Vault.LoadTests.md";

    /// <summary>Fator de <see cref="DurationFactorVariable"/> (maior que zero; padrão 1).</summary>
    public static double DurationFactor =>
        double.TryParse(Environment.GetEnvironmentVariable(DurationFactorVariable), NumberStyles.Float, CultureInfo.InvariantCulture, out var factor) && factor > 0
            ? factor
            : 1;

    /// <summary>Duração da medição multiplicada por <see cref="DurationFactor"/>.</summary>
    public static TimeSpan Duration(double seconds) => TimeSpan.FromSeconds(seconds * DurationFactor);

    /// <summary>Cofre de testes real (<c>TEC_TESTES_VAULT_URI</c>), ou pula o teste com o motivo.</summary>
    public static Uri RequireVault()
    {
        var uri = TestSettings.VaultUri(out string reason);
        Skip.When(uri is null, reason);
        return uri!;
    }

    /// <summary>Tenant do login no cofre de testes (opcional).</summary>
    public static string? TenantId => TestSettings.TenantId();

    /// <summary>Escreve o relatório na saída do teste e no arquivo da pasta de <see cref="ReportsFolderVariable"/>, quando definida.</summary>
    public static void Publish(string title, LoadReport report, string? extra = null)
    {
        string text = $"### {title} · {Runtime}\n\n{report.ToText()}{(extra is null ? string.Empty : extra + "\n")}\n";
        Console.WriteLine(text);
        Append(text);
    }

    /// <summary>Escreve uma medição avulsa (performance) na saída do teste e no relatório.</summary>
    public static void Publish(string title, string text)
    {
        string block = $"### {title} · {Runtime}\n\n{text}\n\n";
        Console.WriteLine(block);
        Append(block);
    }

    private static string Runtime => System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;

    private static readonly object ReportLock = new();

    private static void Append(string text)
    {
        if (Environment.GetEnvironmentVariable(ReportsFolderVariable) is not { Length: > 0 } folder)
            return;

        lock (ReportLock)
        {
            Directory.CreateDirectory(folder);
            File.AppendAllText(Path.Combine(folder, ReportFileName), text);
        }
    }
}
