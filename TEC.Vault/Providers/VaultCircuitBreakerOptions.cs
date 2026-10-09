using TEC.Vault.DependencyInjection;

namespace TEC.Vault.Providers;

/// <summary>
/// Circuit breaker de um provedor de cofre: com o cofre fora do ar, as chamadas seguintes falham na hora com
/// <see cref="Common.VaultErrors.CircuitOpen"/>, sem esperar timeout e retentativas a cada uma.
/// </summary>
/// <remarks>
/// <para>Só contam como falha <see cref="Common.VaultErrors.Unavailable"/> e <see cref="Common.VaultErrors.Throttled"/> (rede, timeout,
/// 5xx, limite de requisições), já depois das retentativas do provedor. Item inexistente, acesso negado ou entrada inválida
/// não abrem o circuito.</para>
/// <para>O circuito abre quando, dentro de <see cref="SamplingDuration"/>, houve pelo menos <see cref="MinimumThroughput"/> chamadas
/// e a proporção de falhas chegou a <see cref="FailureRatio"/>. Fica aberto por <see cref="BreakDuration"/>; depois deixa passar
/// uma chamada de teste (meia-abertura): sucesso fecha o circuito, falha abre de novo.</para>
/// </remarks>
public sealed class VaultCircuitBreakerOptions
{
    /// <summary>Liga o circuit breaker. Padrão: <c>true</c>.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Proporção de falhas que abre o circuito (maior que 0, até 1). Padrão: 0,5.</summary>
    public double FailureRatio { get; set; } = 0.5;

    /// <summary>Mínimo de chamadas na janela para avaliar a proporção (2 a 10.000). Padrão: 10.</summary>
    public int MinimumThroughput { get; set; } = 10;

    /// <summary>Janela de amostragem (0,5 segundo a 1 hora). Padrão: 30 segundos.</summary>
    public TimeSpan SamplingDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Tempo com o circuito aberto antes da chamada de teste (0,5 segundo a 1 hora). Padrão: 30 segundos.</summary>
    public TimeSpan BreakDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Confere os limites.</summary>
    /// <param name="optionPrefix">Prefixo do nome da opção nas mensagens (ex.: "AzureKeyVaultOptions.CircuitBreaker").</param>
    /// <exception cref="InvalidOperationException">Valor fora do limite.</exception>
    public void Validate(string optionPrefix)
    {
        if (Enabled)
            ValidateValues(optionPrefix);
    }

    internal void ValidateValues(string optionPrefix)
    {
        if (double.IsNaN(FailureRatio) || FailureRatio is <= 0 or > 1)
            throw new InvalidOperationException($"{optionPrefix}.FailureRatio deve ser maior que 0 e no máximo 1.");
        if (MinimumThroughput is < 2 or > 10_000)
            throw new InvalidOperationException($"{optionPrefix}.MinimumThroughput deve estar entre 2 e 10.000.");
        if (SamplingDuration < TimeSpan.FromMilliseconds(500) || SamplingDuration > TimeSpan.FromHours(1))
            throw new InvalidOperationException($"{optionPrefix}.SamplingDuration deve estar entre 0,5 segundo e 1 hora.");
        if (BreakDuration < TimeSpan.FromMilliseconds(500) || BreakDuration > TimeSpan.FromHours(1))
            throw new InvalidOperationException($"{optionPrefix}.BreakDuration deve estar entre 0,5 segundo e 1 hora.");
    }

    /// <summary>
    /// Lê a subseção <c>CircuitBreaker</c> (chaves <c>Enabled</c>, <c>FailureRatio</c>, <c>MinimumThroughput</c>,
    /// <c>SamplingDuration</c> e <c>BreakDuration</c>) sobre os valores atuais (uso pelos provedores no registro por configuração).
    /// </summary>
    /// <param name="settings">Seção do provedor.</param>
    public void Read(VaultSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var section = settings.GetSection("CircuitBreaker");
        Enabled = section.GetBoolean("Enabled") ?? Enabled;
        FailureRatio = section.GetDouble("FailureRatio", 0, 1) ?? FailureRatio;
        MinimumThroughput = section.GetInt32("MinimumThroughput", 2, 10_000) ?? MinimumThroughput;
        SamplingDuration = section.GetTimeSpan("SamplingDuration") ?? SamplingDuration;
        BreakDuration = section.GetTimeSpan("BreakDuration") ?? BreakDuration;
    }
}
