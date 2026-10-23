namespace TEC.Vault.Providers;

/// <summary>
/// Escolha da versão atual de um item a partir da listagem de versões (uso pelos provedores e pelas extensões): a atual é a
/// de maior data de criação. Os cofres costumam ter resolução de 1 segundo, então pode haver empate.
/// </summary>
public static class VaultVersionRules
{
    /// <summary>Versões com a maior data de criação (mais de uma = empate no mesmo instante; nenhuma = lista vazia).</summary>
    public static List<T> Newest<T>(IEnumerable<T> versions, Func<T, DateTimeOffset?> createdOn)
    {
        ArgumentNullException.ThrowIfNull(versions);
        ArgumentNullException.ThrowIfNull(createdOn);
        var list = versions as IReadOnlyCollection<T> ?? [.. versions];
        var max = list.Max(createdOn);
        return [.. list.Where(v => createdOn(v) == max)];
    }

    /// <summary>
    /// Desempate determinístico pelos metadados, para quando o cofre não pode dizer qual é a atual (ex.: versão atual
    /// desabilitada): a de maior data de atualização e, persistindo o empate, a de maior identificador de versão (ordinal).
    /// </summary>
    public static T BreakTie<T>(IEnumerable<T> newest, Func<T, DateTimeOffset?> updatedOn, Func<T, string?> version)
    {
        ArgumentNullException.ThrowIfNull(newest);
        ArgumentNullException.ThrowIfNull(updatedOn);
        ArgumentNullException.ThrowIfNull(version);
        return newest.OrderByDescending(updatedOn).ThenByDescending(version, StringComparer.Ordinal).First();
    }
}
