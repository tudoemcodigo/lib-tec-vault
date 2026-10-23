namespace TEC.Vault.LoadTests;

/// <summary>
/// Categorias dos testes de carga (convenção dos componentes TEC), selecionadas pelo CI com
/// <c>--treenode-filter "/*/*/*/*[Category=...]"</c>.
/// </summary>
internal static class TestCategories
{
    /// <summary>Concorrência e fumaça de carga, em segundos: roda em todo pull request.</summary>
    public const string LoadCi = "Carga-CI";

    /// <summary>Medições longas (vazão, latência, memória): <c>performance.yml</c> (semanal/manual) e release.</summary>
    public const string LoadHeavy = "Carga-Pesada";
}
