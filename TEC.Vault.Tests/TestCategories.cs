namespace TEC.Vault.Tests;

/// <summary>
/// Categorias dos testes (convenção dos componentes TEC). A seleção no CI é sempre por categoria:
/// unitários com <c>/*/*/*/*[Category!=Integracao]</c> e integração com <c>/*/*/*/*[Category=Integracao]</c>.
/// </summary>
internal static class TestCategories
{
    /// <summary>Dependência real (Key Vault de testes, HashiCorp Vault em container). Sem o serviço, o teste se pula com o motivo.</summary>
    public const string Integration = "Integracao";
}
