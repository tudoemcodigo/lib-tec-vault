using TEC.Core.Common.Results;

namespace TEC.Vault.Abstractions;

/// <summary>Verificação de acesso ao cofre usada pelo health check. Não lê valores de segredos.</summary>
public interface IVaultHealthProbe
{
    /// <summary>Verifica se o cofre responde e se a identidade da aplicação está autorizada.</summary>
    Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default);
}
