namespace TEC.Vault.DependencyInjection;

/// <summary>
/// Stores que um provedor registra no container (menor privilégio: registre só os que a aplicação usa).
/// O health check verifica exatamente os stores registrados, então a identidade só precisa das permissões correspondentes.
/// </summary>
[Flags]
public enum VaultStores
{
    /// <summary>Nenhum (inválido).</summary>
    None = 0,

    /// <summary>Segredos (<see cref="Abstractions.ISecretReader"/> e capacidades).</summary>
    Secrets = 1,

    /// <summary>Chaves (<see cref="Abstractions.IKeyReader"/>, <see cref="Abstractions.IKeyCryptography"/> e capacidades).</summary>
    Keys = 2,

    /// <summary>Certificados (<see cref="Abstractions.ICertificateReader"/> e capacidades).</summary>
    Certificates = 4,

    /// <summary>Todos.</summary>
    All = Secrets | Keys | Certificates
}
