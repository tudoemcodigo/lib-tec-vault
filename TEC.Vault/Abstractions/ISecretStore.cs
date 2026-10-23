using TEC.Vault.Common;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.Abstractions;

/// <summary>
/// Leitura de segredos (senhas, connection strings, tokens, chaves de API). Independente de provedor.
/// É o que a maioria das aplicações precisa: injete esta interface quando a aplicação só lê (menor privilégio).
/// </summary>
/// <remarks>
/// <para>Nenhum método lança exceção por falha do cofre: toda falha vira <see cref="Result"/> com os códigos de
/// <see cref="VaultErrors"/>. Cancelamento pelo <see cref="CancellationToken"/> continua lançando <see cref="OperationCanceledException"/>.</para>
/// <para>Todo provedor de segredos implementa esta interface. As demais (<see cref="ISecretStore"/>, <see cref="ISecretRecycleBin"/>,
/// <see cref="ISecretBackup"/>) são capacidades que o provedor pode ou não oferecer.</para>
/// </remarks>
public interface ISecretReader
{
    /// <summary>Nome do provedor (ex.: "AzureKeyVault").</summary>
    string ProviderName { get; }

    /// <summary>Lê o valor de um segredo (versão atual ou a informada).</summary>
    Task<Result<VaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default);

    /// <summary>Indica se o segredo existe (não excluído), consultando apenas metadados: o valor não é lido.</summary>
    Task<Result<bool>> ExistsAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Lista os metadados (sem valores) de todos os segredos.</summary>
    Task<Result<IReadOnlyList<SecretProperties>>> ListSecretsAsync(CancellationToken cancellationToken = default);

    /// <summary>Lista os metadados (sem valores) de todas as versões de um segredo.</summary>
    Task<Result<IReadOnlyList<SecretProperties>>> ListSecretVersionsAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Gestão de segredos: leitura (<see cref="ISecretReader"/>) mais gravação, alteração de metadados e exclusão.</summary>
/// <remarks>
/// Exclusão: se o provedor tiver lixeira (<see cref="ISecretRecycleBin"/>), ela é lógica e recuperável até a remoção definitiva;
/// sem lixeira, a semântica é a do provedor (documentada nele).
/// </remarks>
public interface ISecretStore : ISecretReader
{
    /// <summary>Grava o segredo, criando-o ou gerando uma nova versão.</summary>
    Task<Result<SecretProperties>> SetSecretAsync(string name, string value, SecretWriteOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>Altera os metadados (habilitado, validade, tipo, tags) da versão atual ou da informada, sem alterar o valor.</summary>
    Task<Result<SecretProperties>> UpdateSecretPropertiesAsync(string name, SecretPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default);

    /// <summary>Exclui o segredo (todas as versões) e aguarda a conclusão.</summary>
    Task<Result<DeletedVaultItem>> DeleteSecretAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Lixeira de segredos (capacidade opcional): itens excluídos ainda recuperáveis.</summary>
public interface ISecretRecycleBin
{
    /// <summary>Lista os segredos excluídos e ainda recuperáveis.</summary>
    Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedSecretsAsync(CancellationToken cancellationToken = default);

    /// <summary>Recupera um segredo excluído e aguarda a conclusão.</summary>
    Task<Result<SecretProperties>> RecoverDeletedSecretAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Remove definitivamente um segredo excluído. <b>Irreversível.</b></summary>
    Task<Result> PurgeDeletedSecretAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Backup e restauração de segredos (capacidade opcional).</summary>
public interface ISecretBackup
{
    /// <summary>Gera o backup protegido (opaco, criptografado pelo provedor) do segredo, com todas as versões.</summary>
    Task<Result<byte[]>> BackupSecretAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Restaura um backup gerado por <see cref="BackupSecretAsync"/>. O nome não pode existir no cofre.</summary>
    Task<Result<SecretProperties>> RestoreSecretBackupAsync(byte[] backup, CancellationToken cancellationToken = default);
}
