using TEC.Vault.Common;
using TEC.Vault.Keys;
using TEC.Core.Common.Results;

namespace TEC.Vault.Abstractions;

/// <summary>Leitura de chaves criptográficas: parte pública e metadados. A parte privada nunca é retornada.</summary>
/// <remarks>Mesmas regras de <see cref="ISecretReader"/>: falhas viram <see cref="Result"/>.</remarks>
public interface IKeyReader
{
    /// <summary>Nome do provedor.</summary>
    string ProviderName { get; }

    /// <summary>Lê a chave (parte pública e metadados).</summary>
    Task<Result<VaultKey>> GetKeyAsync(string name, string? version = null, CancellationToken cancellationToken = default);

    /// <summary>Lista os metadados de todas as chaves.</summary>
    Task<Result<IReadOnlyList<KeyProperties>>> ListKeysAsync(CancellationToken cancellationToken = default);

    /// <summary>Lista os metadados de todas as versões de uma chave.</summary>
    Task<Result<IReadOnlyList<KeyProperties>>> ListKeyVersionsAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Gestão de chaves: leitura (<see cref="IKeyReader"/>) mais criação, alteração, rotação e exclusão.</summary>
/// <remarks>O uso das chaves (criptografar, assinar...) fica em <see cref="IKeyCryptography"/>.</remarks>
public interface IKeyStore : IKeyReader
{
    /// <summary>Cria a chave ou uma nova versão dela.</summary>
    Task<Result<VaultKey>> CreateKeyAsync(string name, CreateKeyOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Altera os metadados da versão atual ou da informada.</summary>
    Task<Result<VaultKey>> UpdateKeyPropertiesAsync(string name, KeyPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default);

    /// <summary>Gera uma nova versão da chave com os mesmos parâmetros (rotação).</summary>
    Task<Result<VaultKey>> RotateKeyAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Exclui a chave e aguarda a conclusão.</summary>
    Task<Result<DeletedVaultItem>> DeleteKeyAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>
/// Uso das chaves sem que a parte privada saia do cofre: criptografia, proteção de chaves (wrap) e assinatura.
/// Injete esta interface quando a aplicação só usa chaves (menor privilégio: não exige permissão de gestão).
/// </summary>
/// <remarks>Mesmas regras de <see cref="ISecretReader"/>: falhas viram <see cref="Result"/>.</remarks>
public interface IKeyCryptography
{
    /// <summary>Nome do provedor.</summary>
    string ProviderName { get; }

    /// <summary>Criptografa dados pequenos (limite do RSA-OAEP-256: 190 bytes para RSA 2048). Para dados maiores use criptografia envelope.</summary>
    Task<Result<VaultEncryptResult>> EncryptAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default);

    /// <summary>Descriptografa com a versão informada (a mesma usada na criptografia).</summary>
    Task<Result<byte[]>> DecryptAsync(string name, string version, byte[] ciphertext,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default);

    /// <summary>Protege (wrap) uma chave simétrica.</summary>
    Task<Result<VaultEncryptResult>> WrapKeyAsync(string name, byte[] key, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default);

    /// <summary>Recupera (unwrap) uma chave simétrica com a versão informada.</summary>
    Task<Result<byte[]>> UnwrapKeyAsync(string name, string version, byte[] wrappedKey,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default);

    /// <summary>Assina os dados (o hash é calculado localmente; a assinatura, no cofre).</summary>
    Task<Result<VaultSignResult>> SignDataAsync(string name, byte[] data, VaultSignatureAlgorithm algorithm,
        string? version = null, CancellationToken cancellationToken = default);

    /// <summary>Verifica a assinatura com a versão informada. Assinatura inválida é sucesso com <c>false</c>.</summary>
    Task<Result<bool>> VerifyDataAsync(string name, string version, byte[] data, byte[] signature, VaultSignatureAlgorithm algorithm,
        CancellationToken cancellationToken = default);
}

/// <summary>Lixeira de chaves (capacidade opcional).</summary>
public interface IKeyRecycleBin
{
    /// <summary>Lista as chaves excluídas e ainda recuperáveis.</summary>
    Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedKeysAsync(CancellationToken cancellationToken = default);

    /// <summary>Recupera uma chave excluída e aguarda a conclusão.</summary>
    Task<Result<VaultKey>> RecoverDeletedKeyAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Remove definitivamente uma chave excluída. <b>Irreversível: tudo o que foi cifrado com ela fica ilegível.</b></summary>
    Task<Result> PurgeDeletedKeyAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Backup e restauração de chaves (capacidade opcional).</summary>
public interface IKeyBackup
{
    /// <summary>Gera o backup protegido (opaco) da chave.</summary>
    Task<Result<byte[]>> BackupKeyAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Restaura um backup gerado por <see cref="BackupKeyAsync"/>.</summary>
    Task<Result<VaultKey>> RestoreKeyBackupAsync(byte[] backup, CancellationToken cancellationToken = default);
}
