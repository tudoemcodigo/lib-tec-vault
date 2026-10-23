using System.Security.Cryptography.X509Certificates;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Core.Common.Results;

namespace TEC.Vault.Abstractions;

/// <summary>Leitura de certificados X.509: parte pública, metadados e download com a chave privada (se exportável).</summary>
/// <remarks>Mesmas regras de <see cref="ISecretReader"/>: falhas viram <see cref="Result"/>.</remarks>
public interface ICertificateReader
{
    /// <summary>Nome do provedor.</summary>
    string ProviderName { get; }

    /// <summary>Lê a parte pública e os metadados do certificado.</summary>
    Task<Result<VaultCertificate>> GetCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Baixa o certificado <b>com a chave privada</b> (somente se criado/importado como exportável). Auditado em log.
    /// O chamador deve descartar (<c>Dispose</c>) o certificado. Prefira <see cref="IKeyCryptography"/> para assinar sem expor a chave.
    /// </summary>
    Task<Result<X509Certificate2>> DownloadCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default);

    /// <summary>Lista os metadados de todos os certificados.</summary>
    Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificatesAsync(CancellationToken cancellationToken = default);

    /// <summary>Lista os metadados de todas as versões de um certificado.</summary>
    Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificateVersionsAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Gestão de certificados: leitura (<see cref="ICertificateReader"/>) mais criação, importação, alteração e exclusão.</summary>
public interface ICertificateStore : ICertificateReader
{
    /// <summary>Cria o certificado (ou nova versão) e aguarda a emissão.</summary>
    Task<Result<VaultCertificate>> CreateCertificateAsync(string name, CreateCertificateOptions options,
        CancellationToken cancellationToken = default);

    /// <summary>Importa um certificado com chave privada (PFX ou PEM).</summary>
    Task<Result<VaultCertificate>> ImportCertificateAsync(string name, byte[] certificate, ImportCertificateOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>Altera os metadados da versão atual ou da informada.</summary>
    Task<Result<CertificateProperties>> UpdateCertificatePropertiesAsync(string name, CertificatePropertiesUpdate update,
        string? version = null, CancellationToken cancellationToken = default);

    /// <summary>Exclui o certificado (e o que o provedor associar a ele, ex.: chave e segredo) e aguarda a conclusão.</summary>
    Task<Result<DeletedVaultItem>> DeleteCertificateAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Lixeira de certificados (capacidade opcional).</summary>
public interface ICertificateRecycleBin
{
    /// <summary>Lista os certificados excluídos e ainda recuperáveis.</summary>
    Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedCertificatesAsync(CancellationToken cancellationToken = default);

    /// <summary>Recupera um certificado excluído e aguarda a conclusão.</summary>
    Task<Result<VaultCertificate>> RecoverDeletedCertificateAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Remove definitivamente um certificado excluído. <b>Irreversível.</b></summary>
    Task<Result> PurgeDeletedCertificateAsync(string name, CancellationToken cancellationToken = default);
}

/// <summary>Backup e restauração de certificados (capacidade opcional).</summary>
public interface ICertificateBackup
{
    /// <summary>Gera o backup protegido (opaco) do certificado.</summary>
    Task<Result<byte[]>> BackupCertificateAsync(string name, CancellationToken cancellationToken = default);

    /// <summary>Restaura um backup gerado por <see cref="BackupCertificateAsync"/>.</summary>
    Task<Result<VaultCertificate>> RestoreCertificateBackupAsync(byte[] backup, CancellationToken cancellationToken = default);
}
