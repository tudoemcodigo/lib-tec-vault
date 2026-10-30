using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TEC.Vault.Providers;

/// <summary>Carga segura de certificados (uso pelos provedores e pelos modelos).</summary>
/// <remarks>
/// Usa <c>X509CertificateLoader</c>, com os limites padrão contra PFX malicioso (iterações, tamanho, quantidade de itens):
/// <see cref="LoadCertificate"/> nunca aceita PFX/PKCS#7 e <see cref="LoadPkcs12"/> só aceita PKCS#12. Os provedores limitam o
/// tamanho do conteúdo antes da carga.
/// </remarks>
public static class VaultCertificateLoader
{
    /// <summary>
    /// Flags para carregar chave privada só em memória, sem gravar em disco: <see cref="X509KeyStorageFlags.EphemeralKeySet"/>
    /// no Windows e no Linux; <see cref="X509KeyStorageFlags.DefaultKeySet"/> no macOS, que não suporta chave efêmera
    /// (a chave pode ir para um keychain temporário).
    /// </summary>
    public static X509KeyStorageFlags SafeKeyStorageFlags =>
        OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;

    /// <summary>Carrega um certificado X.509 sem chave privada (DER ou PEM). Recusa PFX e PKCS#7.</summary>
    /// <exception cref="CryptographicException">Conteúdo que não é um certificado X.509.</exception>
    public static X509Certificate2 LoadCertificate(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return X509CertificateLoader.LoadCertificate(data);
    }

    /// <summary>Carrega um PKCS#12 (PFX) com a chave privada.</summary>
    /// <param name="data">Conteúdo PKCS#12.</param>
    /// <param name="password">Senha (<c>null</c> = sem senha).</param>
    /// <param name="keyStorageFlags">Flags de armazenamento. <c>null</c> = <see cref="SafeKeyStorageFlags"/>.</param>
    /// <exception cref="CryptographicException">Conteúdo que não é PKCS#12, senha incorreta ou limites excedidos.</exception>
    public static X509Certificate2 LoadPkcs12(byte[] data, string? password, X509KeyStorageFlags? keyStorageFlags = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        return X509CertificateLoader.LoadPkcs12(data, password, keyStorageFlags ?? SafeKeyStorageFlags);
    }

    /// <summary>
    /// Carrega todos os certificados de um PKCS#12 (PFX): o certificado com a chave privada e a cadeia (intermediárias) que vier junto.
    /// O chamador descarta cada certificado da coleção.
    /// </summary>
    /// <param name="data">Conteúdo PKCS#12.</param>
    /// <param name="password">Senha (<c>null</c> = sem senha).</param>
    /// <param name="keyStorageFlags">Flags de armazenamento. <c>null</c> = <see cref="SafeKeyStorageFlags"/>.</param>
    /// <exception cref="CryptographicException">Conteúdo que não é PKCS#12, senha incorreta ou limites excedidos.</exception>
    public static X509Certificate2Collection LoadPkcs12Collection(byte[] data, string? password, X509KeyStorageFlags? keyStorageFlags = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        return X509CertificateLoader.LoadPkcs12Collection(data, password, keyStorageFlags ?? SafeKeyStorageFlags);
    }
}
