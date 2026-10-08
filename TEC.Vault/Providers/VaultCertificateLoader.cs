using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TEC.Vault.Providers;

/// <summary>
/// Carga segura de certificados, com o mesmo comportamento no .NET 8 e no .NET 9+ (uso pelos provedores e pelos modelos).
/// </summary>
/// <remarks>
/// <para>No .NET 9+ usa <c>X509CertificateLoader</c> (limites padrão contra PFX malicioso: iterações, tamanho, quantidade de itens).
/// No .NET 8, onde ele não existe, usa o construtor de <see cref="X509Certificate2"/> com as mesmas regras: o tipo do conteúdo é
/// conferido antes (<see cref="LoadCertificate"/> nunca aceita PFX/PKCS#7; <see cref="LoadPkcs12"/> só aceita PKCS#12) e os
/// mesmos <see cref="X509KeyStorageFlags"/> são usados. O construtor do .NET 8 tem menos limites de PKCS#12 que o
/// <c>X509CertificateLoader</c>; os provedores limitam o tamanho do conteúdo antes da carga.</para>
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
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(data);
#else
        if (X509Certificate2.GetCertContentType(data) != X509ContentType.Cert)
            throw new CryptographicException("O conteúdo não é um certificado X.509.");
        return new X509Certificate2(data);
#endif
    }

    /// <summary>Carrega um PKCS#12 (PFX) com a chave privada.</summary>
    /// <param name="data">Conteúdo PKCS#12.</param>
    /// <param name="password">Senha (<c>null</c> = sem senha).</param>
    /// <param name="keyStorageFlags">Flags de armazenamento. <c>null</c> = <see cref="SafeKeyStorageFlags"/>.</param>
    /// <exception cref="CryptographicException">Conteúdo que não é PKCS#12, senha incorreta ou limites excedidos.</exception>
    public static X509Certificate2 LoadPkcs12(byte[] data, string? password, X509KeyStorageFlags? keyStorageFlags = null)
    {
        ArgumentNullException.ThrowIfNull(data);
        var flags = keyStorageFlags ?? SafeKeyStorageFlags;
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(data, password, flags);
#else
        if (X509Certificate2.GetCertContentType(data) != X509ContentType.Pkcs12)
            throw new CryptographicException("O conteúdo não é PKCS#12.");
        return new X509Certificate2(data, password, flags);
#endif
    }

    /// <summary>Indica qual implementação está em uso (testes): <c>true</c> = <c>X509CertificateLoader</c> (.NET 9+).</summary>
    internal static bool UsesCertificateLoader =>
#if NET9_0_OR_GREATER
        true;
#else
        false;
#endif
}
