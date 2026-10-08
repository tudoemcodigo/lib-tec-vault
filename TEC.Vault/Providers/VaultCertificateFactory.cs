using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TEC.Vault.Certificates;
using TEC.Vault.Keys;

namespace TEC.Vault.Providers;

/// <summary>
/// Geração local de certificados a partir de <see cref="CreateCertificateOptions"/> (uso pelos provedores que não geram o
/// certificado no cofre): par de chaves, requisição com SAN e extensões, autoassinado ou CSR para uma CA.
/// </summary>
public static class VaultCertificateFactory
{
    /// <summary>
    /// Cria o par de chaves e a requisição (subject, SAN, key usage e basic constraints de certificado final).
    /// O chamador descarta a chave.
    /// </summary>
    /// <remarks>As opções devem ter sido validadas por <see cref="VaultCertificateRules.Create"/>.</remarks>
    public static (CertificateRequest Request, AsymmetricAlgorithm Key) CreateRequest(CreateCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var subject = new X500DistinguishedName(options.Subject);
        CertificateRequest request;
        AsymmetricAlgorithm key;
        if (options.KeyType == VaultKeyType.Rsa)
        {
            var rsa = RSA.Create(options.KeySize);
            key = rsa;
            request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        }
        else
        {
            var ecdsa = ECDsa.Create(VaultKeyRules.ToECCurve(options.Curve));
            key = ecdsa;
            request = new CertificateRequest(subject, ecdsa, VaultKeyRules.CurveHash(options.Curve));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        }

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        if (options.DnsNames is { Count: > 0 } dnsNames)
        {
            var san = new SubjectAlternativeNameBuilder();
            foreach (var dns in dnsNames)
                san.AddDnsName(dns);
            request.CertificateExtensions.Add(san.Build());
        }

        return (request, key);
    }

    /// <summary>Certificado autoassinado com a chave privada (válido de 5 minutos antes de <paramref name="now"/> até a validade pedida).</summary>
    public static X509Certificate2 CreateSelfSigned(CreateCertificateOptions options, DateTimeOffset now)
    {
        var (request, key) = CreateRequest(options);
        using (key)
            return request.CreateSelfSigned(now.AddMinutes(-5), now.AddMonths(options.ValidityInMonths));
    }

    /// <summary>
    /// Junta o certificado emitido por uma CA (PEM ou DER) com a chave privada gerada em <see cref="CreateRequest"/>.
    /// </summary>
    /// <exception cref="CryptographicException">O certificado não corresponde à chave.</exception>
    public static X509Certificate2 WithPrivateKey(X509Certificate2 issued, AsymmetricAlgorithm key)
    {
        ArgumentNullException.ThrowIfNull(issued);
        return key switch
        {
            RSA rsa => issued.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => issued.CopyWithPrivateKey(ecdsa),
            _ => throw new ArgumentException("Tipo de chave não suportado.", nameof(key))
        };
    }
}
