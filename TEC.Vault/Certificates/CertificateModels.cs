using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TEC.Vault.Common;
using TEC.Vault.Keys;

namespace TEC.Vault.Certificates;

/// <summary>Metadados de um certificado.</summary>
public sealed record CertificateProperties : VaultItemProperties
{
    /// <summary>Thumbprint SHA-1 em hexadecimal maiúsculo (identificação; não use para decisões de segurança).</summary>
    public string? Thumbprint { get; init; }
}

/// <summary>Certificado do cofre: metadados e parte pública (DER). A chave privada só sai com <c>DownloadCertificateAsync</c>.</summary>
public sealed record VaultCertificate
{
    /// <summary>Metadados.</summary>
    public required CertificateProperties Properties { get; init; }

    /// <summary>Certificado público em DER (.cer).</summary>
    public required byte[] Cer { get; init; }

    /// <summary>Nome.</summary>
    public string Name => Properties.Name;

    /// <summary>Versão.</summary>
    public string? Version => Properties.Version;

    /// <summary>Carrega a parte pública como <see cref="X509Certificate2"/> (sem chave privada). Descarte após o uso.</summary>
    /// <exception cref="System.Security.Cryptography.CryptographicException"><see cref="Cer"/> não é um certificado X.509 (ex.: é um PFX).</exception>
    public X509Certificate2 ToX509Certificate() => Providers.VaultCertificateLoader.LoadCertificate(Cer);
}

/// <summary>Formato do conteúdo armazenado para o certificado.</summary>
public enum CertificateContentFormat
{
    /// <summary>PKCS#12 (PFX).</summary>
    Pkcs12 = 0,

    /// <summary>PEM.</summary>
    Pem = 1
}

/// <summary>Parâmetros de criação de certificado.</summary>
public sealed record CreateCertificateOptions
{
    /// <summary>Subject X.500 (ex.: "CN=api.tudoemcodigo.com"). Obrigatório.</summary>
    public required string Subject { get; init; }

    /// <summary>Nomes DNS alternativos (SAN).</summary>
    public IReadOnlyList<string>? DnsNames { get; init; }

    /// <summary>
    /// Emissor (autoridade certificadora) configurado no provedor, pelo nome que o provedor usa. <c>null</c> (padrão) = certificado
    /// autoassinado. Provedores sem o emissor informado (ou sem emissores) recusam a criação.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>Validade em meses (1 a 120). Padrão: 12.</summary>
    public int ValidityInMonths { get; init; } = 12;

    /// <summary>Tipo da chave. Padrão: RSA.</summary>
    public VaultKeyType KeyType { get; init; } = VaultKeyType.Rsa;

    /// <summary>Exige chave protegida por hardware (HSM). Padrão: <c>false</c>. Veja <see cref="CreateKeyOptions.HardwareProtected"/>.</summary>
    public bool HardwareProtected { get; init; }

    /// <summary>Tamanho RSA (2048, 3072, 4096). Padrão: 3072.</summary>
    public int KeySize { get; init; } = 3072;

    /// <summary>Curva EC. Padrão: P-256.</summary>
    public VaultKeyCurve Curve { get; init; } = VaultKeyCurve.P256;

    /// <summary>
    /// Permite baixar a chave privada. Padrão: <c>false</c> (Zero Trust: a chave privada não sai do cofre;
    /// use-a por <see cref="Abstractions.IKeyCryptography"/> com o mesmo nome, se o provedor associar a chave ao certificado).
    /// </summary>
    public bool Exportable { get; init; }

    /// <summary>Formato do conteúdo. Padrão: PKCS#12.</summary>
    public CertificateContentFormat ContentFormat { get; init; } = CertificateContentFormat.Pkcs12;

    /// <summary>Renovação automática N dias antes de expirar. <c>null</c> = apenas o padrão do provedor.</summary>
    public int? AutoRenewDaysBeforeExpiry { get; init; }

    /// <summary>Habilitado. Padrão: <c>true</c>.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Tags.</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }
}

/// <summary>Parâmetros de importação de certificado (PFX ou PEM com chave privada).</summary>
/// <remarks>
/// Segurança: <see cref="ToString"/> (gerado pelo <c>record</c>) e a visualização do depurador mascaram <see cref="Password"/>,
/// para que a senha não vá parar em logs ou mensagens de exceção por interpolação de string.
/// </remarks>
[DebuggerDisplay("{ToString(),nq}")]
public sealed record ImportCertificateOptions
{
    /// <summary>Senha do PFX (ou da chave privada PEM criptografada), se houver. Nunca registre em log.</summary>
    public string? Password { get; init; }

    /// <summary>Permite baixar a chave privada depois. Padrão: <c>false</c>.</summary>
    public bool Exportable { get; init; }

    /// <summary>Habilitado. Padrão: <c>true</c>.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Tags.</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }

    // Substitui a impressão gerada pelo record: a senha nunca aparece em ToString
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append("Password = ").Append(Password is null ? "null" : "***")
            .Append(", Exportable = ").Append(Exportable)
            .Append(", Enabled = ").Append(Enabled)
            .Append(", Tags = ").Append(Tags is null ? "null" : $"[{Tags.Count}]");
        return true;
    }
}

/// <summary>Alteração de metadados de um certificado. Propriedades <c>null</c> não são alteradas.</summary>
public sealed record CertificatePropertiesUpdate
{
    /// <summary>Habilita ou desabilita.</summary>
    public bool? Enabled { get; init; }

    /// <summary>Novas tags (substituem as atuais).</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }
}
