using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using TEC.Vault.Certificates;
using TEC.Vault.Common;
using TEC.Core.Common.Results;

namespace TEC.Vault.Providers;

/// <summary>
/// Regras de certificados comuns a todos os provedores (uso pelos provedores): validação da criação e inspeção local do
/// conteúdo importado (PFX ou PEM) antes de enviá-lo ao cofre.
/// </summary>
public static partial class VaultCertificateRules
{
    /// <summary>Tamanho máximo do conteúdo importado: 1 MB.</summary>
    public const int MaxCertificateBytes = 1024 * 1024;

    /// <summary>Tamanho máximo do subject.</summary>
    public const int MaxSubjectLength = 1024;

    /// <summary>Quantidade máxima de nomes DNS (SAN).</summary>
    public const int MaxDnsNames = 100;

    /// <summary>
    /// Valida as opções de criação independentes de provedor: subject X.500, nomes DNS, validade, renovação, formato e forma da
    /// chave. O nome do emissor (<see cref="CreateCertificateOptions.Issuer"/>) só é conferido quanto a tamanho e caracteres de
    /// controle: cada provedor valida se o emissor existe.
    /// </summary>
    public static Error? Create(CreateCertificateOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(options.Subject))
            return VaultErrors.InvalidInput("subject", "O subject é obrigatório (ex.: \"CN=api.exemplo.com\").");
        if (VaultInputRules.OptionalText(options.Subject, MaxSubjectLength, "subject") is { } subjectError)
            return subjectError;

        try
        {
            _ = new X500DistinguishedName(options.Subject);
        }
        catch (CryptographicException)
        {
            return VaultErrors.InvalidInput("subject", "Subject X.500 inválido.");
        }

        if (options.DnsNames is { } dnsNames)
        {
            if (dnsNames.Count > MaxDnsNames)
                return VaultErrors.InvalidInput("dnsNames", $"Máximo de {MaxDnsNames} nomes DNS.");
            if (dnsNames.Any(d => d is null || d.Length > 253 || !DnsNamePattern().IsMatch(d)))
                return VaultErrors.InvalidInput("dnsNames", "Nome DNS inválido.");
        }

        if (options.Issuer is not null && (options.Issuer.Length == 0 || VaultInputRules.OptionalText(options.Issuer, 256, "issuer") is not null))
            return VaultErrors.InvalidInput("issuer", "Emissor inválido.");
        if (options.ValidityInMonths is < 1 or > 120)
            return VaultErrors.InvalidInput("validityInMonths", "A validade deve estar entre 1 e 120 meses.");
        if (options.AutoRenewDaysBeforeExpiry is < 1 or > 365)
            return VaultErrors.InvalidInput("autoRenewDaysBeforeExpiry", "A renovação deve ocorrer entre 1 e 365 dias antes de expirar.");
        if (!Enum.IsDefined(options.ContentFormat))
            return VaultErrors.InvalidInput("contentFormat", "Formato inválido.");

        return VaultKeyRules.Shape(options.KeyType, options.KeySize, options.Curve, operations: null);
    }

    /// <summary>
    /// Detecta PEM em qualquer posição do conteúdo (o OpenSSL coloca "Bag Attributes", "subject=" etc. antes dos blocos).
    /// PKCS#12 é binário DER e sempre começa com <c>0x30</c> (SEQUENCE); texto PEM nunca começa com esse byte.
    /// </summary>
    public static bool IsPem(byte[]? certificate) =>
        certificate is { Length: > 10 } && certificate[0] != 0x30 && certificate.AsSpan().IndexOf("-----BEGIN "u8) >= 0;

    /// <summary>Formato do conteúdo a importar: PEM (detectado em qualquer posição) ou PKCS#12.</summary>
    public static CertificateContentFormat DetectFormat(byte[]? certificate) =>
        IsPem(certificate) ? CertificateContentFormat.Pem : CertificateContentFormat.Pkcs12;

    /// <summary>Rótulos PEM aceitos na importação: certificado e chave privada (PKCS#8, PKCS#8 criptografada, PKCS#1 RSA, SEC1 EC).</summary>
    private static readonly string[] PemLabels = ["CERTIFICATE", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

    /// <summary>Reconstrói o PEM só com os blocos reconhecidos, descartando o texto entre eles (ex.: "Bag Attributes").</summary>
    /// <remarks>
    /// O resultado contém a chave privada: quem chama deve zerá-lo (<see cref="CryptographicOperations.ZeroMemory"/>) após o uso.
    /// As cópias intermediárias feitas aqui são zeradas.
    /// </remarks>
    public static byte[] NormalizePem(byte[] certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        char[] text = PemChars(certificate);
        // Cada bloco aceito ganha uma quebra de linha: no pior caso, um caractere a mais por bloco (blocos têm bem mais de 16)
        char[] normalized = new char[text.Length + text.Length / 16 + 1];
        int length = 0;
        try
        {
            ReadOnlySpan<char> remaining = text;
            while (PemEncoding.TryFind(remaining, out var fields))
            {
                if (IsAcceptedLabel(remaining[fields.Label]))
                {
                    var block = remaining[fields.Location];
                    block.CopyTo(normalized.AsSpan(length));
                    length += block.Length;
                    normalized[length++] = '\n';
                }

                remaining = remaining[fields.Location.End..];
            }

            return Encoding.ASCII.GetBytes(normalized, 0, length);
        }
        finally
        {
            Clear(text);
            Clear(normalized);
        }
    }

    private static bool IsAcceptedLabel(ReadOnlySpan<char> label)
    {
        foreach (string accepted in PemLabels)
        {
            if (label.SequenceEqual(accepted))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Confere o certificado localmente antes de enviar: tamanho, formato válido, senha correta, chave privada presente e casando
    /// com o certificado, e RSA de pelo menos 2048 bits.
    /// </summary>
    /// <param name="certificate">Conteúdo PFX ou PEM.</param>
    /// <param name="password">Senha do PFX ou da chave PEM criptografada.</param>
    /// <param name="format">Formato (veja <see cref="DetectFormat"/>).</param>
    /// <param name="subject">Subject do certificado, se válido.</param>
    /// <returns>O erro encontrado, ou <c>null</c> se o conteúdo pode ser importado.</returns>
    /// <remarks>
    /// Custo de CPU: a chave PEM criptografada (<c>ENCRYPTED PRIVATE KEY</c>) é decifrada com o número de iterações PBKDF2 que o
    /// próprio conteúdo declara, e o .NET não limita esse número (diferente do PKCS#12 no <c>X509CertificateLoader</c>). Um conteúdo
    /// hostil pode consumir CPU por bastante tempo; a única defesa aqui é o limite de tamanho (<see cref="MaxCertificateBytes"/>,
    /// 1 MB). Não exponha a importação a entradas não confiáveis sem limitar a taxa de chamadas.
    /// </remarks>
    public static Error? InspectImport(byte[]? certificate, string? password, CertificateContentFormat format, out string? subject)
    {
        subject = null;
        if (VaultInputRules.Bytes(certificate, MaxCertificateBytes, "certificate") is { } sizeError)
            return sizeError;

        X509Certificate2? loaded = null;
        try
        {
            loaded = format == CertificateContentFormat.Pem
                ? LoadPem(certificate!, password)
                : VaultCertificateLoader.LoadPkcs12(certificate!, password);

            if (!loaded.HasPrivateKey)
                return VaultErrors.InvalidInput("certificate", "O certificado precisa conter a chave privada.");

            using var rsa = loaded.GetRSAPublicKey();
            if (rsa is not null && rsa.KeySize < 2048)
                return VaultErrors.InvalidInput("certificate", "Chave RSA menor que 2048 bits não é aceita.");

            subject = loaded.Subject;
            return null;
        }
        catch (CryptographicException)
        {
            return VaultErrors.InvalidInput("certificate", "Certificado inválido ou senha incorreta.");
        }
        catch (ArgumentException)
        {
            return VaultErrors.InvalidInput("certificate", "Certificado inválido.");
        }
        finally
        {
            loaded?.Dispose();
        }
    }

    /// <summary>
    /// Carrega certificado + chave privada do mesmo texto PEM (passado como as duas partes). Com senha, a chave precisa ser
    /// "ENCRYPTED PRIVATE KEY" (PKCS#8 criptografada); sem senha, "PRIVATE KEY", "RSA PRIVATE KEY" ou "EC PRIVATE KEY".
    /// </summary>
    /// <remarks>
    /// O chamador deve descartar o certificado. O texto PEM é decodificado para um buffer próprio (não uma <c>string</c>),
    /// zerado ao final; <paramref name="certificate"/> é do chamador e não é alterado.
    /// </remarks>
    public static X509Certificate2 LoadPem(byte[] certificate, string? password)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        char[] pem = PemChars(certificate);
        try
        {
            return password is null ? X509Certificate2.CreateFromPem(pem, pem) : X509Certificate2.CreateFromEncryptedPem(pem, pem, password);
        }
        finally
        {
            Clear(pem);
        }
    }

    /// <summary>PEM é ASCII; um BOM UTF-8 (comum em arquivos salvos no Windows) é ignorado. Quem chama zera o resultado.</summary>
    private static char[] PemChars(byte[] certificate)
    {
        var bytes = certificate.AsSpan().StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]) ? certificate.AsSpan(3) : certificate;
        char[] chars = new char[Encoding.UTF8.GetCharCount(bytes)];
        Encoding.UTF8.GetChars(bytes, chars);
        return chars;
    }

    private static void Clear(char[] buffer) => CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(buffer.AsSpan()));

    // \z e não $: $ aceitaria uma quebra de linha no final do nome
    [GeneratedRegex(@"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex DnsNamePattern();
}
