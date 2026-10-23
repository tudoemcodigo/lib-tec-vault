using System.Security.Cryptography;
using TEC.Vault.Common;
using TEC.Vault.Keys;
using TEC.Core.Common.Results;

namespace TEC.Vault.Providers;

/// <summary>
/// Regras de chaves comuns a todos os provedores (uso pelos provedores): tamanhos RSA aceitos, operações por tipo e
/// validação da forma da chave. Valores fracos (RSA &lt; 2048) não passam, seja qual for o provedor.
/// </summary>
public static class VaultKeyRules
{
    /// <summary>Tamanhos RSA aceitos: 2048, 3072 e 4096 bits.</summary>
    public static IReadOnlyList<int> AllowedRsaSizes { get; } = [2048, 3072, 4096];

    /// <summary>Todas as operações (aplicáveis a RSA).</summary>
    public const VaultKeyOperations AllOperations = VaultKeyOperations.Encrypt | VaultKeyOperations.Decrypt | VaultKeyOperations.Sign
        | VaultKeyOperations.Verify | VaultKeyOperations.WrapKey | VaultKeyOperations.UnwrapKey;

    /// <summary>Operações aplicáveis a chaves EC: assinar e verificar.</summary>
    public const VaultKeyOperations EcOperations = VaultKeyOperations.Sign | VaultKeyOperations.Verify;

    /// <summary>Maior texto claro de criptografia/wrap: RSA-OAEP-256 com RSA 4096 cifra no máximo 446 bytes.</summary>
    public const int MaxEncryptBytes = 446;

    /// <summary>Tamanho do bloco RSA 4096 (maior texto cifrado/assinatura possível).</summary>
    public const int MaxCiphertextBytes = 512;

    /// <summary>Tamanho máximo dos dados a assinar/verificar: 64 MB.</summary>
    public const int MaxSignDataBytes = 64 * 1024 * 1024;

    /// <summary>Operações padrão quando <see cref="CreateKeyOptions.Operations"/> é <c>null</c>: todas as aplicáveis ao tipo.</summary>
    public static VaultKeyOperations DefaultOperations(VaultKeyType type) => type == VaultKeyType.Rsa ? AllOperations : EcOperations;

    /// <summary>Valida tipo, tamanho RSA, curva EC e operações pedidas.</summary>
    public static Error? Shape(VaultKeyType type, int keySize, VaultKeyCurve curve, VaultKeyOperations? operations)
    {
        if (!Enum.IsDefined(type))
            return VaultErrors.InvalidInput("keyType", "Tipo de chave inválido.");
        if (type == VaultKeyType.Rsa && !AllowedRsaSizes.Contains(keySize))
            return VaultErrors.InvalidInput("keySize", "Tamanho RSA deve ser 2048, 3072 ou 4096 bits.");
        if (type == VaultKeyType.Ec && !Enum.IsDefined(curve))
            return VaultErrors.InvalidInput("curve", "Curva inválida.");
        if (operations is { } ops)
        {
            var allowed = DefaultOperations(type);
            if (ops == VaultKeyOperations.None || (ops & ~allowed) != 0)
            {
                return VaultErrors.InvalidInput("operations", type == VaultKeyType.Rsa
                    ? "Informe ao menos uma operação válida."
                    : "Chaves EC permitem apenas assinar e verificar.");
            }
        }

        return null;
    }

    /// <summary>Valida as operações de uma alteração de metadados (ao menos uma, todas conhecidas).</summary>
    public static Error? Operations(VaultKeyOperations? operations) =>
        operations is { } ops && (ops == VaultKeyOperations.None || (ops & ~AllOperations) != 0)
            ? VaultErrors.InvalidInput("operations", "Operações inválidas.")
            : null;

    /// <summary>Valida um algoritmo de criptografia/wrap.</summary>
    public static Error? EncryptionAlgorithm(VaultEncryptionAlgorithm algorithm) =>
        Enum.IsDefined(algorithm) ? null : VaultErrors.InvalidInput("algorithm", "Algoritmo inválido.");

    /// <summary>Valida um algoritmo de assinatura.</summary>
    public static Error? SignatureAlgorithm(VaultSignatureAlgorithm algorithm) =>
        Enum.IsDefined(algorithm) ? null : VaultErrors.InvalidInput("algorithm", "Algoritmo de assinatura inválido.");

    /// <summary>Curva do .NET correspondente (para provedores que geram ou usam a chave localmente).</summary>
    public static ECCurve ToECCurve(VaultKeyCurve curve) => curve switch
    {
        VaultKeyCurve.P384 => ECCurve.NamedCurves.nistP384,
        VaultKeyCurve.P521 => ECCurve.NamedCurves.nistP521,
        _ => ECCurve.NamedCurves.nistP256
    };

    /// <summary>Hash usado com a curva: P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512.</summary>
    public static HashAlgorithmName CurveHash(VaultKeyCurve curve) => curve switch
    {
        VaultKeyCurve.P384 => HashAlgorithmName.SHA384,
        VaultKeyCurve.P521 => HashAlgorithmName.SHA512,
        _ => HashAlgorithmName.SHA256
    };

    /// <summary>Hash e padding de um algoritmo de assinatura RSA (<c>RS*</c>/<c>PS*</c>); <c>null</c> se o algoritmo não é RSA.</summary>
    public static (HashAlgorithmName Hash, RSASignaturePadding Padding)? RsaSignature(VaultSignatureAlgorithm algorithm) => algorithm switch
    {
        VaultSignatureAlgorithm.RS256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
        VaultSignatureAlgorithm.RS384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
        VaultSignatureAlgorithm.RS512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
        VaultSignatureAlgorithm.PS256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
        VaultSignatureAlgorithm.PS384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
        VaultSignatureAlgorithm.PS512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
        _ => null
    };

    /// <summary>Hash e curva exigida de um algoritmo de assinatura EC (<c>ES*</c>); <c>null</c> se o algoritmo não é EC.</summary>
    public static (HashAlgorithmName Hash, VaultKeyCurve Curve)? EcSignature(VaultSignatureAlgorithm algorithm)
    {
        VaultKeyCurve? curve = algorithm switch
        {
            VaultSignatureAlgorithm.ES256 => VaultKeyCurve.P256,
            VaultSignatureAlgorithm.ES384 => VaultKeyCurve.P384,
            VaultSignatureAlgorithm.ES512 => VaultKeyCurve.P521,
            _ => null
        };
        return curve is { } c ? (CurveHash(c), c) : null;
    }
}
