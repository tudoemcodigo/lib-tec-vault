using TEC.Vault.Common;

namespace TEC.Vault.Keys;

/// <summary>
/// Algoritmo da chave. A parte privada nunca sai do cofre. A proteção por hardware (HSM) é independente do algoritmo:
/// veja <see cref="CreateKeyOptions.HardwareProtected"/>.
/// </summary>
public enum VaultKeyType
{
    /// <summary>RSA.</summary>
    Rsa = 0,

    /// <summary>Curva elíptica (ECDSA).</summary>
    Ec = 1
}

/// <summary>Curvas elípticas suportadas (NIST).</summary>
public enum VaultKeyCurve
{
    /// <summary>P-256 (ES256).</summary>
    P256 = 0,

    /// <summary>P-384 (ES384).</summary>
    P384 = 1,

    /// <summary>P-521 (ES512).</summary>
    P521 = 2
}

/// <summary>Operações permitidas para a chave (menor privilégio: habilite apenas as necessárias).</summary>
[Flags]
public enum VaultKeyOperations
{
    /// <summary>Nenhuma.</summary>
    None = 0,

    /// <summary>Criptografar.</summary>
    Encrypt = 1,

    /// <summary>Descriptografar.</summary>
    Decrypt = 2,

    /// <summary>Assinar.</summary>
    Sign = 4,

    /// <summary>Verificar assinatura.</summary>
    Verify = 8,

    /// <summary>Proteger (wrap) outra chave.</summary>
    WrapKey = 16,

    /// <summary>Recuperar (unwrap) outra chave.</summary>
    UnwrapKey = 32
}

/// <summary>
/// Algoritmo de criptografia/wrap assimétrico. Apenas RSA-OAEP com SHA-256: RSA1_5 (padding oracle) e RSA-OAEP com SHA-1
/// não são oferecidos de propósito.
/// </summary>
public enum VaultEncryptionAlgorithm
{
    /// <summary>RSA-OAEP-256.</summary>
    RsaOaep256 = 0
}

/// <summary>Algoritmos de assinatura suportados.</summary>
public enum VaultSignatureAlgorithm
{
    /// <summary>RSASSA-PKCS1-v1_5 com SHA-256.</summary>
    RS256 = 0,

    /// <summary>RSASSA-PKCS1-v1_5 com SHA-384.</summary>
    RS384 = 1,

    /// <summary>RSASSA-PKCS1-v1_5 com SHA-512.</summary>
    RS512 = 2,

    /// <summary>RSASSA-PSS com SHA-256 (recomendado para RSA).</summary>
    PS256 = 3,

    /// <summary>RSASSA-PSS com SHA-384.</summary>
    PS384 = 4,

    /// <summary>RSASSA-PSS com SHA-512.</summary>
    PS512 = 5,

    /// <summary>ECDSA P-256 com SHA-256.</summary>
    ES256 = 6,

    /// <summary>ECDSA P-384 com SHA-384.</summary>
    ES384 = 7,

    /// <summary>ECDSA P-521 com SHA-512.</summary>
    ES512 = 8
}

/// <summary>Metadados de uma chave.</summary>
public sealed record KeyProperties : VaultItemProperties
{
    /// <summary>Indica se a chave pode ser exportada pelo provedor (política de liberação). <c>false</c> quando o provedor não oferece exportação.</summary>
    public bool Exportable { get; init; }
}

/// <summary>Chave do cofre: metadados e parte pública. A parte privada nunca é retornada.</summary>
public sealed record VaultKey
{
    /// <summary>Metadados.</summary>
    public required KeyProperties Properties { get; init; }

    /// <summary>Tipo da chave.</summary>
    public required VaultKeyType KeyType { get; init; }

    /// <summary>Indica se a chave é protegida por hardware (HSM).</summary>
    public bool HardwareProtected { get; init; }

    /// <summary>Curva (somente chaves EC).</summary>
    public VaultKeyCurve? Curve { get; init; }

    /// <summary>Tamanho em bits (somente RSA).</summary>
    public int? KeySize { get; init; }

    /// <summary>Operações permitidas.</summary>
    public VaultKeyOperations Operations { get; init; }

    /// <summary>Chave pública em SubjectPublicKeyInfo (DER), para verificação/criptografia local (<c>RSA.ImportSubjectPublicKeyInfo</c>).</summary>
    public byte[]? PublicKeySpki { get; init; }

    /// <summary>Nome da chave.</summary>
    public string Name => Properties.Name;

    /// <summary>Versão da chave.</summary>
    public string? Version => Properties.Version;
}

/// <summary>Parâmetros de criação de chave.</summary>
public sealed record CreateKeyOptions
{
    /// <summary>Tipo. Padrão: <see cref="VaultKeyType.Rsa"/>.</summary>
    public VaultKeyType KeyType { get; init; } = VaultKeyType.Rsa;

    /// <summary>
    /// Exige proteção por hardware (HSM). Padrão: <c>false</c>. O provedor precisa oferecer HSM (ex.: Key Vault Premium);
    /// sem suporte, a criação falha com <see cref="Common.VaultErrors.NotSupported"/> (nunca cai para software em silêncio).
    /// </summary>
    public bool HardwareProtected { get; init; }

    /// <summary>Tamanho RSA: 2048, 3072 ou 4096. Padrão: 3072 (segurança além de 2030).</summary>
    public int KeySize { get; init; } = 3072;

    /// <summary>Curva EC. Padrão: P-256.</summary>
    public VaultKeyCurve Curve { get; init; } = VaultKeyCurve.P256;

    /// <summary>
    /// Operações permitidas. <c>null</c> = todas as aplicáveis ao tipo (RSA: todas; EC: assinar e verificar).
    /// Recomendado: informe apenas as necessárias.
    /// </summary>
    public VaultKeyOperations? Operations { get; init; }

    /// <summary>Habilitada. Padrão: <c>true</c>.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Expiração.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>Início da validade.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>Tags.</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }
}

/// <summary>Alteração de metadados de uma chave. Propriedades <c>null</c> não são alteradas.</summary>
public sealed record KeyPropertiesUpdate
{
    /// <summary>Habilita ou desabilita.</summary>
    public bool? Enabled { get; init; }

    /// <summary>Nova expiração.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>Novo início da validade.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>Novas operações permitidas.</summary>
    public VaultKeyOperations? Operations { get; init; }

    /// <summary>Novas tags (substituem as atuais).</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }
}

/// <summary>Resultado de uma criptografia ou wrap. Guarde <see cref="KeyVersion"/>: a descriptografia exige a mesma versão.</summary>
/// <param name="KeyName">Nome da chave usada.</param>
/// <param name="KeyVersion">Versão da chave usada.</param>
/// <param name="Algorithm">Algoritmo.</param>
/// <param name="Ciphertext">Dados cifrados.</param>
public sealed record VaultEncryptResult(string KeyName, string KeyVersion, VaultEncryptionAlgorithm Algorithm, byte[] Ciphertext);

/// <summary>Resultado de uma assinatura.</summary>
/// <param name="KeyName">Nome da chave usada.</param>
/// <param name="KeyVersion">Versão da chave usada (use a mesma para verificar).</param>
/// <param name="Algorithm">Algoritmo.</param>
/// <param name="Signature">Assinatura.</param>
public sealed record VaultSignResult(string KeyName, string KeyVersion, VaultSignatureAlgorithm Algorithm, byte[] Signature);

/// <summary>
/// Dados protegidos por criptografia envelope: AES-256-GCM local com chave de dados aleatória, e a chave de dados
/// protegida (wrap) pela chave do cofre. Todos os campos podem ser armazenados juntos: sem o cofre, nada é legível.
/// </summary>
/// <param name="KeyName">Nome da chave do cofre (KEK).</param>
/// <param name="KeyVersion">Versão da KEK.</param>
/// <param name="WrappedKey">Chave de dados protegida pela KEK.</param>
/// <param name="Ciphertext">Dados cifrados no formato versionado do AES-GCM do TEC.Core ([versão][nonce][tag][dados]).</param>
public sealed record EnvelopeEncryptedData(string KeyName, string KeyVersion, byte[] WrappedKey, byte[] Ciphertext);
