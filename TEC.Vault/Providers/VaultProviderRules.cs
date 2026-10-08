using System.Text.RegularExpressions;
using TEC.Vault.Certificates;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Core.Common.Results;

namespace TEC.Vault.Providers;

/// <summary>
/// Regras de entrada de um provedor (uso pelos provedores): os limites próprios do cofre (padrão de nome, tags, tamanhos) e as
/// validações de cada operação, iguais em todos os provedores. Cada provedor cria uma instância com os seus limites e passa o
/// resultado para <see cref="VaultProviderBase"/>. Retornam o primeiro <see cref="Error"/> encontrado ou <c>null</c>.
/// </summary>
public sealed class VaultProviderRules
{
    /// <summary>Cria as regras.</summary>
    /// <param name="namePattern">Padrão de nome do provedor (ancorado com <c>^</c> e <c>\z</c>).</param>
    /// <param name="nameRule">Descrição do padrão, para a mensagem de erro.</param>
    public VaultProviderRules(Regex namePattern, string nameRule)
    {
        ArgumentNullException.ThrowIfNull(namePattern);
        ArgumentException.ThrowIfNullOrWhiteSpace(nameRule);
        NamePattern = namePattern;
        NameRule = nameRule;
    }

    /// <summary>Padrão de nome.</summary>
    public Regex NamePattern { get; }

    /// <summary>Descrição do padrão de nome.</summary>
    public string NameRule { get; }

    /// <summary>Padrão de versão. Padrão: <see cref="VaultInputRules.HexVersionPattern"/> (32 hexadecimais).</summary>
    public Regex VersionPattern { get; init; } = VaultInputRules.HexVersionPattern();

    /// <summary>Tamanho máximo do valor de um segredo, em bytes UTF-8.</summary>
    public required int MaxSecretValueBytes { get; init; }

    /// <summary>Quantidade máxima de tags.</summary>
    public required int MaxTags { get; init; }

    /// <summary>Tamanho máximo da chave de uma tag.</summary>
    public required int MaxTagKeyLength { get; init; }

    /// <summary>Tamanho máximo do valor de uma tag.</summary>
    public required int MaxTagValueLength { get; init; }

    /// <summary>Tamanho máximo de um backup.</summary>
    public required int MaxBackupBytes { get; init; }

    /// <summary>Tamanho máximo do tipo de conteúdo. Padrão: <see cref="VaultInputRules.MaxContentTypeLength"/>.</summary>
    public int MaxContentTypeLength { get; init; } = VaultInputRules.MaxContentTypeLength;

    /// <summary>Nome obrigatório.</summary>
    public Error? Name(string? name) => VaultInputRules.Name(name, NamePattern, NameRule);

    /// <summary>Versão opcional.</summary>
    public Error? Version(string? version) => VaultInputRules.Version(version, VersionPattern);

    /// <summary>Versão obrigatória.</summary>
    public Error? RequiredVersion(string? version) => VaultInputRules.RequiredVersion(version, VersionPattern);

    /// <summary>Nome obrigatório e versão opcional (leitura de um item).</summary>
    public Error? Item(string? name, string? version) => VaultInputRules.First(Name(name), Version(version));

    /// <summary>Tags.</summary>
    public Error? Tags(IReadOnlyDictionary<string, string>? tags) => VaultInputRules.Tags(tags, MaxTags, MaxTagKeyLength, MaxTagValueLength);

    /// <summary>Backup a restaurar.</summary>
    public Error? Backup(byte[]? backup) => VaultInputRules.Bytes(backup, MaxBackupBytes, "backup");

    /// <summary>Valor de segredo.</summary>
    public Error? SecretValue(string? value) => VaultInputRules.SecretValue(value, MaxSecretValueBytes);

    /// <summary>Gravação de segredo (nova versão): nome, valor, tipo de conteúdo, tags e validade (expiração no futuro).</summary>
    public Error? SetSecret(string? name, string? value, SecretWriteOptions options, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(options);
        return VaultInputRules.First(
            Name(name),
            SecretValue(value),
            VaultInputRules.OptionalText(options.ContentType, MaxContentTypeLength, "contentType"),
            Tags(options.Tags),
            VaultInputRules.Validity(options.NotBefore, options.ExpiresOn, now, requireFutureExpiration: true));
    }

    /// <summary>Alteração de metadados de segredo: nome, versão, tipo de conteúdo, tags e validade.</summary>
    public Error? UpdateSecret(string? name, string? version, SecretPropertiesUpdate update, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(update);
        return VaultInputRules.First(
            Name(name),
            Version(version),
            VaultInputRules.OptionalText(update.ContentType, MaxContentTypeLength, "contentType"),
            Tags(update.Tags),
            VaultInputRules.Validity(update.NotBefore, update.ExpiresOn, now, requireFutureExpiration: false));
    }

    /// <summary>Criação de chave: nome, forma da chave (<see cref="VaultKeyRules.Shape"/>), tags e validade (expiração no futuro).</summary>
    public Error? CreateKey(string? name, CreateKeyOptions options, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(options);
        return VaultInputRules.First(
            Name(name),
            VaultKeyRules.Shape(options.KeyType, options.KeySize, options.Curve, options.Operations),
            Tags(options.Tags),
            VaultInputRules.Validity(options.NotBefore, options.ExpiresOn, now, requireFutureExpiration: true));
    }

    /// <summary>Alteração de metadados de chave: nome, versão, tags, operações e validade.</summary>
    public Error? UpdateKey(string? name, string? version, KeyPropertiesUpdate update, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(update);
        return VaultInputRules.First(
            Name(name),
            Version(version),
            Tags(update.Tags),
            VaultKeyRules.Operations(update.Operations),
            VaultInputRules.Validity(update.NotBefore, update.ExpiresOn, now, requireFutureExpiration: false));
    }

    /// <summary>Criptografia ou wrap (versão opcional): nome, versão, algoritmo e conteúdo até <see cref="VaultKeyRules.MaxEncryptBytes"/>.</summary>
    /// <param name="name">Nome da chave.</param>
    /// <param name="version">Versão (<c>null</c> = atual).</param>
    /// <param name="algorithm">Algoritmo.</param>
    /// <param name="data">Texto claro ou chave a proteger.</param>
    /// <param name="field">Campo do erro (ex.: "plaintext", "key").</param>
    public Error? Encrypt(string? name, string? version, VaultEncryptionAlgorithm algorithm, byte[]? data, string field) =>
        VaultInputRules.First(Name(name), Version(version), VaultKeyRules.EncryptionAlgorithm(algorithm),
            VaultInputRules.Bytes(data, VaultKeyRules.MaxEncryptBytes, field));

    /// <summary>Descriptografia ou unwrap (versão obrigatória): nome, versão, algoritmo e conteúdo até <see cref="VaultKeyRules.MaxCiphertextBytes"/>.</summary>
    /// <param name="name">Nome da chave.</param>
    /// <param name="version">Versão que cifrou.</param>
    /// <param name="algorithm">Algoritmo.</param>
    /// <param name="data">Texto cifrado ou chave protegida.</param>
    /// <param name="field">Campo do erro (ex.: "ciphertext", "wrappedKey").</param>
    public Error? Decrypt(string? name, string? version, VaultEncryptionAlgorithm algorithm, byte[]? data, string field) =>
        VaultInputRules.First(Name(name), RequiredVersion(version), VaultKeyRules.EncryptionAlgorithm(algorithm),
            VaultInputRules.Bytes(data, VaultKeyRules.MaxCiphertextBytes, field));

    /// <summary>Assinatura (versão opcional): nome, versão, algoritmo e dados até <see cref="VaultKeyRules.MaxSignDataBytes"/>.</summary>
    public Error? Sign(string? name, string? version, VaultSignatureAlgorithm algorithm, byte[]? data) =>
        VaultInputRules.First(Name(name), Version(version), VaultKeyRules.SignatureAlgorithm(algorithm),
            VaultInputRules.Bytes(data, VaultKeyRules.MaxSignDataBytes, "data"));

    /// <summary>Verificação de assinatura (versão obrigatória): nome, versão, algoritmo, dados e assinatura.</summary>
    public Error? Verify(string? name, string? version, VaultSignatureAlgorithm algorithm, byte[]? data, byte[]? signature) =>
        VaultInputRules.First(Name(name), RequiredVersion(version), VaultKeyRules.SignatureAlgorithm(algorithm),
            VaultInputRules.Bytes(data, VaultKeyRules.MaxSignDataBytes, "data"),
            VaultInputRules.Bytes(signature, VaultKeyRules.MaxCiphertextBytes, "signature"));

    /// <summary>
    /// Importação de certificado: nome e tags e, só se estiverem válidos, a inspeção local do conteúdo
    /// (<see cref="VaultCertificateRules.InspectImport"/>: formato, senha, chave privada, tamanho da chave).
    /// </summary>
    /// <param name="name">Nome do certificado.</param>
    /// <param name="certificate">Conteúdo PFX ou PEM.</param>
    /// <param name="options">Opções da importação.</param>
    /// <param name="format">Formato detectado (<see cref="VaultCertificateRules.DetectFormat"/>).</param>
    /// <param name="subject">Subject do certificado, se válido.</param>
    public Error? ImportCertificate(string? name, byte[]? certificate, ImportCertificateOptions options,
        out CertificateContentFormat format, out string? subject)
    {
        ArgumentNullException.ThrowIfNull(options);
        format = VaultCertificateRules.DetectFormat(certificate);
        subject = null;
        return VaultInputRules.First(Name(name), Tags(options.Tags))
            ?? VaultCertificateRules.InspectImport(certificate, options.Password, format, out subject);
    }
}
