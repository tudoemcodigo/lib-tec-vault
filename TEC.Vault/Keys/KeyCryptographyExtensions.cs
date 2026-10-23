using System.Security.Cryptography;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Core.Common.Results;
using TEC.Core.Cryptography.Symmetric;

namespace TEC.Vault.Keys;

/// <summary>Criptografia envelope com qualquer provedor de chaves.</summary>
/// <remarks>
/// <para>Uma chave de dados AES-256 aleatória (DEK) cifra o conteúdo localmente com AES-GCM (autenticado, via TEC.Core);
/// a DEK é protegida (wrap) pela chave do cofre (KEK) e descartada da memória. Não há limite de tamanho e o cofre recebe
/// apenas 32 bytes por operação.</para>
/// <para>Use <c>associatedData</c> para amarrar o conteúdo ao contexto (ex.: id do registro): a descriptografia
/// com outro contexto falha, impedindo que um campo cifrado seja copiado para outro registro.</para>
/// <para><b>O envelope garante sigilo e integridade, mas não autentica a origem.</b> O wrap da DEK usa a chave
/// <b>pública</b> da KEK (RSA-OAEP): quem tem a chave pública (qualquer identidade com <c>keys/get</c>, ou quem a copiou)
/// consegue montar um <see cref="EnvelopeEncryptedData"/> válido, com qualquer conteúdo e o <c>associatedData</c> que
/// quiser, e <see cref="DecryptEnvelopeAsync"/> o aceita. Um envelope decifrado com sucesso prova que o conteúdo não foi
/// alterado depois de cifrado e que pertence ao contexto informado, <b>não</b> que foi esta aplicação que o cifrou.</para>
/// <para>Quando a autenticidade importa (ex.: dados recebidos de outro sistema, ou armazenados onde terceiros com a chave
/// pública conseguem gravar), assine o envelope com <see cref="IKeyCryptography.SignDataAsync"/> usando uma chave de
/// assinatura que só o emissor pode usar, e confira com <see cref="IKeyCryptography.VerifyDataAsync"/> antes de decifrar.</para>
/// </remarks>
/// <example>
/// Envelope assinado (autenticidade da origem):
/// <code>
/// var envelope = (await crypto.EncryptEnvelopeAsync("kek-dados", content, context, cancellationToken: ct)).Value;
/// // WrappedKey tem tamanho fixo (o da chave RSA) e o contexto é conhecido de quem confere: a concatenação não é ambígua
/// byte[] signedData = [.. context, .. envelope.WrappedKey, .. envelope.Ciphertext];
/// var signature = (await crypto.SignDataAsync("chave-assinatura", signedData, VaultSignatureAlgorithm.PS256, cancellationToken: ct)).Value;
/// // guarde junto: envelope, signature.Signature e signature.KeyVersion
///
/// // Leitura: confira a assinatura ANTES de decifrar
/// var valid = await crypto.VerifyDataAsync("chave-assinatura", storedKeyVersion, signedData, storedSignature, VaultSignatureAlgorithm.PS256, ct);
/// if (valid.IsFailure || !valid.Value)
///     return VaultErrors.InvalidInput("signature", "Assinatura inválida.");
/// var plaintext = await crypto.DecryptEnvelopeAsync(envelope, context, ct);
/// </code>
/// </example>
public static class KeyCryptographyExtensions
{
    private const int DataKeySize = 32;
    private static readonly AesGcmCryptography Aes = new();

    /// <summary>Cifra <paramref name="plaintext"/> com criptografia envelope (sigilo e integridade; não autentica a origem).</summary>
    public static async Task<Result<EnvelopeEncryptedData>> EncryptEnvelopeAsync(this IKeyCryptography store, string keyName, byte[] plaintext,
        byte[]? associatedData = null, string? keyVersion = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(plaintext);

        var dataKey = Aes.GenerateKey();   // AES-256 (32 bytes), gerador criptográfico do TEC.Core
        try
        {
            var wrapped = await store.WrapKeyAsync(keyName, dataKey, VaultEncryptionAlgorithm.RsaOaep256, keyVersion, cancellationToken)
                .ConfigureAwait(false);
            if (wrapped.IsFailure)
                return wrapped.ToFailure<EnvelopeEncryptedData>();

            var ciphertext = Aes.Encrypt(plaintext, dataKey, associatedData);
            return new EnvelopeEncryptedData(wrapped.Value.KeyName, wrapped.Value.KeyVersion, wrapped.Value.Ciphertext, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    /// <summary>Decifra dados produzidos por <see cref="EncryptEnvelopeAsync"/>. Dados adulterados ou contexto diferente retornam erro de validação.</summary>
    /// <remarks>
    /// Sucesso confirma integridade e contexto, <b>não</b> a origem: quem tem a chave pública da KEK consegue gerar um envelope
    /// aceito por este método. Para autenticar quem cifrou, confira uma assinatura (<see cref="IKeyCryptography.VerifyDataAsync"/>)
    /// antes de decifrar (veja <see cref="KeyCryptographyExtensions"/>).
    /// </remarks>
    public static async Task<Result<byte[]>> DecryptEnvelopeAsync(this IKeyCryptography store, EnvelopeEncryptedData data,
        byte[]? associatedData = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(data);
        if (data.Ciphertext is null || data.WrappedKey is null)
            return VaultErrors.InvalidInput("data", "Dados cifrados incompletos.");

        var unwrapped = await store.UnwrapKeyAsync(data.KeyName, data.KeyVersion, data.WrappedKey, VaultEncryptionAlgorithm.RsaOaep256,
            cancellationToken).ConfigureAwait(false);
        if (unwrapped.IsFailure)
            return unwrapped;

        var dataKey = unwrapped.Value;
        try
        {
            if (dataKey.Length != DataKeySize)
                return InvalidCiphertext();
            return Aes.Decrypt(data.Ciphertext, dataKey, associatedData);
        }
        catch (CryptographicException)
        {
            return InvalidCiphertext();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
        }
    }

    private static Error InvalidCiphertext() => VaultErrors.InvalidInput("ciphertext", "Dados cifrados inválidos, adulterados ou de outro contexto.");
}
