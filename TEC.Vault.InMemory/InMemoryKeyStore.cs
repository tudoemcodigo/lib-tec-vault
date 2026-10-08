using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.InMemory.Internal;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Core.Common.Results;

namespace TEC.Vault.InMemory;

/// <summary>
/// Chaves em memória (desenvolvimento e testes): RSA (2048/3072/4096) e EC (P-256/384/521) geradas localmente, com criptografia
/// RSA-OAEP-256, wrap/unwrap e assinatura/verificação reais, versões, rotação, lixeira e backup.
/// </summary>
/// <remarks>
/// <para>Regras aplicadas como num cofre real: chave desabilitada → <see cref="VaultErrors.DisabledCode"/>; fora da validade,
/// operação não permitida (<see cref="KeyProperties"/>/<see cref="VaultKey.Operations"/>) ou algoritmo incompatível com a chave →
/// <see cref="VaultErrors.RejectedCode"/>. Proteção por hardware (<see cref="CreateKeyOptions.HardwareProtected"/>) não existe em
/// memória: a criação falha com <see cref="VaultErrors.NotSupportedCode"/>.</para>
/// <para>A chave privada fica em memória do processo (PKCS#8) e nunca é retornada pela API.</para>
/// </remarks>
public sealed class InMemoryKeyStore : InMemoryStoreBase, IKeyStore, IKeyCryptography, IKeyRecycleBin, IKeyBackup, IVaultHealthProbe
{
    private sealed record Version(KeyProperties Properties, VaultKeyType KeyType, int? KeySize, VaultKeyCurve? Curve,
        VaultKeyOperations Operations, byte[] PrivateKeyPkcs8, byte[] PublicKeySpki);

    private readonly VersionedItems<Version> _items;

    /// <summary>Cria o store.</summary>
    /// <param name="options">Opções. <c>null</c> = padrão (só permitido em Development).</param>
    /// <param name="logger">Logger (auditoria).</param>
    /// <exception cref="InvalidOperationException">Fora de Development sem <see cref="InMemoryVaultOptions.AllowOutsideDevelopment"/>.</exception>
    public InMemoryKeyStore(InMemoryVaultOptions? options = null, ILogger<InMemoryKeyStore>? logger = null)
        : base(options, logger)
    {
        // Backup guarda cópia própria da chave privada, zerada quando o backup é descartado
        _items = new VersionedItems<Version>(Options.MaxBackups,
            v => v with { PrivateKeyPkcs8 = (byte[])v.PrivateKeyPkcs8.Clone(), PublicKeySpki = (byte[])v.PublicKeySpki.Clone() },
            v => CryptographicOperations.ZeroMemory(v.PrivateKeyPkcs8));
    }

    /// <inheritdoc />
    public Task<Result<VaultKey>> CreateKeyAsync(string name, CreateKeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new CreateKeyOptions();
        var inputError = Rules.CreateKey(name, options, Time.GetUtcNow());

        return Run<VaultKey>("key.create", name, inputError, isWrite: true, () =>
        {
            if (options.HardwareProtected)
                return VaultErrors.NotSupported();

            lock (_items.Sync)
            {
                if (_items.IsDeleted(name))
                    return VaultErrors.Conflict();
            }

            // Fora da trava: gerar RSA 4096 leva centenas de milissegundos e bloquearia todas as operações do store
            var version = Generate(name, options.KeyType, options.KeySize, options.Curve,
                options.Operations ?? VaultKeyRules.DefaultOperations(options.KeyType), options.Enabled, options.NotBefore, options.ExpiresOn, options.Tags);
            return Add(name, version);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultKey>> GetKeyAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        Run<VaultKey>("key.get", name, Rules.Item(name, version), isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.Find(name, version, v => v.Properties.Version!) is { } item ? ToModel(item) : VaultErrors.NotFound();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeysAsync(CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<KeyProperties>>("key.list", null, null, isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.Current().Select(v => v.Properties).ToList();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeyVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<KeyProperties>>("key.versions", name, Rules.Name(name), isWrite: false, () =>
        {
            lock (_items.Sync)
            {
                var versions = _items.Versions(name);
                return versions is null ? VaultErrors.NotFound() : versions.Select(v => v.Properties).ToList();
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultKey>> UpdateKeyPropertiesAsync(string name, KeyPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateKey(name, version, update, Time.GetUtcNow());

        return Run<VaultKey>("key.update", name, inputError, isWrite: true, () =>
        {
            lock (_items.Sync)
            {
                var current = _items.Find(name, version, v => v.Properties.Version!);
                if (current is null)
                    return VaultErrors.NotFound();
                if (update.Operations is { } requested && VaultKeyRules.Shape(current.KeyType, current.KeySize ?? 0, current.Curve ?? default, requested) is { } shapeError
                    && shapeError.Field == "operations")
                {
                    return shapeError;
                }

                var updated = current with
                {
                    Operations = update.Operations ?? current.Operations,
                    Properties = current.Properties with
                    {
                        Enabled = update.Enabled ?? current.Properties.Enabled,
                        ExpiresOn = update.ExpiresOn ?? current.Properties.ExpiresOn,
                        NotBefore = update.NotBefore ?? current.Properties.NotBefore,
                        Tags = update.Tags is null ? current.Properties.Tags : CopyTags(update.Tags),
                        UpdatedOn = Time.GetUtcNow()
                    }
                };
                _items.Replace(name, current, updated);
                return ToModel(updated);
            }
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultKey>> RotateKeyAsync(string name, CancellationToken cancellationToken = default) =>
        Run<VaultKey>("key.rotate", name, Rules.Name(name), isWrite: true, () =>
        {
            Version? current;
            lock (_items.Sync)
                current = _items.Find(name, null, v => v.Properties.Version!);
            if (current is null)
                return VaultErrors.NotFound();

            // Fora da trava (veja CreateKeyAsync); a inclusão confere de novo se a chave não foi excluída enquanto isso
            var version = Generate(name, current.KeyType, current.KeySize ?? 0, current.Curve ?? default, current.Operations,
                enabled: true, notBefore: null, expiresOn: null, current.Properties.Tags);
            return Add(name, version, requireExisting: true);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteKeyAsync(string name, CancellationToken cancellationToken = default) =>
        Run<DeletedVaultItem>("key.delete", name, Rules.Name(name), isWrite: true, () =>
        {
            var now = Time.GetUtcNow();
            lock (_items.Sync)
            {
                return _items.Delete(name, now)
                    ? new DeletedVaultItem(name, now, now + RetentionPeriod)
                    : Result<DeletedVaultItem>.Failure(VaultErrors.NotFound());
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedKeysAsync(CancellationToken cancellationToken = default) =>
        Run<IReadOnlyList<DeletedVaultItem>>("key.list-deleted", null, null, isWrite: false, () =>
        {
            lock (_items.Sync)
                return _items.ListDeleted().Select(d => new DeletedVaultItem(d.Name, d.DeletedOn, d.DeletedOn + RetentionPeriod)).ToList();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultKey>> RecoverDeletedKeyAsync(string name, CancellationToken cancellationToken = default) =>
        Run<VaultKey>("key.recover", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Recover(name) is { } versions ? ToModel(versions[^1]) : VaultErrors.NotFound();
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> PurgeDeletedKeyAsync(string name, CancellationToken cancellationToken = default) =>
        RunVoid("key.purge", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Purge(name) ? Result.Success() : Result.Failure(VaultErrors.NotFound());
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Em memória o backup é um identificador opaco, válido só nesta instância (não contém a chave).</remarks>
    public Task<Result<byte[]>> BackupKeyAsync(string name, CancellationToken cancellationToken = default) =>
        Run<byte[]>("key.backup", name, Rules.Name(name), isWrite: true, () =>
        {
            lock (_items.Sync)
                return _items.Backup(name) is { } token ? token : Result<byte[]>.Failure(VaultErrors.NotFound());
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultKey>> RestoreKeyBackupAsync(byte[] backup, CancellationToken cancellationToken = default) =>
        Run<VaultKey>("key.restore", null, Rules.Backup(backup), isWrite: true, () =>
        {
            lock (_items.Sync)
            {
                var versions = _items.Restore(backup, out _, out bool conflict);
                if (conflict)
                    return VaultErrors.Conflict();
                return versions is null ? VaultErrors.Rejected() : ToModel(versions[^1]);
            }
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultEncryptResult>> EncryptAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) =>
        Run<VaultEncryptResult>("key.encrypt", name,
            Rules.Encrypt(name, version, algorithm, plaintext, "plaintext"),
            isWrite: false, () => UseRsa(name, version, VaultKeyOperations.Encrypt, (key, rsa) =>
                new VaultEncryptResult(name, key.Properties.Version!, algorithm, rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA256))),
            cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> DecryptAsync(string name, string version, byte[] ciphertext,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) =>
        Run<byte[]>("key.decrypt", name,
            Rules.Decrypt(name, version, algorithm, ciphertext, "ciphertext"),
            isWrite: false, () => UseRsa(name, version, VaultKeyOperations.Decrypt, (_, rsa) => rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256)),
            cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultEncryptResult>> WrapKeyAsync(string name, byte[] key, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) =>
        Run<VaultEncryptResult>("key.wrap", name,
            Rules.Encrypt(name, version, algorithm, key, "key"),
            isWrite: false, () => UseRsa(name, version, VaultKeyOperations.WrapKey, (item, rsa) =>
                new VaultEncryptResult(name, item.Properties.Version!, algorithm, rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256))),
            cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> UnwrapKeyAsync(string name, string version, byte[] wrappedKey,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) =>
        Run<byte[]>("key.unwrap", name,
            Rules.Decrypt(name, version, algorithm, wrappedKey, "wrappedKey"),
            isWrite: false, () => UseRsa(name, version, VaultKeyOperations.UnwrapKey, (_, rsa) => rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256)),
            cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultSignResult>> SignDataAsync(string name, byte[] data, VaultSignatureAlgorithm algorithm, string? version = null,
        CancellationToken cancellationToken = default) =>
        Run<VaultSignResult>("key.sign", name,
            Rules.Sign(name, version, algorithm, data),
            isWrite: false, () =>
            {
                var key = Resolve(name, version, VaultKeyOperations.Sign);
                if (key.IsFailure)
                    return key.ToFailure<VaultSignResult>();

                var signature = Sign(key.Value, algorithm, data);
                return signature.IsFailure
                    ? signature.ToFailure<VaultSignResult>()
                    : new VaultSignResult(name, key.Value.Properties.Version!, algorithm, signature.Value);
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> VerifyDataAsync(string name, string version, byte[] data, byte[] signature, VaultSignatureAlgorithm algorithm,
        CancellationToken cancellationToken = default) =>
        Run<bool>("key.verify", name,
            Rules.Verify(name, version, algorithm, data, signature),
            isWrite: false, () =>
            {
                var key = Resolve(name, version, VaultKeyOperations.Verify);
                return key.IsFailure ? key.ToFailure<bool>() : Verify(key.Value, algorithm, data, signature);
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        RunVoid("key.health", null, null, isWrite: false, Result.Success, cancellationToken);

    /// <summary>
    /// Inclui a versão já gerada, sob a trava. Nome na lixeira → conflito; com <paramref name="requireExisting"/> (rotação), chave
    /// excluída durante a geração → não encontrada. Versão não incluída tem a chave privada zerada.
    /// </summary>
    private Result<VaultKey> Add(string name, Version version, bool requireExisting = false)
    {
        lock (_items.Sync)
        {
            Error? error = _items.IsDeleted(name) ? VaultErrors.Conflict()
                : requireExisting && !_items.Exists(name) ? VaultErrors.NotFound()
                : null;
            if (error is null)
            {
                _items.Add(name, version);
                return ToModel(version);
            }

            CryptographicOperations.ZeroMemory(version.PrivateKeyPkcs8);
            return error;
        }
    }

    /// <summary>Versão a usar numa operação criptográfica, conferindo estado, validade e operação permitida.</summary>
    private Result<Version> Resolve(string name, string? version, VaultKeyOperations operation)
    {
        Version? key;
        lock (_items.Sync)
            key = _items.Find(name, version, v => v.Properties.Version!);

        if (key is null)
            return VaultErrors.NotFound();
        if (!key.Properties.Enabled)
            return VaultErrors.Disabled();
        if (!key.Properties.IsActive(Time.GetUtcNow()) || !key.Operations.HasFlag(operation))
            return VaultErrors.Rejected();
        return key;
    }

    private Result<T> UseRsa<T>(string name, string? version, VaultKeyOperations operation, Func<Version, RSA, T> action)
    {
        var key = Resolve(name, version, operation);
        if (key.IsFailure)
            return key.ToFailure<T>();
        if (key.Value.KeyType != VaultKeyType.Rsa)
            return VaultErrors.Rejected();

        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(key.Value.PrivateKeyPkcs8, out _);
        return action(key.Value, rsa);
    }

    private static Result<byte[]> Sign(Version key, VaultSignatureAlgorithm algorithm, byte[] data)
    {
        if (VaultKeyRules.RsaSignature(algorithm) is { } rsaParameters)
        {
            if (key.KeyType != VaultKeyType.Rsa)
                return VaultErrors.Rejected();
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(key.PrivateKeyPkcs8, out _);
            return rsa.SignData(data, rsaParameters.Hash, rsaParameters.Padding);
        }

        if (VaultKeyRules.EcSignature(algorithm) is not { } ec || key.KeyType != VaultKeyType.Ec || key.Curve != ec.Curve)
            return VaultErrors.Rejected();
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(key.PrivateKeyPkcs8, out _);
        return ecdsa.SignData(data, ec.Hash);   // IEEE P1363 (r||s), o formato do JWS e dos cofres
    }

    private static Result<bool> Verify(Version key, VaultSignatureAlgorithm algorithm, byte[] data, byte[] signature)
    {
        if (VaultKeyRules.RsaSignature(algorithm) is { } rsaParameters)
        {
            if (key.KeyType != VaultKeyType.Rsa)
                return VaultErrors.Rejected();
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(key.PublicKeySpki, out _);
            return rsa.VerifyData(data, signature, rsaParameters.Hash, rsaParameters.Padding);
        }

        if (VaultKeyRules.EcSignature(algorithm) is not { } ec || key.KeyType != VaultKeyType.Ec || key.Curve != ec.Curve)
            return VaultErrors.Rejected();
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportSubjectPublicKeyInfo(key.PublicKeySpki, out _);
        return ecdsa.VerifyData(data, signature, ec.Hash);
    }

    private Version Generate(string name, VaultKeyType type, int keySize, VaultKeyCurve curve, VaultKeyOperations operations,
        bool enabled, DateTimeOffset? notBefore, DateTimeOffset? expiresOn, IReadOnlyDictionary<string, string>? tags)
    {
        byte[] pkcs8;
        byte[] spki;
        if (type == VaultKeyType.Rsa)
        {
            using var rsa = RSA.Create(keySize);
            pkcs8 = rsa.ExportPkcs8PrivateKey();
            spki = rsa.ExportSubjectPublicKeyInfo();
        }
        else
        {
            using var ec = ECDsa.Create(VaultKeyRules.ToECCurve(curve));
            pkcs8 = ec.ExportPkcs8PrivateKey();
            spki = ec.ExportSubjectPublicKeyInfo();
        }

        var now = Time.GetUtcNow();
        string version = NewVersion();
        var properties = new KeyProperties
        {
            Name = name,
            Version = version,
            Id = $"memoria://keys/{name}/{version}",
            Enabled = enabled,
            CreatedOn = now,
            UpdatedOn = now,
            NotBefore = notBefore,
            ExpiresOn = expiresOn,
            Tags = CopyTags(tags)
        };

        return new Version(properties, type, type == VaultKeyType.Rsa ? keySize : null, type == VaultKeyType.Ec ? curve : null,
            operations, pkcs8, spki);
    }

    private static VaultKey ToModel(Version version) => new()
    {
        Properties = version.Properties,
        KeyType = version.KeyType,
        HardwareProtected = false,
        KeySize = version.KeySize,
        Curve = version.Curve,
        Operations = version.Operations,
        PublicKeySpki = [.. version.PublicKeySpki]   // cópia: o chamador não altera a chave guardada
    };
}
