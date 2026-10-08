using System.Collections.Concurrent;
using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.AzureKeyVault.Internal;
using TEC.Vault.Common;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Core.Common.Results;
using AzKeyProperties = Azure.Security.KeyVault.Keys.KeyProperties;
using CreateKeyOptions = TEC.Vault.Keys.CreateKeyOptions;
using KeyProperties = TEC.Vault.Keys.KeyProperties;

namespace TEC.Vault.AzureKeyVault;

/// <summary>
/// Chaves do Azure Key Vault: leitura, gestão, criptografia no cofre, lixeira e backup. Permissões RBAC: uso "Key Vault Crypto User";
/// gerenciamento "Key Vault Crypto Officer". Crie com <c>UseAzureKeyVault</c> (DI) ou <see cref="AzureKeyVaultStores"/>.
/// </summary>
public sealed class AzureKeyVaultKeyStore : AzureKeyVaultStoreBase, IKeyStore, IKeyCryptography, IKeyRecycleBin, IKeyBackup, IVaultHealthProbe
{
    /// <summary>Limite de clientes de criptografia em cache (um por nome + versão).</summary>
    internal const int MaxCryptographyClients = 256;

    // Cliente + instante de criação (TimeProvider.GetTimestamp, monotônico): veja GetCryptographyClient
    private readonly ConcurrentDictionary<(string Name, string Version), (CryptographyClient Client, long CreatedAt)> _cryptographyClients = new();

    internal AzureKeyVaultKeyStore(AzureKeyVaultClients clients, ILogger<AzureKeyVaultKeyStore>? logger = null)
        : base(clients, logger)
    {
    }

    private KeyClient Client => Clients.Keys;

    /// <summary>
    /// Cliente de criptografia reaproveitado por (nome, versão): o <see cref="CryptographyClient"/> busca a chave pública uma vez
    /// por instância, então recriá-lo a cada chamada repetia essa busca em toda operação.
    /// </summary>
    /// <remarks>
    /// <para>Sem versão (= versão atual) o cliente <b>não</b> é guardado: ele fixaria a versão vista na primeira chamada e ignoraria
    /// rotações. Ao passar de <see cref="MaxCryptographyClients"/> entradas o cache é esvaziado (versões antigas saem de uso).</para>
    /// <para>Com a chave pública em mãos, o SDK faz encrypt/wrap/verify <b>localmente</b>, sem consultar o cofre: uma chave
    /// desabilitada continuaria sendo usada enquanto o cliente existisse. Por isso cada cliente vive no máximo
    /// <see cref="AzureKeyVaultOptions.CryptographyClientLifetime"/>; depois é recriado e o estado da chave é lido de novo.</para>
    /// </remarks>
    internal CryptographyClient GetCryptographyClient(string name, string? version)
    {
        if (string.IsNullOrEmpty(version))
            return Client.GetCryptographyClient(name);

        // O Key Vault não diferencia maiúsculas em nomes nem versões
        var key = (name.ToUpperInvariant(), version.ToUpperInvariant());
        long now = Clients.Time.GetTimestamp();
        if (_cryptographyClients.TryGetValue(key, out var cached))
        {
            if (Clients.Time.GetElapsedTime(cached.CreatedAt, now) < Clients.CryptographyClientLifetime)
                return cached.Client;

            // Vencido: sai do cache (só esta entrada; outra thread pode já ter trocado por um cliente novo)
            _cryptographyClients.TryRemove(new KeyValuePair<(string Name, string Version), (CryptographyClient Client, long CreatedAt)>(key, cached));
        }

        if (_cryptographyClients.Count >= MaxCryptographyClients)
            _cryptographyClients.Clear();

        return _cryptographyClients.GetOrAdd(key, _ => (Client.GetCryptographyClient(name, version), now)).Client;
    }

    internal int CachedCryptographyClients => _cryptographyClients.Count;

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.health", null, null, isWrite: false, async ct =>
        {
            // Apenas metadados, uma página de um item: confirma rede, autenticação e permissão de listar chaves
            await foreach (var _ in Client.GetPropertiesOfKeysAsync(ct).AsPages(pageSizeHint: 1).ConfigureAwait(false))
                break;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultKey>> CreateKeyAsync(string name, CreateKeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new CreateKeyOptions();
        var inputError = Rules.CreateKey(name, options, Clients.Time.GetUtcNow());

        return ExecuteAsync<VaultKey>("key.create", name, inputError, isWrite: true, async ct =>
        {
            var operations = options.Operations ?? VaultKeyRules.DefaultOperations(options.KeyType);
            KeyVaultKey key;

            if (options.KeyType == VaultKeyType.Rsa)
            {
                var rsa = new CreateRsaKeyOptions(name, hardwareProtected: options.HardwareProtected)
                {
                    KeySize = options.KeySize,
                    Enabled = options.Enabled,
                    ExpiresOn = options.ExpiresOn,
                    NotBefore = options.NotBefore
                };
                AddOperations(rsa.KeyOperations, operations);
                ReplaceTags(rsa.Tags, options.Tags);
                key = await Client.CreateRsaKeyAsync(rsa, ct).ConfigureAwait(false);
            }
            else
            {
                var ec = new CreateEcKeyOptions(name, hardwareProtected: options.HardwareProtected)
                {
                    CurveName = ToAzure(options.Curve),
                    Enabled = options.Enabled,
                    ExpiresOn = options.ExpiresOn,
                    NotBefore = options.NotBefore
                };
                AddOperations(ec.KeyOperations, operations);
                ReplaceTags(ec.Tags, options.Tags);
                key = await Client.CreateEcKeyAsync(ec, ct).ConfigureAwait(false);
            }

            return ToModel(key);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultKey>> GetKeyAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultKey>("key.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            KeyVaultKey key = await Client.GetKeyAsync(name, version, ct).ConfigureAwait(false);
            return ToModel(key);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeysAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<KeyProperties>>("key.list", null, null, isWrite: false, async ct =>
        {
            var list = new List<KeyProperties>();
            await foreach (var properties in Client.GetPropertiesOfKeysAsync(ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToModel(properties));
            }
            return list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeyVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<KeyProperties>>("key.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var list = new List<KeyProperties>();
            await foreach (var properties in Client.GetPropertiesOfKeyVersionsAsync(name, ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToModel(properties));
            }
            return list.Count == 0 ? VaultErrors.NotFound() : list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultKey>> UpdateKeyPropertiesAsync(string name, KeyPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateKey(name, version, update, Clients.Time.GetUtcNow());

        return ExecuteAsync<VaultKey>("key.update", name, inputError, isWrite: true, async ct =>
        {
            // Metadados obtidos pela listagem de versões: um GET da chave responde 403 KeyDisabled para versão desabilitada,
            // o que impediria reabilitá-la
            var versions = new List<AzKeyProperties>();
            await foreach (var item in Client.GetPropertiesOfKeyVersionsAsync(name, ct).ConfigureAwait(false))
                versions.Add(item);

            AzKeyProperties? properties;
            if (version is not null)
            {
                properties = versions.Find(p => string.Equals(p.Version, version, StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                // Versão atual = a mais recente por CreatedOn; em empate (resolução de 1 segundo) só o GET sem versão responde
                // de forma confiável, e com a versão atual desabilitada vale o desempate determinístico pelos metadados
                var newest = VaultVersionRules.Newest(versions, p => p.CreatedOn);
                if (newest.Count > 1)
                {
                    try
                    {
                        KeyVaultKey current = await Client.GetKeyAsync(name, null, ct).ConfigureAwait(false);
                        properties = versions.Find(p => string.Equals(p.Version, current.Properties.Version, StringComparison.OrdinalIgnoreCase));
                    }
                    catch (RequestFailedException ex) when (IsDisabledFailure(ex))
                    {
                        // Outros 403 (RBAC, firewall, rede privada) seguem como erro: alterar a versão errada seria pior que falhar
                        properties = VaultVersionRules.BreakTie(newest, p => p.UpdatedOn, p => p.Version);
                    }
                }
                else
                {
                    properties = newest.Count == 1 ? newest[0] : null;
                }
            }

            if (properties is null)
                return VaultErrors.NotFound();

            if (update.Enabled is { } enabled) properties.Enabled = enabled;
            if (update.ExpiresOn is { } expiresOn) properties.ExpiresOn = expiresOn;
            if (update.NotBefore is { } notBefore) properties.NotBefore = notBefore;
            ReplaceTags(properties.Tags, update.Tags);

            KeyOperation[]? operations = update.Operations is { } requested ? [.. ToAzure(requested)] : null;
            KeyVaultKey updated = await Client.UpdateKeyPropertiesAsync(properties, operations, ct).ConfigureAwait(false);
            return ToModel(updated);
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultKey>> RotateKeyAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultKey>("key.rotate", name, Rules.Name(name), isWrite: true, async ct =>
        {
            KeyVaultKey key = await Client.RotateKeyAsync(name, ct).ConfigureAwait(false);
            return ToModel(key);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<DeletedVaultItem>> DeleteKeyAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<DeletedVaultItem>("key.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var timeout = WithOperationTimeout(ct);
            var operation = await Client.StartDeleteKeyAsync(name, timeout.Token).ConfigureAwait(false);
            DeletedKey deleted = await operation.WaitForCompletionAsync(timeout.Token).ConfigureAwait(false);
            return ToDeleted(deleted.Name, deleted.DeletedOn, deleted.ScheduledPurgeDate);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<DeletedVaultItem>>> ListDeletedKeysAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<DeletedVaultItem>>("key.list-deleted", null, null, isWrite: false, async ct =>
        {
            var list = new List<DeletedVaultItem>();
            await foreach (var deleted in Client.GetDeletedKeysAsync(ct).ConfigureAwait(false))
            {
                EnsureListLimit(list.Count + 1, Clients.MaxListItems);
                list.Add(ToDeleted(deleted.Name, deleted.DeletedOn, deleted.ScheduledPurgeDate));
            }
            return list;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultKey>> RecoverDeletedKeyAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultKey>("key.recover", name, Rules.Name(name), isWrite: true, async ct =>
        {
            using var timeout = WithOperationTimeout(ct);
            var operation = await Client.StartRecoverDeletedKeyAsync(name, timeout.Token).ConfigureAwait(false);
            KeyVaultKey key = await operation.WaitForCompletionAsync(timeout.Token).ConfigureAwait(false);
            return ToModel(key);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> PurgeDeletedKeyAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.purge", name, Rules.Name(name), isWrite: true, ct => Client.PurgeDeletedKeyAsync(name, ct), cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> BackupKeyAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync<byte[]>("key.backup", name, Rules.Name(name), isWrite: true, async ct =>
        {
            byte[] backup = await Client.BackupKeyAsync(name, ct).ConfigureAwait(false);
            return backup;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultKey>> RestoreKeyBackupAsync(byte[] backup, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultKey>("key.restore", null, Rules.Backup(backup), isWrite: true, async ct =>
        {
            KeyVaultKey key = await Client.RestoreKeyBackupAsync(backup, ct).ConfigureAwait(false);
            return ToModel(key);
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultEncryptResult>> EncryptAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultEncryptResult>("key.encrypt", name,
            Rules.Encrypt(name, version, algorithm, plaintext, "plaintext"),
            isWrite: false, async ct =>
            {
                var crypto = GetCryptographyClient(name, version);
                EncryptResult result = await crypto.EncryptAsync(EncryptionAlgorithm.RsaOaep256, plaintext, ct).ConfigureAwait(false);
                return new VaultEncryptResult(name, VersionOf(result.KeyId), algorithm, result.Ciphertext);
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> DecryptAsync(string name, string version, byte[] ciphertext,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) =>
        ExecuteAsync<byte[]>("key.decrypt", name,
            Rules.Decrypt(name, version, algorithm, ciphertext, "ciphertext"),
            isWrite: false, async ct =>
            {
                var crypto = GetCryptographyClient(name, version);
                DecryptResult result = await crypto.DecryptAsync(EncryptionAlgorithm.RsaOaep256, ciphertext, ct).ConfigureAwait(false);
                return result.Plaintext;
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultEncryptResult>> WrapKeyAsync(string name, byte[] key, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultEncryptResult>("key.wrap", name,
            Rules.Encrypt(name, version, algorithm, key, "key"),
            isWrite: false, async ct =>
            {
                var crypto = GetCryptographyClient(name, version);
                WrapResult result = await crypto.WrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, key, ct).ConfigureAwait(false);
                return new VaultEncryptResult(name, VersionOf(result.KeyId), algorithm, result.EncryptedKey);
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> UnwrapKeyAsync(string name, string version, byte[] wrappedKey,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) =>
        ExecuteAsync<byte[]>("key.unwrap", name,
            Rules.Decrypt(name, version, algorithm, wrappedKey, "wrappedKey"),
            isWrite: false, async ct =>
            {
                var crypto = GetCryptographyClient(name, version);
                UnwrapResult result = await crypto.UnwrapKeyAsync(KeyWrapAlgorithm.RsaOaep256, wrappedKey, ct).ConfigureAwait(false);
                return result.Key;
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultSignResult>> SignDataAsync(string name, byte[] data, VaultSignatureAlgorithm algorithm, string? version = null,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<VaultSignResult>("key.sign", name,
            Rules.Sign(name, version, algorithm, data),
            isWrite: false, async ct =>
            {
                var crypto = GetCryptographyClient(name, version);
                SignResult result = await crypto.SignDataAsync(ToAzure(algorithm), data, ct).ConfigureAwait(false);
                return new VaultSignResult(name, VersionOf(result.KeyId), algorithm, result.Signature);
            }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> VerifyDataAsync(string name, string version, byte[] data, byte[] signature, VaultSignatureAlgorithm algorithm,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync<bool>("key.verify", name,
            Rules.Verify(name, version, algorithm, data, signature),
            isWrite: false, async ct =>
            {
                var crypto = GetCryptographyClient(name, version);
                VerifyResult result = await crypto.VerifyDataAsync(ToAzure(algorithm), data, signature, ct).ConfigureAwait(false);
                return result.IsValid;
            }, cancellationToken);

    private static string VersionOf(string keyId) => new KeyVaultKeyIdentifier(new Uri(keyId)).Version;

    private static void AddOperations(IList<KeyOperation> target, VaultKeyOperations operations)
    {
        target.Clear();
        foreach (var operation in ToAzure(operations))
            target.Add(operation);
    }

    private static IEnumerable<KeyOperation> ToAzure(VaultKeyOperations operations)
    {
        if (operations.HasFlag(VaultKeyOperations.Encrypt)) yield return KeyOperation.Encrypt;
        if (operations.HasFlag(VaultKeyOperations.Decrypt)) yield return KeyOperation.Decrypt;
        if (operations.HasFlag(VaultKeyOperations.Sign)) yield return KeyOperation.Sign;
        if (operations.HasFlag(VaultKeyOperations.Verify)) yield return KeyOperation.Verify;
        if (operations.HasFlag(VaultKeyOperations.WrapKey)) yield return KeyOperation.WrapKey;
        if (operations.HasFlag(VaultKeyOperations.UnwrapKey)) yield return KeyOperation.UnwrapKey;
    }

    private static VaultKeyOperations FromAzure(IEnumerable<KeyOperation> operations)
    {
        var result = VaultKeyOperations.None;
        foreach (var operation in operations)
        {
            if (operation == KeyOperation.Encrypt) result |= VaultKeyOperations.Encrypt;
            else if (operation == KeyOperation.Decrypt) result |= VaultKeyOperations.Decrypt;
            else if (operation == KeyOperation.Sign) result |= VaultKeyOperations.Sign;
            else if (operation == KeyOperation.Verify) result |= VaultKeyOperations.Verify;
            else if (operation == KeyOperation.WrapKey) result |= VaultKeyOperations.WrapKey;
            else if (operation == KeyOperation.UnwrapKey) result |= VaultKeyOperations.UnwrapKey;
        }

        return result;
    }

    internal static KeyCurveName ToAzure(VaultKeyCurve curve) => curve switch
    {
        VaultKeyCurve.P256 => KeyCurveName.P256,
        VaultKeyCurve.P384 => KeyCurveName.P384,
        VaultKeyCurve.P521 => KeyCurveName.P521,
        _ => throw new NotSupportedException()
    };

    private static SignatureAlgorithm ToAzure(VaultSignatureAlgorithm algorithm) => algorithm switch
    {
        VaultSignatureAlgorithm.RS256 => SignatureAlgorithm.RS256,
        VaultSignatureAlgorithm.RS384 => SignatureAlgorithm.RS384,
        VaultSignatureAlgorithm.RS512 => SignatureAlgorithm.RS512,
        VaultSignatureAlgorithm.PS256 => SignatureAlgorithm.PS256,
        VaultSignatureAlgorithm.PS384 => SignatureAlgorithm.PS384,
        VaultSignatureAlgorithm.PS512 => SignatureAlgorithm.PS512,
        VaultSignatureAlgorithm.ES256 => SignatureAlgorithm.ES256,
        VaultSignatureAlgorithm.ES384 => SignatureAlgorithm.ES384,
        VaultSignatureAlgorithm.ES512 => SignatureAlgorithm.ES512,
        _ => throw new NotSupportedException()
    };

    internal static KeyProperties ToModel(AzKeyProperties properties) => new()
    {
        Name = properties.Name,
        Version = properties.Version,
        Id = properties.Id?.ToString(),
        Enabled = properties.Enabled ?? false,
        CreatedOn = properties.CreatedOn,
        UpdatedOn = properties.UpdatedOn,
        ExpiresOn = properties.ExpiresOn,
        NotBefore = properties.NotBefore,
        ManagedBy = ToManagedBy(properties.Managed),
        Exportable = properties.Exportable ?? false,
        Tags = CopyTags(properties.Tags)
    };

    internal static VaultKey ToModel(KeyVaultKey key)
    {
        var jwk = key.Key;
        VaultKeyType type;
        bool hardware;
        VaultKeyCurve? curve = null;
        int? size = null;
        byte[] spki;

        if (key.KeyType == KeyType.Rsa || key.KeyType == KeyType.RsaHsm)
        {
            type = VaultKeyType.Rsa;
            hardware = key.KeyType == KeyType.RsaHsm;
            size = jwk.N?.Length * 8;
            using var rsa = jwk.ToRSA(includePrivateParameters: false);
            spki = rsa.ExportSubjectPublicKeyInfo();
        }
        else if (key.KeyType == KeyType.Ec || key.KeyType == KeyType.EcHsm)
        {
            type = VaultKeyType.Ec;
            hardware = key.KeyType == KeyType.EcHsm;
            curve = jwk.CurveName == KeyCurveName.P256 ? VaultKeyCurve.P256
                : jwk.CurveName == KeyCurveName.P384 ? VaultKeyCurve.P384
                : jwk.CurveName == KeyCurveName.P521 ? VaultKeyCurve.P521
                : throw new NotSupportedException();
            using var ec = jwk.ToECDsa(includePrivateParameters: false);
            spki = ec.ExportSubjectPublicKeyInfo();
        }
        else
        {
            // Chaves simétricas (oct) só existem no Managed HSM, que não é suportado por este provedor
            throw new NotSupportedException();
        }

        return new VaultKey
        {
            Properties = ToModel(key.Properties),
            KeyType = type,
            HardwareProtected = hardware,
            Curve = curve,
            KeySize = size,
            Operations = FromAzure(key.KeyOperations),
            PublicKeySpki = spki
        };
    }
}
