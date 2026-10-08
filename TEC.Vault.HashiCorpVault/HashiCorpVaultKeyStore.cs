using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.HashiCorpVault.Internal;
using TEC.Vault.Keys;
using TEC.Vault.Providers;
using TEC.Vault.Providers.Http;
using TEC.Core.Common.Results;
using TEC.Core.Text.Codecs;

namespace TEC.Vault.HashiCorpVault;

/// <summary>
/// Chaves no Transit do HashiCorp Vault: RSA (2048, 3072, 4096) e EC (P-256, P-384, P-521). Criptografar, decifrar, wrap/unwrap
/// e assinar são executados no Vault: a chave privada nunca sai dele.
/// </summary>
/// <remarks>
/// <para><b>Versões</b>: as do Transit (inteiros). Criar uma chave que já existe, com o mesmo tipo, gera uma nova versão (como
/// rotacionar); com outro tipo retorna <see cref="VaultErrors.Conflict"/>.</para>
/// <para><b>Proteção por hardware</b> (<see cref="CreateKeyOptions.HardwareProtected"/>) retorna <see cref="VaultErrors.NotSupported"/>.
/// <b>Sem equivalente no Transit</b> (retornam <see cref="VaultErrors.InvalidInput"/>): validade, habilitar/desabilitar, tags e
/// restrição de operações. Sem lixeira nem backup: a exclusão é definitiva (o provedor liga
/// <c>deletion_allowed</c> antes de excluir; a operação é auditada), e o backup do Transit exporta a chave em texto aberto,
/// por isso não é oferecido.</para>
/// <para>Criptografia RSA usa OAEP com SHA-256 (padrão do Transit). Assinatura RSA-PSS usa salt do tamanho do hash, e ECDSA usa o
/// formato IEEE P1363 (r‖s), o mesmo dos demais provedores.</para>
/// <para><b>Upsert do Transit</b>: cifrar com um nome inexistente cria uma chave AES se o token puder criar. Antes de cifrar ou
/// fazer wrap, o provedor confere (sem cache) que a chave existe e é RSA; ainda assim, dê à aplicação só <c>update</c> em
/// <c>transit/encrypt/*</c> (sem <c>create</c>) na política do Vault.</para>
/// <para>O tipo de cada chave fica em cache por 5 minutos para conferir o algoritmo antes de assinar (o Transit assinaria com a
/// curva da chave mesmo pedindo outro algoritmo).</para>
/// </remarks>
public sealed class HashiCorpVaultKeyStore : HashiCorpVaultStoreBase, IKeyStore, IKeyCryptography, IVaultHealthProbe
{
    private static readonly TimeSpan ShapeCacheLifetime = TimeSpan.FromMinutes(5);

    private sealed record KeyInfo(string Name, VaultKeyType Type, int? Size, VaultKeyCurve? Curve, bool Exportable, int Latest, int MinDecryption,
        SortedDictionary<int, (DateTimeOffset? CreatedOn, byte[]? Spki)> Versions);

    private readonly ConcurrentDictionary<string, (VaultKeyType Type, VaultKeyCurve? Curve, DateTimeOffset At)> _shapes = new(StringComparer.Ordinal);

    /// <summary>Cria o store com conexão própria. As opções são validadas aqui.</summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public HashiCorpVaultKeyStore(HashiCorpVaultOptions options, ILogger<HashiCorpVaultKeyStore>? logger = null)
        : this(new HashiCorpVaultClient(options), ownsClient: true, logger)
    {
    }

    internal HashiCorpVaultKeyStore(HashiCorpVaultClient client, bool ownsClient, ILogger<HashiCorpVaultKeyStore>? logger)
        : base(client, ownsClient, logger)
    {
    }

    private string Mount => VaultEndpoint.Path(Client.Options.Transit.Mount);

    // ---------- Leitura ----------

    /// <inheritdoc />
    public Task<Result<VaultKey>> GetKeyAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.get", name, Rules.Item(name, version), isWrite: false, async ct =>
        {
            var info = await ReadAsync(name, ct).ConfigureAwait(false);
            if (info is null)
                return VaultErrors.NotFound();
            var number = ParseVersion(version) ?? info.Latest;
            return info.Versions.ContainsKey(number) && number >= info.MinDecryption
                ? Result<VaultKey>.Success(Model(info, number))
                : VaultErrors.NotFound();
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks>Chaves de tipos que o TEC.Vault não representa (AES, Ed25519, HMAC) não aparecem.</remarks>
    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeysAsync(CancellationToken cancellationToken = default) =>
        ExecuteAsync<IReadOnlyList<KeyProperties>>("key.list", null, null, isWrite: false, async ct =>
        {
            var names = await Client.ListAsync(HashiCorpVaultClient.Path(Mount, "keys"), ct).ConfigureAwait(false);
            EnsureListLimit(names.Count, Client.Options.MaxListItems);
            var result = new List<KeyProperties>();
            foreach (var name in names)
            {
                if (Rules.Name(name) is null && await ReadAsync(name, ct, exactOnly: true).ConfigureAwait(false) is { } info)
                    result.Add(Properties(info, info.Latest));
            }

            return result;
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<KeyProperties>>> ListKeyVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.versions", name, Rules.Name(name), isWrite: false, async ct =>
        {
            var info = await ReadAsync(name, ct).ConfigureAwait(false);
            if (info is null)
                return VaultErrors.NotFound();
            EnsureListLimit(info.Versions.Keys.Count(v => v >= info.MinDecryption), Client.Options.MaxListItems);
            return Result<IReadOnlyList<KeyProperties>>.Success(info.Versions.Keys.Where(v => v >= info.MinDecryption).Select(v => Properties(info, v)).ToList());
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result> CheckAccessAsync(CancellationToken cancellationToken = default) =>
        RunAsync("key.health", null, null, isWrite: false, async ct =>
        {
            await Client.ListAsync(HashiCorpVaultClient.Path(Mount, "keys"), ct).ConfigureAwait(false);
            return Result.Success();
        }, cancellationToken);

    // ---------- Gestão ----------

    /// <inheritdoc />
    public Task<Result<VaultKey>> CreateKeyAsync(string name, CreateKeyOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new CreateKeyOptions();
        var inputError = Rules.CreateKey(name, options, Time.GetUtcNow()) ??
            (options.ExpiresOn is not null || options.NotBefore is not null || !options.Enabled || options.Tags is { Count: > 0 } ||
             (options.Operations is { } ops && ops != VaultKeyRules.DefaultOperations(options.KeyType))
                ? VaultErrors.InvalidInput("options", "O Transit não tem validade, habilitar/desabilitar, tags nem restrição de operações.")
                : null);

        return ExecuteAsync("key.create", name, inputError, isWrite: true, async ct =>
        {
            if (options.HardwareProtected)
                return VaultErrors.NotSupported();

            var type = TransitType(options);
            var existing = await ReadAsync(name, ct).ConfigureAwait(false);
            if (existing is not null)
            {
                if (TransitType(existing) != type)
                    return VaultErrors.Conflict();
                return await RotateCoreAsync(existing.Name, ct).ConfigureAwait(false);
            }

            var body = HashiCorpVaultClient.Json(w =>
            {
                w.WriteString("type", type);
                w.WriteBoolean("exportable", false);
                w.WriteBoolean("allow_plaintext_backup", false);
            });
            using (await Client.SendAsync(HttpMethod.Post, HashiCorpVaultClient.Path(Mount, "keys", VaultEndpoint.Segment(name)), body,
                       idempotent: true, ct).ConfigureAwait(false))
            {
            }

            var created = await ReadAsync(name, ct, exactOnly: true).ConfigureAwait(false);
            return created is null ? VaultErrors.ProviderFailure() : Result<VaultKey>.Success(Model(created, created.Latest));
        }, cancellationToken);
    }

    /// <inheritdoc />
    /// <remarks>O Transit não tem metadados alteráveis equivalentes: só uma alteração vazia é aceita (devolve a chave).</remarks>
    public Task<Result<VaultKey>> UpdateKeyPropertiesAsync(string name, KeyPropertiesUpdate update, string? version = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);
        var inputError = Rules.UpdateKey(name, version, update, Time.GetUtcNow()) ??
            (update.Enabled is not null || update.ExpiresOn is not null || update.NotBefore is not null || update.Operations is not null || update.Tags is not null
                ? VaultErrors.InvalidInput("update", "O Transit não tem validade, habilitar/desabilitar, tags nem restrição de operações.")
                : null);

        return ExecuteAsync("key.update", name, inputError, isWrite: true, async ct =>
        {
            var info = await ReadAsync(name, ct).ConfigureAwait(false);
            var number = ParseVersion(version) ?? info?.Latest;
            return info is not null && info.Versions.ContainsKey(number!.Value)
                ? Result<VaultKey>.Success(Model(info, number.Value))
                : VaultErrors.NotFound();
        }, cancellationToken);
    }

    /// <inheritdoc />
    public Task<Result<VaultKey>> RotateKeyAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.rotate", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var info = await ReadAsync(name, ct).ConfigureAwait(false);
            return info is null ? VaultErrors.NotFound() : await RotateCoreAsync(info.Name, ct).ConfigureAwait(false);
        }, cancellationToken);

    /// <inheritdoc />
    /// <remarks><b>Definitivo</b>: o Transit não tem lixeira. Dados cifrados com a chave ficam irrecuperáveis.</remarks>
    public Task<Result<DeletedVaultItem>> DeleteKeyAsync(string name, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.delete", name, Rules.Name(name), isWrite: true, async ct =>
        {
            var info = await ReadAsync(name, ct).ConfigureAwait(false);
            if (info is null)
                return VaultErrors.NotFound();

            var keyPath = HashiCorpVaultClient.Path(Mount, "keys", VaultEndpoint.Segment(info.Name));
            using (await Client.SendAsync(HttpMethod.Post, keyPath + "/config", HashiCorpVaultClient.Json(w => w.WriteBoolean("deletion_allowed", true)),
                       idempotent: true, ct).ConfigureAwait(false))
            {
            }

            using (await Client.SendAsync(HttpMethod.Delete, keyPath, null, idempotent: true, ct).ConfigureAwait(false))
            {
            }

            _shapes.TryRemove(info.Name, out _);
            return Result<DeletedVaultItem>.Success(new DeletedVaultItem(info.Name, Time.GetUtcNow(), ScheduledPurgeDate: null));
        }, cancellationToken);

    // ---------- Criptografia ----------

    /// <inheritdoc />
    public Task<Result<VaultEncryptResult>> EncryptAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.encrypt", name, Rules.Encrypt(name, version, algorithm, plaintext, "plaintext"), isWrite: false,
            ct => EncryptCoreAsync(name, plaintext, algorithm, version, ct), cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> DecryptAsync(string name, string version, byte[] ciphertext,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.decrypt", name, Rules.Decrypt(name, version, algorithm, ciphertext, "ciphertext"), isWrite: false,
            ct => DecryptCoreAsync(name, version, ciphertext, ct), cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultEncryptResult>> WrapKeyAsync(string name, byte[] key, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.wrap", name, Rules.Encrypt(name, version, algorithm, key, "key"), isWrite: false,
            ct => EncryptCoreAsync(name, key, algorithm, version, ct), cancellationToken);

    /// <inheritdoc />
    public Task<Result<byte[]>> UnwrapKeyAsync(string name, string version, byte[] wrappedKey,
        VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.unwrap", name, Rules.Decrypt(name, version, algorithm, wrappedKey, "wrappedKey"), isWrite: false,
            ct => DecryptCoreAsync(name, version, wrappedKey, ct), cancellationToken);

    /// <inheritdoc />
    public Task<Result<VaultSignResult>> SignDataAsync(string name, byte[] data, VaultSignatureAlgorithm algorithm, string? version = null,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.sign", name, Rules.Sign(name, version, algorithm, data), isWrite: false, async ct =>
        {
            var shape = await ShapeAsync(name, ct).ConfigureAwait(false);
            if (shape is null)
                return VaultErrors.NotFound();
            if (ParametersFor(algorithm, shape.Value.Type, shape.Value.Curve) is not { } parameters)
                return VaultErrors.Rejected();

            var body = HashiCorpVaultClient.Json(w =>
            {
                w.WriteBase64String("input", data);
                if (version is not null)
                    w.WriteNumber("key_version", ParseVersion(version)!.Value);
                parameters.Write(w);
            });
            using var response = await Client.SendAsync(HttpMethod.Post,
                HashiCorpVaultClient.Path(Mount, "sign", VaultEndpoint.Segment(name), parameters.Hash), body, idempotent: true, ct).ConfigureAwait(false);
            var (signatureVersion, signature) = ParseVaultValue(VaultJson.String(response!.Data, "signature"), parameters.Url);
            return Result<VaultSignResult>.Success(new VaultSignResult(name, signatureVersion, algorithm, signature));
        }, cancellationToken);

    /// <inheritdoc />
    public Task<Result<bool>> VerifyDataAsync(string name, string version, byte[] data, byte[] signature, VaultSignatureAlgorithm algorithm,
        CancellationToken cancellationToken = default) =>
        ExecuteAsync("key.verify", name, Rules.Verify(name, version, algorithm, data, signature), isWrite: false, async ct =>
        {
            var shape = await ShapeAsync(name, ct).ConfigureAwait(false);
            if (shape is null)
                return VaultErrors.NotFound();
            if (ParametersFor(algorithm, shape.Value.Type, shape.Value.Curve) is not { } parameters)
                return VaultErrors.Rejected();

            var encoded = parameters.Url ? Base64UrlEncoder.Encode(signature) : Convert.ToBase64String(signature);
            var body = HashiCorpVaultClient.Json(w =>
            {
                w.WriteBase64String("input", data);
                w.WriteString("signature", $"vault:v{version}:{encoded}");
                parameters.Write(w);
            });
            using var response = await Client.SendAsync(HttpMethod.Post,
                HashiCorpVaultClient.Path(Mount, "verify", VaultEndpoint.Segment(name), parameters.Hash), body, idempotent: true, ct).ConfigureAwait(false);
            return Result<bool>.Success(response!.Data.TryGetProperty("valid", out var valid) && valid.ValueKind == JsonValueKind.True);
        }, cancellationToken);

    // ---------- Implementação ----------

    private async Task<Result<VaultEncryptResult>> EncryptCoreAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm, string? version,
        CancellationToken ct)
    {
        if (await RsaKeyErrorAsync(name, fresh: true, ct).ConfigureAwait(false) is { } error)
            return error;

        var body = HashiCorpVaultClient.Json(w =>
        {
            w.WriteBase64String("plaintext", plaintext);
            if (version is not null)
                w.WriteNumber("key_version", ParseVersion(version)!.Value);
            w.WriteString("padding_scheme", "oaep");
        });
        using var response = await Client.SendAsync(HttpMethod.Post, HashiCorpVaultClient.Path(Mount, "encrypt", VaultEndpoint.Segment(name)), body,
            idempotent: true, ct).ConfigureAwait(false);
        var (keyVersion, ciphertext) = ParseVaultValue(VaultJson.String(response!.Data, "ciphertext"), url: false);
        return new VaultEncryptResult(name, keyVersion, algorithm, ciphertext);
    }

    private async Task<Result<byte[]>> DecryptCoreAsync(string name, string version, byte[] ciphertext, CancellationToken ct)
    {
        if (await RsaKeyErrorAsync(name, fresh: false, ct).ConfigureAwait(false) is { } error)
            return error;

        var body = HashiCorpVaultClient.Json(w =>
        {
            w.WriteString("ciphertext", $"vault:v{version}:{Convert.ToBase64String(ciphertext)}");
            w.WriteString("padding_scheme", "oaep");
        });
        using var response = await Client.SendAsync(HttpMethod.Post, HashiCorpVaultClient.Path(Mount, "decrypt", VaultEndpoint.Segment(name)), body,
            idempotent: true, ct).ConfigureAwait(false);
        var plaintext = response!.Data.TryGetProperty("plaintext", out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetBytesFromBase64()
            : throw new JsonException("Resposta sem plaintext.");
        return plaintext;
    }

    /// <summary>
    /// Confere que a chave existe e é RSA antes de cifrar/decifrar: o Transit criaria uma chave AES ao cifrar com um nome
    /// inexistente (upsert) se o token tiver permissão de criação.
    /// </summary>
    private async Task<Error?> RsaKeyErrorAsync(string name, bool fresh, CancellationToken ct)
    {
        if (fresh)
            _shapes.TryRemove(name, out _);   // cifrar com chave excluída por outra instância criaria uma chave AES (upsert)
        var shape = await ShapeAsync(name, ct).ConfigureAwait(false);
        if (shape is null)
            return VaultErrors.NotFound();
        return shape.Value.Type == VaultKeyType.Rsa ? null : VaultErrors.Rejected();
    }

    private async Task<Result<VaultKey>> RotateCoreAsync(string name, CancellationToken ct)
    {
        using (await Client.SendAsync(HttpMethod.Post, HashiCorpVaultClient.Path(Mount, "keys", VaultEndpoint.Segment(name), "rotate"), null,
                   idempotent: false, ct).ConfigureAwait(false))
        {
        }

        var info = await ReadAsync(name, ct, exactOnly: true).ConfigureAwait(false);
        return info is null ? VaultErrors.NotFound() : Result<VaultKey>.Success(Model(info, info.Latest));
    }

    /// <summary>Chave pelo nome exato ou, sem ela, pelo único nome igual sem diferenciar maiúsculas. Tipo não suportado → <c>null</c>.</summary>
    private async Task<KeyInfo?> ReadAsync(string name, CancellationToken ct, bool exactOnly = false)
    {
        using (var response = await Client.GetAsync(HashiCorpVaultClient.Path(Mount, "keys", VaultEndpoint.Segment(name)), ct).ConfigureAwait(false))
        {
            if (response is not null)
                return Parse(name, response.Data);
        }

        if (exactOnly)
            return null;

        var names = await Client.ListAsync(HashiCorpVaultClient.Path(Mount, "keys"), ct).ConfigureAwait(false);
        if (names.Count > Client.Options.MaxListItems)
            throw new VaultListLimitExceededException(Client.Options.MaxListItems);
        var match = names
            .Where(n => !string.Equals(n, name, StringComparison.Ordinal) && string.Equals(n, name, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return match.Count == 1 ? await ReadAsync(match[0], ct, exactOnly: true).ConfigureAwait(false) : null;
    }

    private async Task<(VaultKeyType Type, VaultKeyCurve? Curve)?> ShapeAsync(string name, CancellationToken ct)
    {
        var now = Time.GetUtcNow();
        if (_shapes.TryGetValue(name, out var cached) && now - cached.At < ShapeCacheLifetime)
            return (cached.Type, cached.Curve);

        var info = await ReadAsync(name, ct, exactOnly: true).ConfigureAwait(false);
        if (info is null)
            return null;
        _shapes[name] = (info.Type, info.Curve, now);
        return (info.Type, info.Curve);
    }

    private static KeyInfo? Parse(string name, JsonElement data)
    {
        var type = VaultJson.String(data, "type");
        (VaultKeyType Type, int? Size, VaultKeyCurve? Curve)? shape = type switch
        {
            "rsa-2048" => (VaultKeyType.Rsa, 2048, null),
            "rsa-3072" => (VaultKeyType.Rsa, 3072, null),
            "rsa-4096" => (VaultKeyType.Rsa, 4096, null),
            "ecdsa-p256" => (VaultKeyType.Ec, null, VaultKeyCurve.P256),
            "ecdsa-p384" => (VaultKeyType.Ec, null, VaultKeyCurve.P384),
            "ecdsa-p521" => (VaultKeyType.Ec, null, VaultKeyCurve.P521),
            _ => null
        };
        if (shape is not { } s)
            return null;

        var versions = new SortedDictionary<int, (DateTimeOffset?, byte[]?)>();
        if (data.TryGetProperty("keys", out var keys) && keys.ValueKind == JsonValueKind.Object)
        {
            foreach (var key in keys.EnumerateObject())
            {
                if (!int.TryParse(key.Name, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || key.Value.ValueKind != JsonValueKind.Object)
                    continue;
                versions[number] = (VaultJson.Date(key.Value, "creation_time"), Spki(VaultJson.String(key.Value, "public_key")));
            }
        }

        var latest = data.TryGetProperty("latest_version", out var l) && l.TryGetInt32(out var lv) ? lv : versions.Keys.LastOrDefault();
        var minDecryption = data.TryGetProperty("min_decryption_version", out var m) && m.TryGetInt32(out var mv) ? mv : 1;
        var exportable = data.TryGetProperty("exportable", out var e) && e.ValueKind == JsonValueKind.True;
        return new KeyInfo(VaultJson.String(data, "name") ?? name, s.Type, s.Size, s.Curve, exportable, latest, minDecryption, versions);
    }

    private static byte[]? Spki(string? pem)
    {
        if (string.IsNullOrEmpty(pem) || !System.Security.Cryptography.PemEncoding.TryFind(pem, out var fields) ||
            !pem.AsSpan()[fields.Label].SequenceEqual("PUBLIC KEY"))
            return null;
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }

    private static string TransitType(CreateKeyOptions options) => options.KeyType == VaultKeyType.Rsa
        ? "rsa-" + options.KeySize.ToString(CultureInfo.InvariantCulture)
        : options.Curve switch
        {
            VaultKeyCurve.P384 => "ecdsa-p384",
            VaultKeyCurve.P521 => "ecdsa-p521",
            _ => "ecdsa-p256"
        };

    private static string TransitType(KeyInfo info) => TransitType(new CreateKeyOptions
    {
        KeyType = info.Type,
        KeySize = info.Size ?? 3072,
        Curve = info.Curve ?? VaultKeyCurve.P256
    });

    private KeyProperties Properties(KeyInfo info, int version) => new()
    {
        Name = info.Name,
        Version = Text(version),
        Id = $"{Client.Options.Transit.Mount}/keys/{info.Name}",
        Enabled = true,
        CreatedOn = info.Versions.TryGetValue(version, out var v) ? v.CreatedOn : null,
        Exportable = info.Exportable
    };

    private VaultKey Model(KeyInfo info, int version) => new()
    {
        Properties = Properties(info, version),
        KeyType = info.Type,
        KeySize = info.Size,
        Curve = info.Curve,
        Operations = VaultKeyRules.DefaultOperations(info.Type),
        PublicKeySpki = info.Versions.TryGetValue(version, out var v) ? v.Spki : null
    };

    private sealed record SignatureParameters(string Hash, string? Padding, bool Url)
    {
        public void Write(Utf8JsonWriter writer)
        {
            writer.WriteBoolean("prehashed", false);
            if (Padding is not null)
            {
                writer.WriteString("signature_algorithm", Padding);
                if (Padding == "pss")
                    writer.WriteString("salt_length", "hash");
            }
            else
                writer.WriteString("marshaling_algorithm", "jws");
        }
    }

    /// <summary>Parâmetros do Transit para o algoritmo, ou <c>null</c> se o algoritmo não combina com a chave.</summary>
    private static SignatureParameters? ParametersFor(VaultSignatureAlgorithm algorithm, VaultKeyType type, VaultKeyCurve? curve)
    {
        if (VaultKeyRules.RsaSignature(algorithm) is { } rsa)
        {
            return type != VaultKeyType.Rsa
                ? null
                : new SignatureParameters(HashName(rsa.Hash), rsa.Padding == System.Security.Cryptography.RSASignaturePadding.Pss ? "pss" : "pkcs1v15", Url: false);
        }

        return VaultKeyRules.EcSignature(algorithm) is { } ec && type == VaultKeyType.Ec && curve == ec.Curve
            ? new SignatureParameters(HashName(ec.Hash), null, Url: true)
            : null;
    }

    private static string HashName(System.Security.Cryptography.HashAlgorithmName hash) =>
        hash == System.Security.Cryptography.HashAlgorithmName.SHA384 ? "sha2-384"
        : hash == System.Security.Cryptography.HashAlgorithmName.SHA512 ? "sha2-512"
        : "sha2-256";

    /// <summary><c>vault:v{versão}:{base64}</c> → versão e bytes.</summary>
    private static (string Version, byte[] Bytes) ParseVaultValue(string? value, bool url)
    {
        var parts = value?.Split(':');
        if (parts is not { Length: 3 } || parts[0] != "vault" || !parts[1].StartsWith('v') ||
            !int.TryParse(parts[1].AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var version))
            throw new JsonException("Valor do Transit fora do formato vault:vN:...");
        return (version.ToString(CultureInfo.InvariantCulture), VaultJson.FromBase64(parts[2], url));
    }
}
