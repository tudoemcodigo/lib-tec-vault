using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using TEC.Vault.Abstractions;
using TEC.Vault.Common;
using TEC.Vault.Keys;
using TEC.Vault.Secrets;
using TEC.Vault.Tests.Fakes;
using TEC.Core.Common.Results;
using TEC.Core.Cryptography.Symmetric;

namespace TEC.Vault.Tests;

/// <summary>Extensões que funcionam com qualquer provedor: rotação de segredo e criptografia envelope.</summary>
public class ExtensionsTests
{
    // ---------- RotateSecretAsync: cancelamento depois da gravação ----------

    [Test]
    public async Task RotateSecret_canceled_after_write_returns_incomplete_new_version_and_logs()
    {
        var logs = new CapturingLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var memory = Memory.Secrets();
        var original = (await memory.SetSecretAsync("api-token", "v1")).Value;
        using var cts = new CancellationTokenSource();
        var store = new ScriptedSecretStore(memory) { AfterSet = () => cts.CancelAsync() };   // o chamador desiste logo após a gravação

        var result = await store.RotateSecretAsync("api-token", disablePreviousVersions: true, timeProvider: null,
            logger: factory.CreateLogger("rotacao"), validity: null, generation: null, cancellationToken: cts.Token);

        var versions = (await memory.ListSecretVersionsAsync("api-token")).Value;
        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value.Current.Version).IsNotEqualTo(original.Version);
        await Assert.That(versions.Select(v => v.Version)).Contains(result.Value.Current.Version);   // a nova versão não se perdeu
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.FailedVersions).IsEquivalentTo(new[] { original.Version! });
        await Assert.That(result.Value.Errors.Single().Code).IsEqualTo(VaultErrors.CanceledCode);
        await Assert.That(versions.Single(v => v.Version == original.Version).Enabled).IsTrue();
        string generated = (await memory.GetSecretAsync("api-token")).Value.Value;
        await Assert.That(logs.Entries.Any(e => e.Level == LogLevel.Warning && e.Text.Contains("api-token")
            && e.Text.Contains(result.Value.Current.Version!) && e.Text.Contains(VaultErrors.CanceledCode))).IsTrue();
        await Assert.That(logs.AllText).DoesNotContain(generated);

        // Conclusão idempotente, sem nova versão
        var completed = await memory.DisablePreviousSecretVersionsAsync("api-token", result.Value.Current.Version!);
        await Assert.That(completed.Value.IsComplete).IsTrue();
        await Assert.That((await memory.ListSecretVersionsAsync("api-token")).Value.Count).IsEqualTo(2);
    }

    [Test]
    public async Task RotateSecret_canceled_before_write_throws_and_creates_no_version()
    {
        var memory = Memory.Secrets();
        await memory.SetSecretAsync("api-token", "v1");
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.That(async () => { await memory.RotateSecretAsync("api-token", disablePreviousVersions: true, cancellationToken: cts.Token); })
            .Throws<OperationCanceledException>();
        await Assert.That((await memory.ListSecretVersionsAsync("api-token")).Value.Count).IsEqualTo(1);
    }

    [Test]
    public async Task DisablePreviousSecretVersions_canceled_still_throws()
    {
        var memory = Memory.Secrets();
        var first = (await memory.SetSecretAsync("x", "1")).Value;
        await memory.SetSecretAsync("x", "2");
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.That(async () => { await memory.DisablePreviousSecretVersionsAsync("x", first.Version!, cts.Token); })
            .Throws<OperationCanceledException>();
    }

    // ---------- Envelope ----------

    [Test]
    [Arguments(16)]
    [Arguments(31)]
    [Arguments(33)]
    public async Task DecryptEnvelope_with_wrong_size_data_key_is_rejected(int size)
    {
        var crypto = new UnwrapStub(Result<byte[]>.Success(new byte[size]));
        var data = new EnvelopeEncryptedData("kek", FakeKeyVault.Version, [1, 2, 3], [4, 5, 6]);

        var result = await crypto.DecryptEnvelopeAsync(data);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.InvalidInputCode);
        await Assert.That(result.Error.Field).IsEqualTo("ciphertext");
        await Assert.That(crypto.Returned!.All(b => b == 0)).IsTrue();   // a chave devolvida é zerada mesmo recusada
    }

    [Test]
    public async Task DecryptEnvelope_propagates_unwrap_failure()
    {
        var crypto = new UnwrapStub(Result<byte[]>.Failure(VaultErrors.Disabled()));
        var data = new EnvelopeEncryptedData("kek", FakeKeyVault.Version, [1, 2, 3], [4, 5, 6]);

        var result = await crypto.DecryptEnvelopeAsync(data);

        await Assert.That(result.Error!.Code).IsEqualTo(VaultErrors.DisabledCode);
    }

    [Test]
    public async Task Envelope_forged_with_public_key_is_accepted_known_behavior()
    {
        // Documenta o limite do envelope (README, docs/chaves.md, docs/seguranca.md): sigilo e vínculo ao contexto, sem
        // autenticação de origem. Quem tem só a chave PÚBLICA da KEK monta um envelope que DecryptEnvelopeAsync aceita.
        // Para autenticar a origem, assine com SignDataAsync e confira com VerifyDataAsync antes de decifrar.
        var keys = await Memory.KeysWithKekAsync();
        var kek = (await keys.GetKeyAsync("kek")).Value;
        using var publicKey = RSA.Create();
        publicKey.ImportSubjectPublicKeyInfo(kek.PublicKeySpki, out _);

        var aes = new AesGcmCryptography();
        byte[] dataKey = aes.GenerateKey();
        byte[] context = "cliente:42"u8.ToArray();
        var forged = new EnvelopeEncryptedData("kek", kek.Properties.Version!,
            publicKey.Encrypt(dataKey, RSAEncryptionPadding.OaepSHA256),
            aes.Encrypt("conteudo forjado"u8.ToArray(), dataKey, context));

        var result = await keys.DecryptEnvelopeAsync(forged, context);

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(result.Value).IsEquivalentTo("conteudo forjado"u8.ToArray());
    }

    [Test]
    public async Task Signed_envelope_detects_forgery()
    {
        // A mitigação documentada: assinatura com chave que só o emissor usa, conferida antes de decifrar
        var keys = await Memory.KeysWithKekAsync();
        await keys.CreateKeyAsync("assinatura", new CreateKeyOptions { KeyType = VaultKeyType.Ec, Curve = VaultKeyCurve.P256 });
        byte[] context = "cliente:42"u8.ToArray();

        var envelope = (await keys.EncryptEnvelopeAsync("kek", "legitimo"u8.ToArray(), context)).Value;
        byte[] signed = [.. context, .. envelope.WrappedKey, .. envelope.Ciphertext];
        var signature = (await keys.SignDataAsync("assinatura", signed, VaultSignatureAlgorithm.ES256)).Value;

        var forged = envelope with { Ciphertext = (await keys.EncryptEnvelopeAsync("kek", "forjado"u8.ToArray(), context)).Value.Ciphertext };
        byte[] forgedSigned = [.. context, .. forged.WrappedKey, .. forged.Ciphertext];

        var legit = await keys.VerifyDataAsync("assinatura", signature.KeyVersion, signed, signature.Signature, VaultSignatureAlgorithm.ES256);
        var tampered = await keys.VerifyDataAsync("assinatura", signature.KeyVersion, forgedSigned, signature.Signature, VaultSignatureAlgorithm.ES256);

        await Assert.That(legit.Value).IsTrue();
        await Assert.That(tampered.Value).IsFalse();
    }

    /// <summary>Criptografia que só responde ao unwrap, com o resultado configurado.</summary>
    private sealed class UnwrapStub(Result<byte[]> unwrap) : IKeyCryptography
    {
        public byte[]? Returned { get; private set; }

        public string ProviderName => "Stub";

        public Task<Result<byte[]>> UnwrapKeyAsync(string name, string version, byte[] wrappedKey,
            VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default)
        {
            Returned = unwrap.IsSuccess ? unwrap.Value : null;
            return Task.FromResult(unwrap);
        }

        public Task<Result<VaultEncryptResult>> EncryptAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
            string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<byte[]>> DecryptAsync(string name, string version, byte[] ciphertext,
            VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<VaultEncryptResult>> WrapKeyAsync(string name, byte[] key, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
            string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<VaultSignResult>> SignDataAsync(string name, byte[] data, VaultSignatureAlgorithm algorithm,
            string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<Result<bool>> VerifyDataAsync(string name, string version, byte[] data, byte[] signature, VaultSignatureAlgorithm algorithm,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }
}
