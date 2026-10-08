using System.Text;
using TEC.Vault.Common;
using TEC.Vault.Keys;

namespace TEC.Vault.LoadGenerator;

/// <summary>Cenários de carga sobre um <see cref="VaultTarget"/> e as misturas prontas usadas pelo CLI e pelos testes de carga.</summary>
public static class VaultScenarios
{
    /// <summary>Erro registrado quando o conteúdo devolvido não confere (corrupção sob concorrência).</summary>
    public const string MismatchError = "conteúdo divergente";

    /// <summary>Leitura de um segredo semeado sorteado (pelo cache, quando ligado).</summary>
    public static LoadScenario ReadSecret(VaultTarget target, int weight = 1) => new("ler segredo", weight, async (random, ct) =>
    {
        string name = target.SecretNames[random.Next(target.SecretNames.Count)];
        var result = await target.Reader.GetSecretAsync(name, cancellationToken: ct).ConfigureAwait(false);
        if (result.IsFailure)
            return result.Error!.Code;
        // Segredos semeados nunca são reescritos: o valor tem de ser exatamente o semeado
        return result.Value.Value == $"valor-{name}" ? null : MismatchError;
    });

    /// <summary>Gravação de uma nova versão num conjunto pequeno de nomes (disputa de escrita no mesmo item).</summary>
    public static LoadScenario WriteSecret(VaultTarget target, int weight = 1, int names = 8) => new("gravar segredo", weight, async (random, ct) =>
    {
        string name = $"{target.Prefix}escrita-{random.Next(names)}";
        target.TrackCreatedSecret(name);
        var result = await target.Secrets.SetSecretAsync(name, $"v{random.Next()}", cancellationToken: ct).ConfigureAwait(false);
        return result.Error?.Code;
    });

    /// <summary>Listagem de metadados de todos os segredos (operação cara, use com peso baixo).</summary>
    public static LoadScenario ListSecrets(VaultTarget target, int weight = 1) =>
        LoadScenario.FromResult("listar segredos", weight, (_, ct) => target.Secrets.ListSecretsAsync(ct));

    /// <summary>Criptografia envelope completa (wrap da chave de dados + AES-GCM, depois unwrap + decifra) com conferência do conteúdo.</summary>
    public static LoadScenario Envelope(VaultTarget target, int weight = 1) => new("envelope cifra+decifra", weight, async (random, ct) =>
    {
        byte[] plaintext = new byte[random.Next(16, 2048)];
        random.NextBytes(plaintext);
        byte[] context = Encoding.UTF8.GetBytes($"registro-{random.Next(1000)}");

        var encrypted = await target.Crypto.EncryptEnvelopeAsync(target.KeyName, plaintext, context, target.KeyVersion, ct).ConfigureAwait(false);
        if (encrypted.IsFailure)
            return encrypted.Error!.Code;

        var decrypted = await target.Crypto.DecryptEnvelopeAsync(encrypted.Value, context, ct).ConfigureAwait(false);
        if (decrypted.IsFailure)
            return decrypted.Error!.Code;
        return decrypted.Value.AsSpan().SequenceEqual(plaintext) ? null : MismatchError;
    });

    /// <summary>Assinatura no cofre (RS256) e verificação, que tem de ser válida.</summary>
    public static LoadScenario SignVerify(VaultTarget target, int weight = 1) => new("assinar+verificar", weight, async (random, ct) =>
    {
        byte[] data = new byte[random.Next(16, 1024)];
        random.NextBytes(data);

        var signed = await target.Crypto.SignDataAsync(target.KeyName, data, VaultSignatureAlgorithm.RS256, target.KeyVersion, ct).ConfigureAwait(false);
        if (signed.IsFailure)
            return signed.Error!.Code;

        var verified = await target.Crypto.VerifyDataAsync(target.KeyName, target.KeyVersion, data, signed.Value.Signature,
            VaultSignatureAlgorithm.RS256, ct).ConfigureAwait(false);
        if (verified.IsFailure)
            return verified.Error!.Code;
        return verified.Value ? null : MismatchError;
    });

    /// <summary>
    /// Entrada hostil (nome com injeção de caminho, controle ou tamanho excessivo): tem de ser recusada na validação, sem chamar
    /// o cofre. Sucesso = recusa com <see cref="VaultErrors.InvalidInputCode"/>.
    /// </summary>
    public static LoadScenario InvalidInput(VaultTarget target, int weight = 1) => new("entrada inválida", weight, async (random, ct) =>
    {
        string name = random.Next(4) switch
        {
            0 => "../keys/" + random.Next(),
            1 => "nome\n",
            2 => new string('a', 128 + random.Next(4096)),
            _ => "nome?api-version=1&x=" + random.Next()
        };
        var result = await target.Reader.GetSecretAsync(name, cancellationToken: ct).ConfigureAwait(false);
        return result.Error?.Code == VaultErrors.InvalidInputCode ? null : "entrada hostil aceita";
    });

    /// <summary>Misturas prontas (nome → cenários).</summary>
    public static IReadOnlyList<LoadScenario> Mix(string name, VaultTarget target) => name switch
    {
        "leitura" => [ReadSecret(target)],
        "escrita" => [WriteSecret(target)],
        "cripto" => [Envelope(target, 1), SignVerify(target, 1)],
        "misto" => [ReadSecret(target, 70), WriteSecret(target, 10), Envelope(target, 10), SignVerify(target, 5), InvalidInput(target, 4), ListSecrets(target, 1)],
        _ => throw new ArgumentException($"Mistura desconhecida: '{name}'. Use: {string.Join(", ", MixNames)}.", nameof(name))
    };

    /// <summary>Nomes das misturas aceitas por <see cref="Mix"/>.</summary>
    public static IReadOnlyList<string> MixNames { get; } = ["leitura", "escrita", "cripto", "misto"];
}
