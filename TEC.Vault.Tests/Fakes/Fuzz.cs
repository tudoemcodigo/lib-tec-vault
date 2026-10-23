using System.Text;

namespace TEC.Vault.Tests.Fakes;

/// <summary>
/// Geração de entradas hostis para fuzzing, sem biblioteca externa: sorteios com semente fixa (reproduzíveis; a semente vai
/// na mensagem da falha) a partir de um alfabeto com os caracteres que costumam quebrar validações (injeção de caminho e de
/// query, controle, quebra de linha, Unicode confundível, bidi, surrogates soltos).
/// </summary>
internal static class Fuzz
{
    /// <summary>Semente padrão; outra pode ser forçada por <c>TEC_TESTES_FUZZ_SEMENTE</c> para reproduzir uma falha.</summary>
    public static int Seed => int.TryParse(Environment.GetEnvironmentVariable("TEC_TESTES_FUZZ_SEMENTE"), out int seed) ? seed : 20261005;

    /// <summary>Iterações por teste (<c>TEC_TESTES_FUZZ_ITERACOES</c>; padrão 2.000).</summary>
    public static int Iterations => int.TryParse(Environment.GetEnvironmentVariable("TEC_TESTES_FUZZ_ITERACOES"), out int n) && n > 0 ? n : 2_000;

    // Caracteres não ASCII montados pelo código (sem literais invisíveis ou bidi no fonte)
    private static string C(int code) => ((char)code).ToString();

    private static readonly string[] Pieces =
    [
        "a", "Z", "0", "9", "-", "_", ".", "/", "\\", "..", "../", "%2e%2e%2f", "%00", "?", "#", "&", "=", ":", "@", " ", "\t",
        "\n", "\r\n", "\0", C(0x0085), C(0x2028), C(0x00E9), C(0x0130), C(0x0131), C(0x00DF), C(0xFF21), C(0x0430), C(0x202E), C(0x200B),
        C(0xFEFF), char.ConvertFromUtf32(0x1F600), C(0xD800), C(0xDFFF), "'", "\"", "<", ">", "{", "}", "*", "$", "api-version=7.6", "secrets",
        "keys", "%", "+", "~"
    ];

    /// <summary>Texto hostil de até <paramref name="maxPieces"/> pedaços (inclui vazio e textos longos).</summary>
    public static string Text(Random random, int maxPieces = 40)
    {
        switch (random.Next(20))
        {
            case 0:
                return string.Empty;
            case 1:
                return new string((char)random.Next('a', 'z' + 1), random.Next(100, 300));   // perto e além do limite de 127
            case 2:
                return new string((char)random.Next(0, 0x10000), random.Next(1, 8));          // qualquer UTF-16, inclusive inválido
        }

        var text = new StringBuilder();
        int count = random.Next(1, maxPieces);
        for (int i = 0; i < count; i++)
            text.Append(Pieces[random.Next(Pieces.Length)]);
        return text.ToString();
    }

    /// <summary>Bytes aleatórios, ou um conteúdo válido com bits trocados, truncado ou estendido.</summary>
    public static byte[] Bytes(Random random, byte[]? valid = null, int maxLength = 4096)
    {
        if (valid is null || random.Next(4) == 0)
        {
            byte[] noise = new byte[random.Next(1, maxLength)];
            random.NextBytes(noise);
            return noise;
        }

        byte[] mutated = random.Next(3) switch
        {
            0 => valid[..random.Next(1, valid.Length)],                                      // truncado
            1 => [.. valid, .. Enumerable.Range(0, random.Next(1, 64)).Select(_ => (byte)random.Next(256))],   // estendido
            _ => (byte[])valid.Clone()
        };
        int flips = random.Next(1, 8);
        for (int i = 0; i < flips; i++)
            mutated[random.Next(mutated.Length)] ^= (byte)(1 << random.Next(8));
        return mutated;
    }

    /// <summary>Oráculo independente da regra de nome do Key Vault: 1 a 127 caracteres ASCII alfanuméricos ou hífen.</summary>
    public static bool IsValidKeyVaultName(string name) =>
        name.Length is >= 1 and <= 127 && name.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or '-');

    /// <summary>Oráculo da regra de versão: 32 dígitos hexadecimais ASCII.</summary>
    public static bool IsValidVersion(string version) =>
        version.Length == 32 && version.All(char.IsAsciiHexDigit);
}
