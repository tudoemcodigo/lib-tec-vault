using TEC.Core.IO;

namespace TEC.Vault.Synced.Internal;

/// <summary>Item lido da fonte. <see cref="ToString"/> não mostra o valor.</summary>
internal sealed record SyncedEntry(string Name, string Value, DateTimeOffset? UpdatedOn, string? Source = null)
{
    public override string ToString() => $"SyncedEntry {{ Name = {Name}, Value = *** }}";
}

/// <summary>Conteúdo da fonte fora do formato esperado. A mensagem traz só a posição (linha, chave), nunca valores.</summary>
internal sealed class SyncedFormatException(string message) : Exception(message);

/// <summary>Leitura de arquivos de texto da fonte: tamanho limitado e UTF-8 estrito.</summary>
internal static class SyncedText
{
    /// <summary>
    /// Lê o arquivo inteiro (limite de tamanho, UTF-8 estrito, sem BOM: <see cref="BoundedFileReader"/> do TEC.Core);
    /// <c>null</c> se ele passar de <paramref name="maxBytes"/>.
    /// </summary>
    internal static string? ReadFile(string path, int maxBytes, out DateTimeOffset updatedOn)
    {
        updatedOn = File.GetLastWriteTimeUtc(path);
        try
        {
            return BoundedFileReader.TryReadUtf8(path, maxBytes, out string? text) ? text : null;
        }
        catch (InvalidDataException)
        {
            throw new SyncedFormatException($"arquivo com conteúdo fora de UTF-8: {Path.GetFileName(path)}");
        }
    }

    /// <summary>Remove quebras de linha no final (ferramentas costumam gravar o valor com "\n").</summary>
    internal static string TrimTrailingNewlines(string value) => value.TrimEnd('\r', '\n');
}
