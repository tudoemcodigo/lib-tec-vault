using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
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
    private const int InitialBufferBytes = 4 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

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

    /// <summary>
    /// Lê um arquivo já aberto, com as mesmas regras de <see cref="ReadFile"/>: nunca guarda mais que <paramref name="maxBytes"/> + 1
    /// bytes (mesmo sem tamanho conhecido), UTF-8 estrito, BOM descartado e buffers zerados. <c>null</c> se passar do limite.
    /// O handle é fechado no fim (leia antes o que precisar dele, como a data de modificação).
    /// </summary>
    /// <param name="handle">Arquivo aberto para leitura.</param>
    /// <param name="maxBytes">Tamanho máximo aceito.</param>
    /// <param name="name">Nome do item, para a mensagem de erro (nunca o conteúdo).</param>
    internal static string? ReadHandle(SafeFileHandle handle, int maxBytes, string name)
    {
        using var stream = new FileStream(handle, FileAccess.Read, bufferSize: 1);
        long reported = stream.CanSeek ? stream.Length : 0;
        if (reported > maxBytes)
            return null;

        int limit = (int)Math.Min((long)maxBytes + 1, Array.MaxLength);
        var buffer = new byte[reported > 0 ? (int)Math.Min(reported + 1, limit) : Math.Min(InitialBufferBytes, limit)];
        int total = 0;
        try
        {
            while (true)
            {
                if (total == buffer.Length)
                {
                    if (buffer.Length == limit)
                        break;
                    var bigger = new byte[(int)Math.Min((long)buffer.Length * 2, limit)];
                    buffer.AsSpan(0, total).CopyTo(bigger);
                    CryptographicOperations.ZeroMemory(buffer);
                    buffer = bigger;
                }

                int read = stream.Read(buffer, total, buffer.Length - total);
                if (read == 0)
                    break;
                total += read;
            }

            if (total == limit)
                return null;

            var content = buffer.AsSpan(0, total);
            if (content.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
                content = content[3..];

            try
            {
                return StrictUtf8.GetString(content);
            }
            catch (DecoderFallbackException)
            {
                throw new SyncedFormatException($"arquivo com conteúdo fora de UTF-8: {name}");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Remove quebras de linha no final (ferramentas costumam gravar o valor com "\n").</summary>
    internal static string TrimTrailingNewlines(string value) => value.TrimEnd('\r', '\n');
}
