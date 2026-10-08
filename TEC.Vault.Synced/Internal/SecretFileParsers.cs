using System.Text;
using System.Text.Json;

namespace TEC.Vault.Synced.Internal;

/// <summary>Leitura de um arquivo JSON ou .env com vários segredos. Erros informam só a posição, nunca valores.</summary>
internal static class SecretFileParsers
{
    internal const string Separator = "--";
    private const int MaxDepth = 16;

    /// <summary>
    /// JSON: objeto na raiz; objetos aninhados viram nomes com <c>--</c> (<c>{"Db":{"Senha":"x"}}</c> → <c>Db--Senha</c>).
    /// Texto, número e booleano viram texto; <c>null</c> e listas são recusados.
    /// </summary>
    internal static List<KeyValuePair<string, string>> ParseJson(string content)
    {
        var result = new List<KeyValuePair<string, string>>();
        try
        {
            using var document = JsonDocument.Parse(content, new JsonDocumentOptions
            {
                MaxDepth = MaxDepth,
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                throw new SyncedFormatException("o JSON deve ter um objeto na raiz");
            Flatten(document.RootElement, null, result);
        }
        catch (JsonException exception)
        {
            throw new SyncedFormatException($"JSON inválido (linha {exception.LineNumber + 1})");
        }

        return result;
    }

    private static void Flatten(JsonElement element, string? prefix, List<KeyValuePair<string, string>> result)
    {
        foreach (var property in element.EnumerateObject())
        {
            var name = prefix is null ? property.Name : prefix + Separator + property.Name;
            switch (property.Value.ValueKind)
            {
                case JsonValueKind.Object:
                    Flatten(property.Value, name, result);
                    break;
                case JsonValueKind.String:
                    result.Add(new(name, property.Value.GetString()!));
                    break;
                case JsonValueKind.Number:
                case JsonValueKind.True:
                case JsonValueKind.False:
                    result.Add(new(name, property.Value.GetRawText()));
                    break;
                default:
                    throw new SyncedFormatException($"valor não suportado (null ou lista) na chave {Safe(name)}");
            }
        }
    }

    /// <summary>
    /// .env: <c>CHAVE=valor</c> por linha; <c>#</c> inicia comentário; <c>export </c> opcional. Valor entre aspas duplas aceita
    /// <c>\n</c>, <c>\r</c>, <c>\t</c>, <c>\"</c> e <c>\\</c> e pode ocupar várias linhas; entre aspas simples é literal; sem aspas,
    /// vai até o fim da linha (ou até <c> #</c>) sem espaços nas pontas. Sem expansão de variáveis (<c>$OUTRA</c> fica como está).
    /// <c>__</c> no nome vira <c>--</c>.
    /// </summary>
    internal static List<KeyValuePair<string, string>> ParseDotEnv(string content)
    {
        var result = new List<KeyValuePair<string, string>>();
        var line = 1;
        var i = 0;

        while (i < content.Length)
        {
            // espaços e linhas vazias
            if (content[i] is ' ' or '\t' or '\r')
            {
                i++;
                continue;
            }

            if (content[i] == '\n')
            {
                line++;
                i++;
                continue;
            }

            if (content[i] == '#')
            {
                SkipToEndOfLine(content, ref i);
                continue;
            }

            var startLine = line;
            var keyStart = i;
            while (i < content.Length && content[i] is not ('=' or '\n'))
                i++;
            if (i >= content.Length || content[i] != '=')
                throw new SyncedFormatException($".env inválido na linha {startLine}: esperado CHAVE=valor");

            var key = content[keyStart..i].Trim();
            if (key.StartsWith("export ", StringComparison.Ordinal) || key.StartsWith("export\t", StringComparison.Ordinal))
                key = key[7..].TrimStart();
            if (key.Length == 0 || !key.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-'))
                throw new SyncedFormatException($".env inválido na linha {startLine}: nome de chave inválido");
            i++;   // '='

            var afterEquals = i;
            while (i < content.Length && content[i] is ' ' or '\t')
                i++;

            string value;
            if (i < content.Length && content[i] == '#' && i > afterEquals)
            {
                // "CHAVE= # comentário": espaço seguido de # inicia comentário mesmo logo após o '=' (valor vazio)
                value = string.Empty;
            }
            else if (i < content.Length && content[i] == '"')
                value = ReadDoubleQuoted(content, ref i, ref line, startLine);
            else if (i < content.Length && content[i] == '\'')
                value = ReadSingleQuoted(content, ref i, ref line, startLine);
            else
            {
                var valueStart = i;
                while (i < content.Length && content[i] != '\n' && !(content[i] == '#' && i > valueStart && content[i - 1] is ' ' or '\t'))
                    i++;
                value = content[valueStart..i].Trim();
            }

            // depois do valor: só espaços e comentário até o fim da linha
            while (i < content.Length && content[i] is ' ' or '\t' or '\r')
                i++;
            if (i < content.Length && content[i] == '#')
                SkipToEndOfLine(content, ref i);
            else if (i < content.Length && content[i] != '\n')
                throw new SyncedFormatException($".env inválido na linha {line}: conteúdo depois do valor");

            result.Add(new(key.Replace("__", Separator, StringComparison.Ordinal), value));
        }

        return result;
    }

    private static string ReadDoubleQuoted(string content, ref int i, ref int line, int startLine)
    {
        var builder = new StringBuilder();
        i++;   // abre aspas
        while (i < content.Length)
        {
            var c = content[i++];
            switch (c)
            {
                case '"':
                    return builder.ToString();
                case '\\' when i < content.Length:
                    var escaped = content[i++];
                    builder.Append(escaped switch
                    {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        '"' => '"',
                        '\\' => '\\',
                        _ => throw new SyncedFormatException($".env inválido na linha {line}: escape não suportado")
                    });
                    break;
                case '\n':
                    line++;
                    builder.Append(c);
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        throw new SyncedFormatException($".env inválido na linha {startLine}: aspas duplas sem fechamento");
    }

    private static string ReadSingleQuoted(string content, ref int i, ref int line, int startLine)
    {
        var start = ++i;
        while (i < content.Length && content[i] != '\'')
        {
            if (content[i] == '\n')
                line++;
            i++;
        }

        if (i >= content.Length)
            throw new SyncedFormatException($".env inválido na linha {startLine}: aspas simples sem fechamento");
        return content[start..i++];
    }

    private static void SkipToEndOfLine(string content, ref int i)
    {
        while (i < content.Length && content[i] != '\n')
            i++;
    }

    /// <summary>Nome para mensagem de erro: só os caracteres esperados em um nome (evita levar conteúdo arbitrário ao log).</summary>
    private static string Safe(string name) =>
        name.Length <= 128 && name.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-') ? name : "(nome inválido)";
}
