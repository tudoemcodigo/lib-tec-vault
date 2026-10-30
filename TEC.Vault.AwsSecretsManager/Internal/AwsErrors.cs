using System.Net;
using System.Text.Json;
using System.Xml;

namespace TEC.Vault.AwsSecretsManager.Internal;

/// <summary>
/// Erros da AWS. O Secrets Manager responde quase todos os erros com HTTP 400 e o tipo no corpo (<c>__type</c>); o STS, em XML
/// (<c>&lt;Code&gt;</c>). Aqui o tipo vira o status HTTP equivalente, para que retentativa (429), novo login (401) e conversão de
/// erro sejam as mesmas dos demais provedores HTTP.
/// </summary>
internal static class AwsErrors
{
    private const int MaxCodeLength = 100;

    /// <summary>Status equivalente de uma resposta 4xx do Secrets Manager (protocolo JSON 1.1).</summary>
    internal static HttpStatusCode JsonStatus(HttpStatusCode status, ReadOnlyMemory<byte> body) => Status(status, JsonCode(body.Span));

    /// <summary>Status equivalente de uma resposta 4xx do STS (protocolo Query, corpo XML).</summary>
    internal static HttpStatusCode QueryStatus(HttpStatusCode status, ReadOnlyMemory<byte> body) => Status(status, QueryCode(body.Span));

    /// <summary>
    /// Código do erro no corpo JSON (<c>__type</c> ou <c>code</c>), sem o namespace (<c>com.amazonaws...#</c>) nem o sufixo
    /// (<c>:http://...</c>). <c>null</c> se ausente ou fora do formato. Seguro para log (só letras, dígitos, ponto e sublinhado).
    /// </summary>
    internal static string? JsonCode(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
            return null;
        try
        {
            var reader = new Utf8JsonReader(body, new JsonReaderOptions { MaxDepth = 16 });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var isCode = reader.ValueTextEquals("__type") || reader.ValueTextEquals("code") || reader.ValueTextEquals("Code");
                if (!reader.Read())
                    return null;
                if (isCode && reader.TokenType == JsonTokenType.String)
                    return Sanitize(reader.GetString());
                reader.Skip();
            }
        }
        catch (JsonException)
        {
        }

        return null;
    }

    /// <summary>Código do erro no XML do protocolo Query (<c>ErrorResponse/Error/Code</c>). Mesmas regras de <see cref="JsonCode"/>.</summary>
    internal static string? QueryCode(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
            return null;
        try
        {
            using var stream = new MemoryStream(body.ToArray(), writable: false);
            using var reader = XmlReader.Create(stream, SafeXml(body.Length));
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "Code")
                    return Sanitize(reader.ReadElementContentAsString());
            }
        }
        catch (XmlException)
        {
        }

        return null;
    }

    /// <summary>Leitor de XML sem DTD, sem resolução de entidades externas e com teto de caracteres.</summary>
    internal static XmlReaderSettings SafeXml(int bytes) => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = Math.Max(1024, (long)bytes * 2),
        MaxCharactersFromEntities = 1024,
        IgnoreComments = true,
        IgnoreProcessingInstructions = true,
        IgnoreWhitespace = true
    };

    private static HttpStatusCode Status(HttpStatusCode status, string? code) => code switch
    {
        "ResourceNotFoundException" => HttpStatusCode.NotFound,
        "ResourceExistsException" => HttpStatusCode.Conflict,
        "AccessDeniedException" or "AccessDenied" or "NotAuthorized" or "DecryptionFailure" or "EncryptionFailure" => HttpStatusCode.Forbidden,
        // Credencial vencida, revogada ou recusada: um novo login (credencial renovada) e uma nova tentativa
        "UnrecognizedClientException" or "InvalidClientTokenId" or "ExpiredTokenException" or "ExpiredToken" or "InvalidSignatureException"
            or "IncompleteSignature" or "SignatureDoesNotMatch" or "MissingAuthenticationToken" or "RequestExpired" => HttpStatusCode.Unauthorized,
        "ThrottlingException" or "Throttling" or "TooManyRequestsException" or "RequestLimitExceeded" => HttpStatusCode.TooManyRequests,
        "InternalServiceError" or "InternalFailure" or "ServiceUnavailable" or "IDPCommunicationError" => HttpStatusCode.ServiceUnavailable,
        _ => status
    };

    private static string? Sanitize(string? code)
    {
        if (string.IsNullOrEmpty(code))
            return null;
        var colon = code.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
            code = code[..colon];
        var hash = code.IndexOf('#', StringComparison.Ordinal);
        if (hash >= 0)
            code = code[(hash + 1)..];
        return code.Length is > 0 and <= MaxCodeLength && code.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_') ? code : null;
    }
}
