using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TEC.Vault.AwsSecretsManager.Internal;

/// <summary>
/// Assinatura AWS Signature Version 4 (SigV4) das chamadas ao Secrets Manager, com as primitivas do .NET (compatível com Native AOT).
/// </summary>
/// <remarks>
/// Assina <c>content-type</c>, <c>host</c>, <c>x-amz-date</c>, <c>x-amz-target</c> e, com credencial temporária,
/// <c>x-amz-security-token</c>. Cada tentativa é assinada de novo (data atual). As chaves derivadas são zeradas depois do uso.
/// </remarks>
internal static class AwsSigV4Signer
{
    private const string Algorithm = "AWS4-HMAC-SHA256";
    private const string Service = "secretsmanager";

    /// <summary>Hash SHA-256 (hexadecimal minúsculo) do corpo, calculado uma vez por chamada e guardado na requisição.</summary>
    internal static readonly HttpRequestOptionsKey<string> PayloadHashKey = new("TEC.Vault.AwsSecretsManager.PayloadSha256");

    internal static string HashPayload(ReadOnlySpan<byte> payload) => Convert.ToHexStringLower(SHA256.HashData(payload));

    /// <summary>Assina a requisição (URI absoluta e hash do corpo em <see cref="PayloadHashKey"/>).</summary>
    internal static void Sign(HttpRequestMessage request, AwsCredentials credentials, string region, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        var uri = request.RequestUri is { IsAbsoluteUri: true } absolute
            ? absolute
            : throw new InvalidOperationException("A requisição assinada precisa de endereço absoluto.");
        if (!request.Options.TryGetValue(PayloadHashKey, out var payloadHash))
            throw new InvalidOperationException("A requisição assinada precisa do hash do corpo.");

        var amzDate = now.UtcDateTime.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var dateStamp = amzDate[..8];
        request.Headers.Remove("x-amz-date");
        request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);
        request.Headers.Remove("x-amz-security-token");
        if (credentials.SessionToken is { } sessionToken)
            request.Headers.TryAddWithoutValidation("x-amz-security-token", sessionToken);

        var headers = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["host"] = uri.IsDefaultPort ? uri.IdnHost : $"{uri.IdnHost}:{uri.Port.ToString(CultureInfo.InvariantCulture)}",
            ["x-amz-date"] = amzDate
        };
        if (request.Content?.Headers.ContentType is { } contentType)
            headers["content-type"] = contentType.ToString();
        if (request.Headers.TryGetValues("x-amz-target", out var target))
            headers["x-amz-target"] = string.Join(',', target);
        if (credentials.SessionToken is { } token)
            headers["x-amz-security-token"] = token;

        var canonicalHeaders = new StringBuilder();
        foreach (var (name, value) in headers)
            canonicalHeaders.Append(name).Append(':').Append(value.Trim()).Append('\n');
        var signedHeaders = string.Join(';', headers.Keys);

        var path = string.IsNullOrEmpty(uri.AbsolutePath) ? "/" : uri.AbsolutePath;
        var canonicalRequest = $"{request.Method.Method}\n{path}\n\n{canonicalHeaders}\n{signedHeaders}\n{payloadHash}";
        var scope = $"{dateStamp}/{region}/{Service}/aws4_request";
        var stringToSign = $"{Algorithm}\n{amzDate}\n{scope}\n{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest)))}";

        var signature = Signature(credentials.SecretAccessKey, dateStamp, region, stringToSign);
        request.Headers.Remove("Authorization");
        request.Headers.TryAddWithoutValidation("Authorization",
            $"{Algorithm} Credential={credentials.AccessKeyId}/{scope}, SignedHeaders={signedHeaders}, Signature={signature}");
    }

    private static string Signature(string secretAccessKey, string dateStamp, string region, string stringToSign)
    {
        var secret = Encoding.UTF8.GetBytes("AWS4" + secretAccessKey);
        var date = HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes(dateStamp));
        var regional = HMACSHA256.HashData(date, Encoding.UTF8.GetBytes(region));
        var service = HMACSHA256.HashData(regional, Encoding.UTF8.GetBytes(Service));
        var signing = HMACSHA256.HashData(service, "aws4_request"u8);
        try
        {
            return Convert.ToHexStringLower(HMACSHA256.HashData(signing, Encoding.UTF8.GetBytes(stringToSign)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(date);
            CryptographicOperations.ZeroMemory(regional);
            CryptographicOperations.ZeroMemory(service);
            CryptographicOperations.ZeroMemory(signing);
        }
    }
}
