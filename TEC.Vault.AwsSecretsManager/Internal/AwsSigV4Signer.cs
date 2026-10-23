using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace TEC.Vault.AwsSecretsManager.Internal;

/// <summary>
/// Assinador nativo de requisições AWS Signature Version 4 (SigV4) para chamadas HTTP ao AWS Secrets Manager.
/// Não utiliza bibliotecas externas, operando 100% com primitivas criptográficas nativas do .NET e compatível com Native AOT.
/// </summary>
internal static class AwsSigV4Signer
{
    private const string Algorithm = "AWS4-HMAC-SHA256";
    private const string Service = "secretsmanager";

    public static void Sign(HttpRequestMessage request, byte[] payloadBytes, string region, string accessKeyId, string secretAccessKey, string? sessionToken, DateTimeOffset timestamp)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(region);
        ArgumentException.ThrowIfNullOrWhiteSpace(accessKeyId);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretAccessKey);

        var dateStamp = timestamp.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var amzDate = timestamp.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);

        request.Headers.Remove("x-amz-date");
        request.Headers.Add("x-amz-date", amzDate);

        if (!string.IsNullOrWhiteSpace(sessionToken))
        {
            request.Headers.Remove("x-amz-security-token");
            request.Headers.Add("x-amz-security-token", sessionToken);
        }

        // 1. Canonical Headers e Signed Headers
        var uri = request.RequestUri ?? throw new InvalidOperationException("URI da requisição é obrigatória.");
        var host = uri.Host + (uri.IsDefaultPort ? "" : $":{uri.Port}");

        var headers = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["host"] = host,
            ["x-amz-date"] = amzDate
        };

        if (request.Content?.Headers.ContentType is not null)
            headers["content-type"] = request.Content.Headers.ContentType.ToString();

        if (request.Headers.TryGetValues("x-amz-target", out var targetValues))
            headers["x-amz-target"] = string.Join(",", targetValues);

        if (!string.IsNullOrWhiteSpace(sessionToken))
            headers["x-amz-security-token"] = sessionToken;

        var canonicalHeadersBuilder = new StringBuilder();
        var signedHeadersBuilder = new StringBuilder();

        foreach (var (k, v) in headers.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var lowerKey = k.ToLowerInvariant();
            canonicalHeadersBuilder.Append(lowerKey).Append(':').Append(v.Trim()).Append('\n');

            if (signedHeadersBuilder.Length > 0)
                signedHeadersBuilder.Append(';');
            signedHeadersBuilder.Append(lowerKey);
        }

        var signedHeaders = signedHeadersBuilder.ToString();
        var canonicalHeaders = canonicalHeadersBuilder.ToString();

        // 2. Hashed Payload
        var hashedPayload = HexEncode(SHA256.HashData(payloadBytes));

        // 3. Canonical Request
        var path = uri.AbsolutePath;
        if (string.IsNullOrEmpty(path))
            path = "/";

        var canonicalRequest = $"{request.Method.Method}\n{path}\n\n{canonicalHeaders}\n{signedHeaders}\n{hashedPayload}";

        // 4. String to Sign
        var credentialScope = $"{dateStamp}/{region}/{Service}/aws4_request";
        var hashedCanonicalRequest = HexEncode(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest)));
        var stringToSign = $"{Algorithm}\n{amzDate}\n{credentialScope}\n{hashedCanonicalRequest}";

        // 5. Signature
        var signature = CalculateSignature(secretAccessKey, dateStamp, region, Service, stringToSign);

        // 6. Header Authorization
        var authorization = $"{Algorithm} Credential={accessKeyId}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";
        request.Headers.Remove("Authorization");
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
    }

    private static string CalculateSignature(string secretKey, string dateStamp, string region, string service, string stringToSign)
    {
        var kSecret = Encoding.UTF8.GetBytes("AWS4" + secretKey);
        var kDate = HmacSha256(kSecret, Encoding.UTF8.GetBytes(dateStamp));
        var kRegion = HmacSha256(kDate, Encoding.UTF8.GetBytes(region));
        var kService = HmacSha256(kRegion, Encoding.UTF8.GetBytes(service));
        var kSigning = HmacSha256(kService, Encoding.UTF8.GetBytes("aws4_request"));

        var signatureBytes = HmacSha256(kSigning, Encoding.UTF8.GetBytes(stringToSign));
        return HexEncode(signatureBytes);
    }

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    private static string HexEncode(byte[] bytes)
    {
#if NET9_0_OR_GREATER || NET8_0_OR_GREATER
        return Convert.ToHexString(bytes).ToLowerInvariant();
#else
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
            sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
#endif
    }
}
