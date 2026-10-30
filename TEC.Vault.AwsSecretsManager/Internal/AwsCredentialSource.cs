using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using Microsoft.Extensions.Logging;
using TEC.Vault.Providers.Http;

namespace TEC.Vault.AwsSecretsManager.Internal;

/// <summary>
/// Obtém a credencial da AWS da fonte escolhida na inicialização (<see cref="AwsCredentialKind"/>): web identity no STS,
/// endpoint de credenciais do container, IMDSv2 ou chaves estáticas. É o login da <see cref="VaultTokenSource"/>, que guarda a
/// credencial, renova antes de expirar (credenciais temporárias têm <c>Expiration</c>), faz um login só em concorrência e segura
/// falhas por um intervalo. Thread-safe.
/// </summary>
internal sealed class AwsCredentialSource : IDisposable
{
    private const string ImdsTokenTtlSeconds = "21600";
    private const int MaxCredentialResponseBytes = 64 * 1024;

    // Estado do IMDS quando há chaves estáticas como alternativa: desconhecido, confirmado (nunca troca) ou descartado
    private const int ImdsUnknown = 0;
    private const int ImdsConfirmed = 1;
    private const int ImdsRuledOut = 2;

    private readonly AwsSecretsManagerOptions _options;
    private readonly AwsSecretsManagerOptions.Resolved _resolved;
    private readonly ILogger _logger;
    private readonly VaultHttpClient? _sts;
    private readonly VaultHttpClient? _container;
    private readonly VaultHttpClient? _imds;
    private readonly VaultCredentialInput? _webIdentityToken;
    private int _imdsState;

    internal AwsCredentialSource(AwsSecretsManagerOptions options, AwsSecretsManagerOptions.Resolved resolved, ILogger logger)
    {
        _options = options;
        _resolved = resolved;
        _logger = logger;

        switch (resolved.Credentials)
        {
            case AwsCredentialKind.WebIdentity:
                _webIdentityToken = VaultCredentialInput.FromFile(resolved.WebIdentityTokenFile!, "AwsSecretsManagerOptions.WebIdentityTokenFile");
                _sts = new VaultHttpClient(resolved.StsEndpoint!, options.Http) { ErrorStatusMapper = AwsErrors.QueryStatus };
                break;
            case AwsCredentialKind.Container:
                _container = new VaultHttpClient(new Uri(resolved.ContainerUri!.GetLeftPart(UriPartial.Authority) + "/"), LocalSettings(options.Http, 5));
                break;
            case AwsCredentialKind.InstanceMetadata:
                _imds = new VaultHttpClient(new Uri("http://169.254.169.254/"), LocalSettings(options.Http, 2));
                break;
        }
    }

    /// <summary>Login da <see cref="VaultTokenSource"/>: a credencial atual da fonte, como texto opaco com a expiração.</summary>
    internal async Task<VaultToken> LoginAsync(CancellationToken cancellationToken)
    {
        var (credentials, expires) = _resolved.Credentials switch
        {
            AwsCredentialKind.WebIdentity => await WebIdentityAsync(cancellationToken).ConfigureAwait(false),
            AwsCredentialKind.Container => await ContainerAsync(cancellationToken).ConfigureAwait(false),
            AwsCredentialKind.InstanceMetadata => await InstanceMetadataOrStaticAsync(cancellationToken).ConfigureAwait(false),
            _ => (Static() ?? throw new VaultLoginException("credencial estática da AWS ausente (AccessKeyId/SecretAccessKey ou as variáveis)"), null)
        };
        return new VaultToken(credentials.Encode(), expires);
    }

    public void Dispose()
    {
        _sts?.Dispose();
        _container?.Dispose();
        _imds?.Dispose();
    }

    /// <summary>
    /// Transporte dos endpoints locais de credenciais (container, IMDS): tempo limite curto e no máximo uma nova tentativa, para
    /// não segurar a primeira chamada fora da AWS; o handler e o relógio são os do provedor.
    /// </summary>
    private static VaultHttpSettings LocalSettings(VaultHttpSettings http, int timeoutSeconds) => new()
    {
        MaxRetries = Math.Min(http.MaxRetries, 1),
        NetworkTimeout = http.NetworkTimeout < TimeSpan.FromSeconds(timeoutSeconds) ? http.NetworkTimeout : TimeSpan.FromSeconds(timeoutSeconds),
        MaxRetryDelay = http.MaxRetryDelay,
        MaxResponseBytes = MaxCredentialResponseBytes,
        Handler = http.Handler,
        TimeProvider = http.TimeProvider
    };

    // ---------- 1. Web identity (IRSA): AssumeRoleWithWebIdentity no STS ----------

    private async Task<(AwsCredentials, DateTimeOffset?)> WebIdentityAsync(CancellationToken cancellationToken)
    {
        string token;
        try
        {
            token = _webIdentityToken!.Read();   // relido a cada renovação (o Kubernetes troca o token projetado)
        }
        catch (InvalidOperationException exception)
        {
            throw new VaultLoginException(exception.Message, exception);
        }

        var form = Encoding.UTF8.GetBytes(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15" +
            "&RoleArn=" + Uri.EscapeDataString(_resolved.RoleArn!) +
            "&RoleSessionName=" + Uri.EscapeDataString(_resolved.RoleSessionName!) +
            "&WebIdentityToken=" + Uri.EscapeDataString(token));
        try
        {
            using var response = await _sts!.SendAsync(() => new HttpRequestMessage(HttpMethod.Post, _sts.BaseAddress)
            {
                Content = new ByteArrayContent(form) { Headers = { ContentType = new("application/x-www-form-urlencoded") { CharSet = "utf-8" } } }
            }, idempotent: true, cancellationToken).ConfigureAwait(false);

            await EnsureLoginSuccessAsync(_sts, response, "o AWS STS", xml: true, cancellationToken).ConfigureAwait(false);
            var body = await _sts.ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
            try
            {
                return ParseStsCredentials(body);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(form);
        }
    }

    /// <summary><c>AssumeRoleWithWebIdentityResult/Credentials</c> do XML do STS (sem DTD, com teto).</summary>
    private static (AwsCredentials, DateTimeOffset?) ParseStsCredentials(byte[] body)
    {
        string? accessKeyId = null, secretAccessKey = null, sessionToken = null, expiration = null;
        try
        {
            using var stream = new MemoryStream(body, writable: false);
            using var reader = XmlReader.Create(stream, AwsErrors.SafeXml(body.Length));
            var inCredentials = false;
            while (!reader.EOF)
            {
                if (reader.NodeType == XmlNodeType.Element && reader.LocalName == "Credentials")
                {
                    inCredentials = true;
                    reader.Read();
                    continue;
                }

                if (inCredentials && reader.NodeType == XmlNodeType.Element)
                {
                    switch (reader.LocalName)
                    {
                        case "AccessKeyId":
                            accessKeyId = reader.ReadElementContentAsString();
                            continue;
                        case "SecretAccessKey":
                            secretAccessKey = reader.ReadElementContentAsString();
                            continue;
                        case "SessionToken":
                            sessionToken = reader.ReadElementContentAsString();
                            continue;
                        case "Expiration":
                            expiration = reader.ReadElementContentAsString();
                            continue;
                    }
                }

                if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName == "Credentials")
                    inCredentials = false;
                reader.Read();
            }
        }
        catch (XmlException exception)
        {
            throw new VaultLoginException("o AWS STS devolveu uma resposta fora do formato", exception);
        }

        if (sessionToken is null)
            throw new VaultLoginException("o AWS STS não devolveu token de sessão");
        return (AwsCredentials.Create(accessKeyId, secretAccessKey, sessionToken, "STS"), Expiration(expiration, "STS"));
    }

    // ---------- 2. Container (ECS, EKS Pod Identity) ----------

    private async Task<(AwsCredentials, DateTimeOffset?)> ContainerAsync(CancellationToken cancellationToken)
    {
        var authorization = ContainerAuthorization();
        using var response = await _container!.SendAsync(() =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, _resolved.ContainerUri);
            if (authorization is not null)
                request.Headers.TryAddWithoutValidation("Authorization", authorization);
            return request;
        }, idempotent: true, cancellationToken).ConfigureAwait(false);

        await EnsureLoginSuccessAsync(_container, response, "o endpoint de credenciais do container", xml: false, cancellationToken).ConfigureAwait(false);
        return await ReadJsonCredentialsAsync(_container, response, "container", cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Token do cabeçalho <c>Authorization</c>: o arquivo de <c>AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE</c> (relido a cada
    /// renovação; o EKS Pod Identity o troca) ou <c>AWS_CONTAINER_AUTHORIZATION_TOKEN</c>.
    /// </summary>
    private string? ContainerAuthorization()
    {
        string? value;
        try
        {
            if (Text(_options.ReadVariable("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")) is { } file)
                value = VaultCredentialInput.FromFile(file, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE").Read();
            else if (Text(_options.ReadVariable("AWS_CONTAINER_AUTHORIZATION_TOKEN")) is { } token)
                value = token;
            else
                return null;
        }
        catch (InvalidOperationException exception)
        {
            throw new VaultLoginException(exception.Message, exception);
        }

        // Vai para um cabeçalho: só ASCII visível e espaço (sem quebra de linha nem caracteres de controle)
        return value.All(c => c is >= ' ' and <= '~')
            ? value
            : throw new VaultLoginException("token de autorização do container fora do formato");
    }

    // ---------- 3. IMDSv2 (EC2), com as chaves estáticas como alternativa ----------

    private async Task<(AwsCredentials, DateTimeOffset?)> InstanceMetadataOrStaticAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _imdsState) == ImdsRuledOut)
            return (Static() ?? throw new VaultLoginException("credencial estática da AWS ausente"), null);

        try
        {
            var credentials = await InstanceMetadataAsync(cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _imdsState, ImdsConfirmed);
            return credentials;
        }
        catch (Exception exception) when (exception is HttpRequestException or TimeoutException or VaultHttpException or VaultLoginException
                                              or VaultResponseTooLargeException && Volatile.Read(ref _imdsState) == ImdsUnknown)
        {
            // Primeira tentativa sem resposta útil do IMDS (fora do EC2, ou instância sem perfil): as chaves estáticas, se houver,
            // passam a valer para o processo. Depois de um IMDS que já respondeu, uma falha dele não troca de identidade
            if (Static() is not { } fallback)
                throw;

            Volatile.Write(ref _imdsState, ImdsRuledOut);
            AwsLog.InstanceMetadataUnavailable(_logger, exception.GetType().Name);
            return (fallback, null);
        }
    }

    private async Task<(AwsCredentials, DateTimeOffset?)> InstanceMetadataAsync(CancellationToken cancellationToken)
    {
        string token;
        using (var response = await _imds!.SendAsync(() =>
               {
                   var request = new HttpRequestMessage(HttpMethod.Put, "latest/api/token");
                   request.Headers.TryAddWithoutValidation("X-aws-ec2-metadata-token-ttl-seconds", ImdsTokenTtlSeconds);
                   return request;
               }, idempotent: true, cancellationToken).ConfigureAwait(false))
        {
            await EnsureLoginSuccessAsync(_imds, response, "o IMDS", xml: false, cancellationToken).ConfigureAwait(false);
            token = await ReadTextAsync(_imds, response, cancellationToken).ConfigureAwait(false);
        }

        if (token.Length is 0 or > 4096 || !token.All(c => c is > ' ' and <= '~'))
            throw new VaultLoginException("o IMDS devolveu um token fora do formato");

        string role;
        using (var response = await _imds.SendAsync(() => ImdsRequest("latest/meta-data/iam/security-credentials/", token), idempotent: true,
                   cancellationToken).ConfigureAwait(false))
        {
            await EnsureLoginSuccessAsync(_imds, response, "o IMDS (instância sem perfil do IAM?)", xml: false, cancellationToken).ConfigureAwait(false);
            role = (await ReadTextAsync(_imds, response, cancellationToken).ConfigureAwait(false))
                .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? string.Empty;
        }

        if (role.Length is 0 or > 64 || !role.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '=' or ',' or '.' or '@' or '_' or '-'))
            throw new VaultLoginException("o IMDS devolveu um nome de papel fora do formato");

        using var credentials = await _imds.SendAsync(() => ImdsRequest("latest/meta-data/iam/security-credentials/" + role, token), idempotent: true,
            cancellationToken).ConfigureAwait(false);
        await EnsureLoginSuccessAsync(_imds, credentials, "o IMDS", xml: false, cancellationToken).ConfigureAwait(false);
        return await ReadJsonCredentialsAsync(_imds, credentials, "IMDS", cancellationToken).ConfigureAwait(false);
    }

    private static HttpRequestMessage ImdsRequest(string path, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.TryAddWithoutValidation("X-aws-ec2-metadata-token", token);
        return request;
    }

    // ---------- 4. Chaves estáticas (último recurso) ----------

    /// <summary>Chaves estáticas, relidas a cada login (código ou variáveis). <c>null</c> se não houver nenhuma.</summary>
    private AwsCredentials? Static()
    {
        var accessKeyId = Text(_options.AccessKeyId) ?? Variable(_options.AccessKeyIdVariable);
        var secretAccessKey = Text(_options.SecretAccessKey) ?? Variable(_options.SecretAccessKeyVariable);
        if (accessKeyId is null && secretAccessKey is null)
            return null;
        if (accessKeyId is null || secretAccessKey is null)
            throw new VaultLoginException("credencial estática da AWS incompleta: informe a chave de acesso e o segredo de acesso");

        var sessionToken = Text(_options.SessionToken) ?? Variable(_options.SessionTokenVariable);
        return AwsCredentials.Create(accessKeyId, secretAccessKey, sessionToken, "estática");
    }

    private string? Variable(string? name) => Text(name) is { } variable ? Text(_options.ReadVariable(variable)) : null;

    // ---------- Comum ----------

    /// <summary>
    /// 4xx (exceto 408 e 429) é login recusado (<see cref="VaultLoginException"/>, com o código do erro da AWS quando houver);
    /// 408, 429 e 5xx mantêm o status real (indisponível ou limite, contam no circuit breaker).
    /// </summary>
    private static async Task EnsureLoginSuccessAsync(VaultHttpClient client, HttpResponseMessage response, string source, bool xml,
        CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
            return;

        var status = response.StatusCode;
        if ((int)status is >= 400 and < 500 && status is not (HttpStatusCode.RequestTimeout or HttpStatusCode.TooManyRequests))
        {
            string? code = null;
            try
            {
                var body = await client.ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
                code = xml ? AwsErrors.QueryCode(body) : AwsErrors.JsonCode(body);
            }
            catch (Exception exception) when (exception is VaultResponseTooLargeException or TimeoutException or HttpRequestException)
            {
                // O código do erro é só para o log
            }

            response.Dispose();
            throw new VaultLoginException($"{source} recusou o login ({(int)status}{(code is null ? "" : " " + code)})");
        }

        VaultHttpClient.EnsureSuccess(response, "no login");
    }

    private static async Task<string> ReadTextAsync(VaultHttpClient client, HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var body = await client.ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
        try
        {
            return Encoding.UTF8.GetString(body).Trim();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>Resposta JSON do container ou do IMDS: <c>AccessKeyId</c>, <c>SecretAccessKey</c>, <c>Token</c> e <c>Expiration</c>.</summary>
    private static async Task<(AwsCredentials, DateTimeOffset?)> ReadJsonCredentialsAsync(VaultHttpClient client, HttpResponseMessage response,
        string source, CancellationToken cancellationToken)
    {
        var body = await client.ReadBytesAsync(response, cancellationToken).ConfigureAwait(false);
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 16 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new VaultLoginException($"credencial da AWS fora do formato ({source})");
            if (String(root, "Code") is { } code && !string.Equals(code, "Success", StringComparison.Ordinal))
                throw new VaultLoginException($"{source} não devolveu credencial (Code diferente de Success)");

            var credentials = AwsCredentials.Create(String(root, "AccessKeyId"), String(root, "SecretAccessKey"), String(root, "Token"), source);
            return (credentials, Expiration(String(root, "Expiration"), source));
        }
        catch (JsonException exception)
        {
            throw new VaultLoginException($"credencial da AWS fora do formato ({source})", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(body);
        }
    }

    /// <summary>Expiração ISO 8601 de uma credencial temporária; sem ela não há renovação antecipada, então é obrigatória.</summary>
    private static DateTimeOffset Expiration(string? text, string source) =>
        DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value)
            ? value
            : throw new VaultLoginException($"credencial temporária da AWS sem expiração válida ({source})");

    private static string? String(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string? Text(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

/// <summary>Mensagens de log do provedor AWS (source generator). Nunca registram valores.</summary>
internal static partial class AwsLog
{
    [LoggerMessage(3101, LogLevel.Information,
        "AWS Secrets Manager: o serviço de metadados do EC2 não respondeu ({ExceptionType}); o processo passa a usar as chaves estáticas configuradas.")]
    public static partial void InstanceMetadataUnavailable(ILogger logger, string exceptionType);
}
