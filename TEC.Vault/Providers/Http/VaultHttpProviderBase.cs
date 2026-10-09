using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TEC.Vault.Common;

namespace TEC.Vault.Providers.Http;

/// <summary>
/// Base para provedores acessados por HTTP sem SDK (HashiCorp Vault, Infisical...): <see cref="VaultProviderBase"/> com a
/// conversão padrão das falhas de <see cref="VaultHttpClient"/>.
/// </summary>
/// <remarks>
/// Conversão de status: 400/422 → <see cref="VaultErrors.Rejected"/>, 401 → <see cref="VaultErrors.AuthenticationFailed"/>,
/// 403 → <see cref="VaultErrors.AccessDenied"/>, 404 → <see cref="VaultErrors.NotFound"/>, 409/412 → <see cref="VaultErrors.Conflict"/>,
/// 429 → <see cref="VaultErrors.Throttled"/>, 408/5xx, falha de rede e tempo limite → <see cref="VaultErrors.Unavailable"/>.
/// Login sem credencial legível → <see cref="VaultErrors.AuthenticationFailed"/>. Resposta fora do formato ou acima de
/// <see cref="VaultHttpSettings.MaxResponseBytes"/> → <see cref="VaultErrors.ProviderFailure"/>.
/// </remarks>
public abstract class VaultHttpProviderBase : VaultProviderBase
{
    /// <summary>Cria a base.</summary>
    /// <param name="providerName">Nome do provedor.</param>
    /// <param name="logger">Logger do provedor.</param>
    /// <param name="circuitBreaker">Circuit breaker do cofre (<see cref="VaultHttpSettings.CircuitBreaker"/>); <c>null</c> = desligado.</param>
    protected VaultHttpProviderBase(string providerName, ILogger logger, VaultCircuitBreaker? circuitBreaker = null)
        : base(providerName, logger, circuitBreaker)
    {
    }

    /// <inheritdoc />
    protected sealed override VaultFailure? MapException(Exception exception) =>
        MapProviderException(exception) ?? MapHttpException(exception);

    /// <summary>Conversões próprias do provedor, avaliadas antes das padrão. Padrão: nenhuma.</summary>
    protected virtual VaultFailure? MapProviderException(Exception exception) => null;

    /// <summary>Conversão padrão das falhas HTTP (também usada pelos testes de cada provedor).</summary>
    public static VaultFailure? MapHttpException(Exception exception) => exception switch
    {
        VaultResponseTooLargeException large => new VaultFailure(VaultErrors.ProviderFailure(), $"resposta acima de MaxResponseBytes ({large.MaxBytes} bytes)"),
        VaultHttpException http => MapStatus(http.StatusCode, http.Detail),
        VaultLoginException login => new VaultFailure(VaultErrors.AuthenticationFailed(), "login: " + login.Message),
        TimeoutException => new VaultFailure(VaultErrors.Unavailable(), "tempo limite"),
        HttpRequestException request => new VaultFailure(VaultErrors.Unavailable(), "rede: " + (request.HttpRequestError.ToString())),
        JsonException => new VaultFailure(VaultErrors.ProviderFailure(), "resposta em formato inesperado"),
        _ => null
    };

    /// <summary>Conversão de um status HTTP de erro.</summary>
    public static VaultFailure MapStatus(HttpStatusCode status, string? detail = null)
    {
        var text = detail is null ? ((int)status).ToString(System.Globalization.CultureInfo.InvariantCulture) : $"{(int)status} {detail}";
        return status switch
        {
            HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => new VaultFailure(VaultErrors.Rejected(), text),
            HttpStatusCode.Unauthorized => new VaultFailure(VaultErrors.AuthenticationFailed(), text),
            HttpStatusCode.Forbidden => new VaultFailure(VaultErrors.AccessDenied(), text),
            HttpStatusCode.NotFound => new VaultFailure(VaultErrors.NotFound(), text),
            HttpStatusCode.Conflict or HttpStatusCode.PreconditionFailed => new VaultFailure(VaultErrors.Conflict(), text),
            HttpStatusCode.TooManyRequests => new VaultFailure(VaultErrors.Throttled(), text),
            HttpStatusCode.RequestTimeout => new VaultFailure(VaultErrors.Unavailable(), text),
            >= HttpStatusCode.InternalServerError => new VaultFailure(VaultErrors.Unavailable(), text),
            _ => new VaultFailure(VaultErrors.ProviderFailure(), text)
        };
    }
}

/// <summary>Falha no login do cofre (credencial ausente, ilegível ou recusada). A mensagem nunca contém a credencial.</summary>
public sealed class VaultLoginException : Exception
{
    /// <summary>Cria a exceção.</summary>
    public VaultLoginException(string message, Exception? innerException = null) : base(message, innerException)
    {
    }
}
