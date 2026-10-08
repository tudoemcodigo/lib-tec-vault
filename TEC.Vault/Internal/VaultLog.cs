using Microsoft.Extensions.Logging;

namespace TEC.Vault.Internal;

/// <summary>
/// Mensagens de log do cofre (source generator: sem alocação quando o nível está desabilitado).
/// Segurança: valores de segredos, textos claros, chaves e certificados nunca são registrados; apenas provedor,
/// operação, nome do item e códigos de erro. Operações de escrita são registradas em Information (trilha de auditoria).
/// </summary>
internal static partial class VaultLog
{
    [LoggerMessage(2000, LogLevel.Debug, "Cofre {Provider}: {Operation} de '{ItemName}' concluída em {ElapsedMilliseconds} ms.")]
    public static partial void ReadSucceeded(ILogger logger, string provider, string operation, string itemName, long elapsedMilliseconds);

    [LoggerMessage(2001, LogLevel.Information, "Auditoria do cofre {Provider}: {Operation} de '{ItemName}' concluída em {ElapsedMilliseconds} ms.")]
    public static partial void WriteSucceeded(ILogger logger, string provider, string operation, string itemName, long elapsedMilliseconds);

    [LoggerMessage(2002, LogLevel.Information, "Cofre {Provider}: {Operation} de '{ItemName}' retornou {ErrorCode} ({Detail}).")]
    public static partial void ExpectedFailure(ILogger logger, string provider, string operation, string itemName, string errorCode, string detail);

    [LoggerMessage(2003, LogLevel.Warning, "Auditoria do cofre {Provider}: {Operation} de '{ItemName}' retornou {ErrorCode} ({Detail}).")]
    public static partial void WriteFailure(ILogger logger, string provider, string operation, string itemName, string errorCode, string detail);

    [LoggerMessage(2004, LogLevel.Error, "Cofre {Provider}: {Operation} de '{ItemName}' falhou por infraestrutura: {ErrorCode} ({Detail}).")]
    public static partial void InfrastructureFailure(ILogger logger, string provider, string operation, string itemName, string errorCode, string detail);

    [LoggerMessage(2005, LogLevel.Error, "Cofre {Provider}: {Operation} de '{ItemName}' lançou {ExceptionType} inesperada; convertida em {ErrorCode}.")]
    public static partial void UnexpectedException(ILogger logger, Exception exception, string provider, string operation, string itemName,
        string exceptionType, string errorCode);

    [LoggerMessage(2006, LogLevel.Debug, "Cofre {Provider}: {Operation} de '{ItemName}' recusada na validação de entrada ({Field}).")]
    public static partial void InvalidInput(ILogger logger, string provider, string operation, string itemName, string field);

    [LoggerMessage(2007, LogLevel.Warning, "Health check do cofre falhou: {ErrorCode}.")]
    public static partial void HealthCheckFailed(ILogger logger, string errorCode);

    [LoggerMessage(2008, LogLevel.Information, "Auditoria do cofre {Provider}: {Operation} de '{ItemName}': {Reason}.")]
    public static partial void SensitiveRead(ILogger logger, string provider, string operation, string itemName, string reason);

    [LoggerMessage(2009, LogLevel.Warning,
        "Cofre {Provider}: rotação de '{ItemName}' gravou a versão {Version}, mas {Pending} versões anteriores podem continuar habilitadas ({ErrorCode}). Conclua com DisablePreviousSecretVersionsAsync.")]
    public static partial void RotationIncomplete(ILogger logger, string provider, string itemName, string version, int pending, string errorCode);

    [LoggerMessage(2010, LogLevel.Warning,
        "Health check do cofre sem nenhuma verificação: nenhum store registrado oferece uma operação de verificação (ex.: só IKeyCryptography sem IVaultHealthProbe). O check responde saudável sem consultar o cofre.")]
    public static partial void HealthCheckWithoutChecks(ILogger logger);

    // ---------- Provedor de IConfiguration ----------

    [LoggerMessage(2100, LogLevel.Error, "Configuração do cofre ({Provider}): falha na carga inicial: {ErrorCode}.")]
    public static partial void ConfigurationLoadFailed(ILogger logger, string provider, string errorCode);

    [LoggerMessage(2101, LogLevel.Warning, "Configuração do cofre ({Provider}): falha na recarga, valores anteriores mantidos: {ErrorCode}.")]
    public static partial void ConfigurationReloadFailed(ILogger logger, string provider, string errorCode);

    [LoggerMessage(2102, LogLevel.Error,
        "Configuração do cofre ({Provider}): {Count} segredos correspondem ao filtro, acima do limite MaxSecrets ({MaxSecrets}). Use um Prefix mais específico ou aumente MaxSecrets.")]
    public static partial void ConfigurationTooManySecrets(ILogger logger, string provider, int count, int maxSecrets);

    [LoggerMessage(2103, LogLevel.Error, "Configuração do cofre ({Provider}): tempo limite de {TimeoutSeconds} s excedido ao carregar os segredos.")]
    public static partial void ConfigurationTimeout(ILogger logger, string provider, double timeoutSeconds);

    [LoggerMessage(2104, LogLevel.Information, "Configuração do cofre ({Provider}): {Count} segredos carregados ({Read} lidos do cofre) em {ElapsedMilliseconds} ms.")]
    public static partial void ConfigurationLoaded(ILogger logger, string provider, int count, int read, long elapsedMilliseconds);

    [LoggerMessage(2105, LogLevel.Error, "Configuração do cofre ({Provider}): recarga lançou {ExceptionType} inesperada; valores anteriores mantidos.")]
    public static partial void ConfigurationReloadException(ILogger logger, Exception exception, string provider, string exceptionType);

    [LoggerMessage(2106, LogLevel.Error, "Configuração do cofre ({Provider}): a carga lançou {ExceptionType} inesperada.")]
    public static partial void ConfigurationLoadException(ILogger logger, Exception exception, string provider, string exceptionType);

    [LoggerMessage(2107, LogLevel.Debug, "Configuração do cofre ({Provider}): carga descartada, uma carga iniciada depois já foi aplicada.")]
    public static partial void ConfigurationStaleLoadDiscarded(ILogger logger, string provider);
}
