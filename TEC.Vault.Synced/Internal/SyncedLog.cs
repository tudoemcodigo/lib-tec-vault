using Microsoft.Extensions.Logging;

namespace TEC.Vault.Synced.Internal;

/// <summary>Mensagens de log dos leitores sincronizados (source generator). Nunca registram valores.</summary>
internal static partial class SyncedLog
{
    [LoggerMessage(3001, LogLevel.Warning, "Link simbólico para fora da pasta de segredos ignorado: {Name}.")]
    public static partial void LinkOutsideFolderIgnored(ILogger logger, string name);

    [LoggerMessage(3002, LogLevel.Warning, "Arquivo de segredo ignorado: o destino mudou entre a conferência e a abertura: {Name}.")]
    public static partial void LinkChangedWhileOpeningIgnored(ILogger logger, string name);
}
