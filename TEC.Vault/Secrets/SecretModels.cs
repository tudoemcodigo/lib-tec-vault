using System.Diagnostics;
using TEC.Vault.Common;
using TEC.Core.Common.Results;

namespace TEC.Vault.Secrets;

/// <summary>Metadados de um segredo (sem o valor).</summary>
public sealed record SecretProperties : VaultItemProperties
{
    /// <summary>Tipo do conteúdo (ex.: "text/plain", "application/json"). Informativo.</summary>
    public string? ContentType { get; init; }
}

/// <summary>Segredo lido do cofre: metadados + valor.</summary>
/// <remarks>
/// Segurança: não é um <c>record</c> de propósito. <see cref="ToString"/> e a visualização do depurador mascaram o valor,
/// para que ele não vá parar em logs, mensagens de exceção ou serializações acidentais por interpolação de string.
/// Não guarde a instância além do necessário.
/// </remarks>
[DebuggerDisplay("{ToString(),nq}")]
public sealed class VaultSecret
{
    /// <summary>Cria o segredo.</summary>
    public VaultSecret(SecretProperties properties, string value)
    {
        ArgumentNullException.ThrowIfNull(properties);
        ArgumentNullException.ThrowIfNull(value);
        Properties = properties;
        Value = value;
    }

    /// <summary>Metadados do segredo.</summary>
    public SecretProperties Properties { get; }

    /// <summary>Valor do segredo. Nunca registre em log.</summary>
    public string Value { get; }

    /// <summary>Nome do segredo.</summary>
    public string Name => Properties.Name;

    /// <summary>Versão do segredo.</summary>
    public string? Version => Properties.Version;

    /// <inheritdoc />
    public override string ToString() => $"VaultSecret {{ Name = {Name}, Version = {Version}, Value = *** }}";
}

/// <summary>Opções de gravação de um segredo (nova versão).</summary>
public sealed record SecretWriteOptions
{
    /// <summary>Tipo do conteúdo (ex.: "text/plain"). Máximo 255 caracteres.</summary>
    public string? ContentType { get; init; }

    /// <summary>Habilitado. Padrão: <c>true</c>.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>Validade. Recomendado: todo segredo deve expirar e ser rotacionado.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>Início da validade.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>Tags. Nunca coloque dados sensíveis em tags.</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }
}

/// <summary>Alteração de metadados de uma versão de segredo. Propriedades <c>null</c> não são alteradas.</summary>
public sealed record SecretPropertiesUpdate
{
    /// <summary>Habilita ou desabilita a versão.</summary>
    public bool? Enabled { get; init; }

    /// <summary>Nova data de expiração.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>Nova data de início da validade.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>Novo tipo do conteúdo.</summary>
    public string? ContentType { get; init; }

    /// <summary>Novas tags (substituem as atuais).</summary>
    public IReadOnlyDictionary<string, string>? Tags { get; init; }
}

/// <summary>
/// Resultado de <c>SecretStoreExtensions.RotateSecretAsync</c> e <see cref="SecretStoreExtensions.DisablePreviousSecretVersionsAsync"/>.
/// </summary>
/// <remarks>
/// A rotação tem duas etapas no cofre (gravar a nova versão e desabilitar as anteriores) e não é atômica. Se a nova versão foi
/// gravada, o resultado é sucesso e informa a versão criada em <see cref="Current"/>, mesmo que alguma versão anterior não tenha
/// sido desabilitada. Confira <see cref="IsComplete"/>: se for <c>false</c>, <b>não</b> rotacione de novo (criaria mais uma versão);
/// chame <see cref="SecretStoreExtensions.DisablePreviousSecretVersionsAsync"/> com <c>Current.Version</c>, que é idempotente.
/// </remarks>
public sealed record SecretRotationResult
{
    /// <summary>Versão atual: a nova versão gravada pela rotação (ou a informada, ao só desabilitar as anteriores).</summary>
    public required SecretProperties Current { get; init; }

    /// <summary>Versões anteriores desabilitadas nesta chamada.</summary>
    public IReadOnlyList<string> DisabledVersions { get; init; } = [];

    /// <summary>
    /// Versões anteriores que deveriam ter sido desabilitadas e podem continuar habilitadas: falha do cofre ou cancelamento
    /// depois da gravação da nova versão (<see cref="VaultErrors.CanceledCode"/> em <see cref="Errors"/>).
    /// </summary>
    public IReadOnlyList<string> FailedVersions { get; init; } = [];

    /// <summary>Erros das versões em <see cref="FailedVersions"/> (mesma ordem).</summary>
    public IReadOnlyList<Error> Errors { get; init; } = [];

    /// <summary><c>true</c> se todas as etapas pedidas foram concluídas.</summary>
    public bool IsComplete => FailedVersions.Count == 0;
}

/// <summary>Formato do segredo gerado por <see cref="SecretStoreExtensions.GenerateSecretAsync"/>.</summary>
public enum SecretGenerationKind
{
    /// <summary>Senha com letras, dígitos e símbolos (sem caracteres ambíguos).</summary>
    Password = 0,

    /// <summary>Token aleatório em Base64Url (seguro para URLs e cabeçalhos).</summary>
    Token = 1,

    /// <summary>Valor aleatório em hexadecimal minúsculo.</summary>
    Hex = 2
}

/// <summary>Parâmetros de geração de segredo (gerador criptograficamente seguro do TEC.Core).</summary>
public sealed record SecretGenerationOptions
{
    /// <summary>Formato. Padrão: <see cref="SecretGenerationKind.Password"/>.</summary>
    public SecretGenerationKind Kind { get; init; } = SecretGenerationKind.Password;

    /// <summary>
    /// Tamanho: caracteres para senha (16 a 1024) ou bytes aleatórios para token/hex (16 a 1024).
    /// Padrão: 32 (senha de 32 caracteres ou 256 bits de entropia).
    /// </summary>
    public int Length { get; init; } = 32;

    /// <summary>Senha: incluir símbolos. Padrão: <c>true</c>.</summary>
    public bool IncludeSpecialCharacters { get; init; } = true;
}
