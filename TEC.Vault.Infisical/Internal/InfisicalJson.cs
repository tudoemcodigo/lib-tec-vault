using System.Text.Json;
using System.Text.Json.Serialization;

namespace TEC.Vault.Infisical.Internal;

// Contratos da API v4 do Infisical (https://infisical.com/docs/api-reference). Só os campos usados.

internal sealed class InfisicalLoginResponse
{
    public string? AccessToken { get; set; }

    public double ExpiresIn { get; set; }
}

internal sealed class UniversalAuthLogin
{
    public required string ClientId { get; init; }

    public required string ClientSecret { get; init; }
}

internal sealed class KubernetesAuthLogin
{
    public required string IdentityId { get; init; }

    public required string Jwt { get; init; }

    public string? OrganizationSlug { get; init; }
}

internal sealed class InfisicalMetadata
{
    public string Key { get; set; } = "";

    public string? Value { get; set; }

    public bool? IsEncrypted { get; set; }
}

internal sealed class InfisicalSecret
{
    public string? Id { get; set; }

    public long Version { get; set; }

    public string SecretKey { get; set; } = "";

    public string? SecretValue { get; set; }

    public bool SecretValueHidden { get; set; }

    public DateTimeOffset? CreatedAt { get; set; }

    public DateTimeOffset? UpdatedAt { get; set; }

    public string? SecretPath { get; set; }

    public List<InfisicalMetadata>? SecretMetadata { get; set; }
}

internal sealed class InfisicalSecretEnvelope
{
    public InfisicalSecret? Secret { get; set; }

    /// <summary>Presente quando o ambiente tem política de aprovação: a escrita ficou pendente.</summary>
    public JsonElement? Approval { get; set; }
}

internal sealed class InfisicalSecretList
{
    public List<InfisicalSecret> Secrets { get; set; } = [];
}

internal sealed class InfisicalWrite
{
    public required string ProjectId { get; init; }

    public required string Environment { get; init; }

    public required string SecretPath { get; init; }

    public string Type { get; init; } = "shared";

    public string? SecretValue { get; init; }

    public List<InfisicalMetadata>? SecretMetadata { get; init; }
}

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(InfisicalLoginResponse))]
[JsonSerializable(typeof(UniversalAuthLogin))]
[JsonSerializable(typeof(KubernetesAuthLogin))]
[JsonSerializable(typeof(InfisicalSecretEnvelope))]
[JsonSerializable(typeof(InfisicalSecretList))]
[JsonSerializable(typeof(InfisicalWrite))]
internal sealed partial class InfisicalJsonContext : JsonSerializerContext;
