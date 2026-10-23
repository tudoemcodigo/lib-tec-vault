namespace TEC.Vault.Common;

/// <summary>Metadados comuns a segredos, chaves e certificados. Nunca contém o valor do item.</summary>
public abstract record VaultItemProperties
{
    /// <summary>Nome do item no cofre.</summary>
    public required string Name { get; init; }

    /// <summary>Versão do item (formato definido pelo provedor).</summary>
    public string? Version { get; init; }

    /// <summary>
    /// Identificador completo do item no provedor, no formato dele (ex.: URI no Azure Key Vault, ARN na AWS, caminho no
    /// HashiCorp Vault). Informativo: as operações usam sempre <see cref="Name"/> e <see cref="Version"/>.
    /// </summary>
    public string? Id { get; init; }

    /// <summary>Indica se o item está habilitado. Itens desabilitados não podem ser lidos nem usados.</summary>
    public bool Enabled { get; init; }

    /// <summary>Data de criação.</summary>
    public DateTimeOffset? CreatedOn { get; init; }

    /// <summary>Data da última atualização.</summary>
    public DateTimeOffset? UpdatedOn { get; init; }

    /// <summary>Data a partir da qual o item deixa de ser válido.</summary>
    public DateTimeOffset? ExpiresOn { get; init; }

    /// <summary>Data a partir da qual o item passa a ser válido.</summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>
    /// Quem gerencia o item, quando não é a aplicação: o item foi criado por outro recurso do provedor e não deve ser
    /// alterado diretamente. <c>null</c> = item comum. Exemplos: <c>"certificate"</c> para o segredo e a chave que guardam
    /// um certificado no Azure Key Vault; o serviço dono do segredo na AWS (<c>OwningService</c>).
    /// </summary>
    public string? ManagedBy { get; init; }

    /// <summary>Indica se o item é gerenciado por outro recurso do provedor (<see cref="ManagedBy"/> preenchido).</summary>
    public bool IsManaged => ManagedBy is not null;

    /// <summary>Tags (metadados livres). Nunca coloque dados sensíveis em tags: elas não são protegidas como o valor.</summary>
    public IReadOnlyDictionary<string, string> Tags { get; init; } = EmptyTags;

    /// <summary>Indica se o item está habilitado e dentro do período de validade no momento informado.</summary>
    public bool IsActive(DateTimeOffset now) =>
        Enabled && (NotBefore is null || NotBefore <= now) && (ExpiresOn is null || ExpiresOn > now);

    internal static readonly IReadOnlyDictionary<string, string> EmptyTags = new Dictionary<string, string>(0);
}

/// <summary>Item excluído, ainda recuperável até <see cref="ScheduledPurgeDate"/> (se o provedor tiver lixeira).</summary>
/// <param name="Name">Nome do item.</param>
/// <param name="DeletedOn">Data da exclusão.</param>
/// <param name="ScheduledPurgeDate">Data em que o provedor remove o item definitivamente (<c>null</c> = não informada).</param>
public sealed record DeletedVaultItem(string Name, DateTimeOffset? DeletedOn, DateTimeOffset? ScheduledPurgeDate);
