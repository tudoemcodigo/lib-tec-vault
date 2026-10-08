using TEC.Core.Common.Results;

namespace TEC.Vault.Common;

/// <summary>
/// Erros padronizados do cofre. Todo provedor converte as suas falhas para estes códigos, então o consumidor trata
/// o resultado da mesma forma, seja qual for o cofre.
/// </summary>
/// <remarks>
/// Segurança: as mensagens nunca incluem nome de item, endereço do cofre, identidade ou resposta do provedor.
/// Falhas de infraestrutura (acesso negado ao cofre, autenticação, indisponibilidade) usam <see cref="ErrorType.ExternalService"/>,
/// cuja mensagem não é exposta ao cliente da API: um 403 do cofre é problema de configuração da aplicação, não do usuário.
/// </remarks>
public static class VaultErrors
{
    /// <summary>Código: dado de entrada inválido (nome, valor, tags, datas...).</summary>
    public const string InvalidInputCode = "VAULT_ENTRADA_INVALIDA";

    /// <summary>Código: item não encontrado (ou excluído).</summary>
    public const string NotFoundCode = "VAULT_ITEM_NAO_ENCONTRADO";

    /// <summary>Código: item em estado que impede a operação (ex.: excluído aguardando remoção, já existente).</summary>
    public const string ConflictCode = "VAULT_CONFLITO";

    /// <summary>Código: item desabilitado.</summary>
    public const string DisabledCode = "VAULT_ITEM_DESABILITADO";

    /// <summary>Código: certificado sem chave privada exportável.</summary>
    public const string NotExportableCode = "VAULT_CERTIFICADO_NAO_EXPORTAVEL";

    /// <summary>Código: o cofre recusou os dados enviados.</summary>
    public const string RejectedCode = "VAULT_REQUISICAO_RECUSADA";

    /// <summary>Código: a identidade da aplicação não tem permissão no cofre.</summary>
    public const string AccessDeniedCode = "VAULT_ACESSO_NEGADO";

    /// <summary>Código: não foi possível autenticar no cofre.</summary>
    public const string AuthenticationFailedCode = "VAULT_AUTENTICACAO_FALHOU";

    /// <summary>Código: limite de requisições do cofre excedido.</summary>
    public const string ThrottledCode = "VAULT_LIMITE_EXCEDIDO";

    /// <summary>Código: cofre indisponível (rede, timeout, erro 5xx).</summary>
    public const string UnavailableCode = "VAULT_INDISPONIVEL";

    /// <summary>Código: operação não suportada pelo provedor.</summary>
    public const string NotSupportedCode = "VAULT_OPERACAO_NAO_SUPORTADA";

    /// <summary>Código: falha não classificada do provedor.</summary>
    public const string ProviderFailureCode = "VAULT_FALHA";

    /// <summary>
    /// Código: etapa cancelada pelo chamador depois que parte da operação já tinha sido feita no cofre (ex.: rotação de segredo
    /// cancelada ao desabilitar as versões anteriores, com a nova versão já gravada). Operações simples canceladas lançam
    /// <see cref="OperationCanceledException"/> e não usam este código.
    /// </summary>
    public const string CanceledCode = "VAULT_OPERACAO_CANCELADA";

    /// <summary>
    /// Código: a listagem passou do limite de itens configurado no provedor (ex.: <c>MaxListItems</c>). A operação é interrompida
    /// assim que o limite é ultrapassado, sem ler o restante.
    /// </summary>
    public const string TooManyItemsCode = "VAULT_LISTAGEM_ACIMA_DO_LIMITE";

    /// <summary>Listagem acima do limite de itens do provedor (HTTP 500: ajuste de configuração da aplicação).</summary>
    public static Error TooManyItems() =>
        Error.Failure(TooManyItemsCode, "A listagem do cofre passou do limite de itens configurado. Use uma pasta/prefixo mais específico ou aumente o limite do provedor.");

    /// <summary>Entrada inválida (HTTP 400).</summary>
    public static Error InvalidInput(string field, string message) => Error.Validation(InvalidInputCode, message, field);

    /// <summary>Item não encontrado (HTTP 404).</summary>
    public static Error NotFound() => Error.NotFound(NotFoundCode, "Item não encontrado no cofre.");

    /// <summary>Conflito de estado (HTTP 409).</summary>
    public static Error Conflict() =>
        Error.Conflict(ConflictCode, "O item está em um estado que impede a operação (ex.: excluído aguardando remoção definitiva).");

    /// <summary>Item desabilitado (HTTP 422).</summary>
    public static Error Disabled() => Error.BusinessRule(DisabledCode, "O item está desabilitado no cofre.");

    /// <summary>Certificado sem chave privada exportável (HTTP 422).</summary>
    public static Error NotExportable() =>
        Error.BusinessRule(NotExportableCode, "O certificado não permite exportar a chave privada. Use o cofre de chaves para assinar.");

    /// <summary>Requisição recusada pelo cofre (HTTP 400).</summary>
    public static Error Rejected() => Error.Validation(RejectedCode, "Os dados informados foram recusados pelo cofre.");

    /// <summary>Acesso negado ao cofre (oculto do cliente).</summary>
    public static Error AccessDenied() =>
        Error.ExternalService(AccessDeniedCode, "A identidade da aplicação não tem permissão para esta operação no cofre.");

    /// <summary>Falha de autenticação (oculto do cliente).</summary>
    public static Error AuthenticationFailed() =>
        Error.ExternalService(AuthenticationFailedCode, "Não foi possível autenticar a aplicação no cofre.");

    /// <summary>Limite de requisições excedido (oculto do cliente).</summary>
    public static Error Throttled() => Error.ExternalService(ThrottledCode, "Limite de requisições do cofre excedido.");

    /// <summary>Cofre indisponível (oculto do cliente).</summary>
    public static Error Unavailable() => Error.ExternalService(UnavailableCode, "O cofre está indisponível no momento.");

    /// <summary>Operação não suportada pelo provedor (HTTP 500).</summary>
    public static Error NotSupported() => Error.Failure(NotSupportedCode, "Operação não suportada pelo provedor de cofre configurado.");

    /// <summary>Falha não classificada (oculto do cliente).</summary>
    public static Error ProviderFailure() => Error.ExternalService(ProviderFailureCode, "Falha ao executar a operação no cofre.");

    /// <summary>Etapa cancelada pelo chamador depois de parte da operação já concluída (HTTP 500).</summary>
    public static Error Canceled() => Error.Failure(CanceledCode, "A operação foi cancelada antes de terminar; parte dela já foi feita no cofre.");
}
