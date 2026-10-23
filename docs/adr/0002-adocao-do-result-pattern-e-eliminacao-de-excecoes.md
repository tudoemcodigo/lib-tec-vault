# ADR 0002: Adoção do Result Pattern e Eliminação de Exceções de Infraestrutura

## Status
Aprovado

## Data
2026-10-08

## Contexto
SDKs de nuvem tradicionais comunicam erros de rede, limites e autorização lançando exceções complexas (`RequestFailedException`, `VaultException`, `HttpRequestException`). Isso gera sérios problemas em sistemas de produção:
1. **Vazamento de Dados Sensíveis**: Exceções de rede frequentemente contêm em sua mensagem a URL do cofre, parâmetros de query, cabeçalhos de autorização ou identificadores de recursos internos. Se capturadas por um middleware genérico e serializadas para o cliente (em respostas de erro HTTP ou logs abertos), representam vulnerabilidade de reconhecimento da infraestrutura.
2. **Controle de Fluxo Ineficiente**: O lançamento e captura de exceções para casos comuns como "item não encontrado" ou "versão inexistente" consome ciclos de CPU e alocações de memória desnecessárias.
3. **Falta de Padronização**: Cada provedor codifica erros HTTP de forma diferente (ex.: 404 no Azure vs 404 no HashiCorp Vault vs 404 no Infisical).

## Decisão
Adotar o **Result Pattern** nativo do `TEC.Core` (`Result` e `Result<T>`) em todas as operações públicas de leitura, escrita e criptografia do `TEC.Vault`:
- Nenhum método público do `TEC.Vault` lança exceções para falhas esperadas ou operacionais.
- Todos os erros são convertidos em instâncias de `Error` com códigos canônicos definidos em `VaultErrors` (`VAULT_ITEM_NAO_ENCONTRADO`, `VAULT_ACESSO_NEGADO`, `VAULT_LIMITE_EXCEDIDO`, `VAULT_INDISPONIVEL`, `VAULT_CIRCUITO_ABERTO`, etc.).
- Exceções originais são capturadas internamente pela classe base (`VaultProviderBase` e `VaultHttpProviderBase`) e registradas em log estruturado apenas em nível técnico seguro (sem corpo nem valores).
- Cancelamento explícito solicitado pelo chamador (`cancellationToken.IsCancellationRequested`) continua propagando `OperationCanceledException` conforme diretrizes do .NET.

## Consequências
### Positivas
- Zero vazamento acidental de URLs, identidades gerenciadas ou detalhes de infraestrutura em respostas ao cliente.
- Alto desempenho e clareza no fluxo de código do chamador (`if (result.IsFailure) return result.ToFailure();`).
- Tratamento uniforme e previsível em toda a stack, independente de o cofre ser local, Azure, HashiCorp ou Infisical.

### Neutras / Negativas
- Desenvolvedores habituados ao modelo de `try/catch` para tudo precisam adotar a disciplina de conferir `result.IsSuccess` ou desestruturar o `Result`.
