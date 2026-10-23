# ADR 0011: Provedor Encadeado com Fallback em Camadas

## Status
Aprovado

## Data
2026-10-23

## Contexto
Em arquiteturas modernas de microsserviços, desenvolvedores frequentemente precisam rodar a aplicação localmente ou aplicar um hotfix emergencial em produção sem alterar as configurações corporativas nos cofres centrais de nuvem (Azure Key Vault, HashiCorp Vault, AWS, Google).
Se o componente de cofre obrigar a escolha de um único provedor exclusivo, o desenvolvedor é forçado a:
1. Recompilar a aplicação para trocar o provedor.
2. Criar lógicas artesanais de bypass no código de negócio.

## Decisão
Implementar o `ChainedSecretReader` no núcleo do `TEC.Vault`, permitindo encadear uma lista ordenada de leitores de segredos:
- Resolução por prioridade decrescente.
- O erro `VAULT_ITEM_NAO_ENCONTRADO` atua como gatilho de transição para o próximo leitor da cadeia.
- Erros terminais (como `VAULT_ACESSO_NEGADO`) interrompem o encadeamento para não mascarar falhas de segurança.
- As listagens de segredos agregam as entradas de todos os stores de forma deduplicada e consistente.

## Consequências
### Positivas
- Permite cenários avançados de *override* de configuração (ex.: Variáveis de Ambiente locais com fallback transparente para cofre de nuvem).
- Totalmente compatível com `ISecretReader` e com a sonda de saúde `IVaultHealthProbe`.

### Neutras / Negativas
- Em caso de itens inexistentes em toda a cadeia, o tempo total de resposta é a soma dos tempos de consulta de cada provedor até a constatação de `VAULT_ITEM_NAO_ENCONTRADO`.
