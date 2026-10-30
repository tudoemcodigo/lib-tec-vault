# ADR 0006: Resiliência em Camadas: Retentativa Idempotente e Circuit Breaker por Cofre

## Status
Aprovado

## Data
2026-10-09

## Contexto
Cofres de segredos em rede (Azure Key Vault, HashiCorp Vault, Infisical) são serviços compartilhados e altamente sensíveis a rajadas de tráfego, limites de taxa (*rate limiting* HTTP 429) e quedas temporárias de rede (*flapping* ou indisponibilidade HTTP 503).
Dois problemas recorrentes afetam sistemas sem resiliência planejada:
1. **Sobrecarga do cofre por retentativas cegas**: Se todos os nós de uma aplicação retentarem operações não idempotentes ou retentarem indefinidamente quando o cofre estiver caído, o problema de *thundering herd* impede que o cofre se recupere.
2. **Retentativa perigosa de operações de escrita**: Retentar uma criação ou mutação não idempotente pode causar inconsistência ou criação duplicada de recursos.
3. **Cascata de bloqueio na aplicação**: Quando o cofre falha continuamente, threads de requisição acumulam timeouts longos, esgotando o ThreadPool da aplicação e derrubando serviços dependentes.

## Decisão
Implementar resiliência em duas camadas complementares, operando de fora para dentro:
1. **Camada 1: Retentativa Idempotente Interna (`VaultHttpClient` / SDK Azure)**:
   - Retentativas com *jitter* e *exponential backoff* aplicadas **exclusivamente a operações seguras e idempotentes** (GET, HEAD, DELETE e PUT idempotente). Métodos POST de mutação não idempotentes não sofrem retentativa cega.
   - Respeito estrito ao cabeçalho HTTP `Retry-After` quando retornado pelo cofre.
2. **Camada 2: Circuit Breaker Compartilhado por Cofre (`VaultCircuitBreaker` com `Polly.Core`)**:
   - Uma instância única de circuito compartilhado por todos os stores (segredos, chaves e certificados) que conversam com o mesmo cofre.
   - Baseado na biblioteca moderna `Polly.Core` 8.8.0 (compatível com Native AOT e sem dependências pesadas).
   - O circuito monitora falhas padronizadas do cofre (`VAULT_INDISPONIVEL` e `VAULT_LIMITE_EXCEDIDO`).
   - Quando o limiar de falhas é atingido, o circuito **abre**: chamadas subsequentes são recusadas instantaneamente na borda da aplicação com o erro `VAULT_CIRCUITO_ABERTO`, sem gastar sockets, conexões ou tempo de espera contra o cofre.
   - Transição controlada para estado de *Meia-Abertura* (*Half-Open*): uma única chamada de teste é autorizada; se bem-sucedida, o circuito fecha; se falhar ou for cancelada, o circuito reabre imediatamente.

## Consequências
### Positivas
- Proteção ativa do cofre de segredos contra saturação durante momentos de instabilidade.
- Falha rápida (*fail-fast*) da aplicação quando o cofre estiver comprovadamente inacessível, liberando threads do runtime.
- Telemetria e métricas dedicadas (`vault.circuit.state_changes`) permitindo dashboards e alarmes de SRE em tempo real.

### Neutras / Negativas
- A camada 1 fica no `VaultHttpClient` (HashiCorp Vault, Infisical, AWS e Google, este desde a revisão de 2026-10-29 do ADR 0012) e no SDK do Azure. Tempo limite, inclusive na leitura do corpo, sai como `VAULT_INDISPONIVEL` e conta no circuito.
- Além das operações idempotentes, o `VaultHttpClient` repete qualquer chamada recusada com 429 (a requisição foi rejeitada antes de ser processada).
- Durante o período de circuito aberto, consultas a segredos não em cache falham de imediato, exigindo que a aplicação trate `VAULT_CIRCUITO_ABERTO` (por exemplo, degradando graciosamente ou utilizando valores já em cache).
