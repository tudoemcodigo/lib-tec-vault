# ADR 0010: Auditoria e Observabilidade Sem Vazamento de Segredos

## Status
Aprovado

## Data
2026-10-08

## Contexto
Em ambientes produtivos regulados (PCI-DSS, LGPD, ISO 27001), sistemas de monitoramento e agregação de logs (Elasticsearch, Loki, Datadog, Prometheus, Dynatrace) ingerem centenas de gigabytes de telemetria diários.
O maior risco de vazamento de credenciais na era moderna não reside em invasões de banco de dados, mas sim no descarte acidental de valores sensíveis em sistemas de log e métricas:
1. Interpolação acidental de segredos em mensagens de log (`logger.LogInformation("Lendo segredo: {Val}", secret.Value)`).
2. Chamadas a `ToString()` em objetos de retorno expondo o segredo em claro.
3. Exportação de nomes de itens confidenciais como tags de métricas do Prometheus, gerando explosão de cardinalidade (*cardinality explosion*) e vazamento de informações.
4. Tentativas de injeção ou valores digitados por engano no lugar do nome do segredo registrados em claro nos logs de auditoria.

## Decisão
Blindar toda a camada de telemetria, log e OpenTelemetry do `TEC.Vault` através de controles rígidos de segurança:
1. **Mascaramento Nativo em Objetos de Segredo**:
   - As estruturas e classes que encapsulam segredos (`SecretValue`, `SecretBundle`) sobrescrevem `ToString()` para retornar um texto fixo mascarado (`***`), impedindo vazamento acidental em serializações ou logs genéricos.
2. **Logs Estruturados com Alta Performance (`LoggerMessage`)**:
   - Todos os logs de auditoria utilizam geradores de código `LoggerMessage`, garantindo zero alocação e impedindo interpolação manual de strings.
   - Logs de escrita (`WriteSucceeded`) e leituras confidenciais registram apenas o nome do item e o tempo de execução em milissegundos — **nunca o valor do segredo**.
3. **Higienização de Entradas Não Confiáveis (`SensitiveDataMasker`)**:
   - Nomes de itens recusados por erro de validação (que podem conter senhas digitadas por engano pelo operador ou payloads de ataque) nunca são impressos em claro no log: são registrados apenas como o tamanho da entrada e o HMAC com chave aleatória do processo (`SensitiveDataMasker.DescribeUntrusted`).
4. **Métricas Sem Explosão de Cardinalidade**:
   - O `Meter` `TEC.Vault` registra durações e contadores de operações (`vault.operations`, `vault.circuit.state_changes`) utilizando tags genéricas (`vault.provider`, `vault.operation`, `error.type`). **Nenhum nome de item, versão ou valor é utilizado como dimensão/tag de métrica**.

## Consequências
### Positivas
- Risco zero de vazamento de segredos para indexadores de logs ou painéis de observabilidade.
- Total conformidade com PCI-DSS e LGPD para auditoria de acesso a dados confidenciais.
- Métricas limpas com cardinalidade controlada e compatibilidade integral com OpenTelemetry.

### Neutras / Negativas
- A identificação de um nome de segredo inválido em tempo de desenvolvimento exige conferir a configuração local, já que o log intencionalmente oculta a string recusada.
