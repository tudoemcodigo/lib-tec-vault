# ADR 0007: Cache em Memória com Invalidação por Escrita e Proteção Anti-Stampede

## Status
Aprovado

## Data
2026-10-08

## Contexto
Leituras contínuas de segredos remotos (como tokens de autenticação de banco de dados ou chaves de APIs parceiras) a cada requisição de entrada introduzem latência de rede adicional (10 a 100 ms) e atingem as cotas de requisição dos cofres.
No entanto, o uso ingênuo de cache em memória para segredos traz dois graves problemas:
1. **Cache Stampede (Thundering Herd)**: Quando o cache de um segredo de alta demanda expira, centenas de requisições paralelas disparam consultas idênticas e simultâneas ao cofre remoto ao mesmo tempo, gerando pico de latência e gatilhando limites de rate limit (HTTP 429).
2. **Inconsistência após mutação**: Se a aplicação rotacionar ou gravar um segredo via `SetSecretAsync`, o cache local continuaria servindo o valor desatualizado até expirar o TTL, causando falhas de autenticação.

## Decisão
Implementar um decorador de cache especializado (`CachingSecretReader`) acionado opcionalmente via `EnableSecretCache`:
1. **Proteção Anti-Stampede (Single-Flight / Coalescência de Chamadas)**:
   - Utilização do padrão SingleFlight para garantir que, sob concorrência intensa na mesma chave, **apenas uma única chamada real** seja despachada contra o cofre remoto.
   - Todas as demais requisições concorrentes aguardam o término dessa mesma tarefa em execução e compartilham o resultado obtido.
2. **Invalidação Proativa nas Mutações**:
   - Escritas pelas interfaces (`SetSecretAsync`, `UpdateSecretPropertiesAsync`, `DeleteSecretAsync`, recuperação, remoção definitiva e restauração de backup; a rotação passa por `SetSecretAsync`) limpam **todo** o cache e mudam um contador de geração. Uma leitura que estava em andamento durante a escrita não grava seu valor. Limpar tudo evita depender da comparação de nomes, que varia entre provedores.
3. **Isolamento de Segurança**:
   - O cache em memória é desligado por padrão e opera com TTL configurável (`Vault:Cache:Duration`, maior que zero e até 1 hora, nunca além do `ExpiresOn` do segredo) e no máximo 1.024 entradas.
   - Cópias em cache são encapsuladas e mascaradas em representações textuais para evitar vazamento acidental em depuradores ou dumps.
4. **Teto da leitura compartilhada** (revisão de 2026-10-29): a chamada compartilhada não usa o `CancellationToken` de nenhum chamador, mas tem teto próprio de 2 minutos. Passou dele, quem aguarda recebe `VAULT_INDISPONIVEL` e a próxima leitura consulta o cofre de novo; antes, um provedor que nunca respondesse prendia a chave para sempre.
5. **Chave conforme o provedor** (revisão de 2026-10-29): o nome na chave segue `VaultProviderBase.NameComparer`. Num cofre que não diferencia maiúsculas, grafias diferentes ocupam uma entrada só; nos demais (e em leitores que não derivam da base), continuam separadas, porque juntar nomes que o cofre trata como diferentes serviria um segredo no lugar de outro.

## Consequências
### Positivas
- Redução drástica da latência de leitura para microsegundos em chamadas frequentes.
- Redução drástica dos custos e consumo de cota de chamadas contra serviços gerenciados de cofre.
- Proteção absoluta contra travamentos por *Cache Stampede*.

### Neutras / Negativas
- Em arquiteturas com múltiplas réplicas da aplicação, a mutação feita em uma réplica invalida o cache apenas daquela réplica local; as demais réplicas aguardam o vencimento do TTL configurado (recomendado até 5 minutos). Uma escrita pela classe concreta do provedor, que continua registrada no container, também não limpa o cache.
