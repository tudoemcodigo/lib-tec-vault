# ADR 0005: Isolamento e Blindagem de Segredos em Variáveis de Ambiente

## Status
Aprovado

## Data
2026-10-08

## Contexto
O padrão "Twelve-Factor App" preconiza o armazenamento de configurações e credenciais em variáveis de ambiente. Ferramentas modernas de segredos (como `infisical run`, `bws run`, `op run` ou a diretiva `envFrom` do Kubernetes) injetam segredos no processo da aplicação através de variáveis de ambiente.

No entanto, o uso ingênuo de variáveis de ambiente para segredos traz graves riscos de segurança e integridade:
1. **Exposição indiscriminada**: O processo do SO contém variáveis normais do sistema (`PATH`, `HOME`, `USERNAME`, flags do runtime). Se a aplicação listar todas as variáveis indiscriminadamente, dados não confidenciais e metadados de infraestrutura são expostos como segredos.
2. **Vazamento por herança**: Processos-filho (`fork`/`exec`) e chamadas a binários externos herdam todas as variáveis do processo-pai.
3. **Persistência em dumps de depuração**: O bloco de ambiente fica exposto em dumps de memória do processo e em `/proc/<pid>/environ` no Linux.
4. **Ausência de versionamento**: Variáveis de ambiente não possuem carimbo de data nem versão nativa, inviabilizando detecção de rotação e recarga incremental pelo `IConfiguration`.

## Decisão
Implementar a leitura de variáveis de ambiente através de uma classe especializada e blindada, a `EnvironmentSecretStore` (provedor `"EnvironmentVariables"`), com regras rígidas de segurança:
1. **Prefixo Obrigatório de Segurança**:
   - É obrigatório informar um prefixo com pelo menos 2 caracteres alfanuméricos ou sublinhado (ex.: `TECVAULT_`).
   - Tentativas de configurar prefixo vazio ou nulo disparam `InvalidOperationException` na inicialização da aplicação, impedindo a exposição acidental de variáveis do sistema.
2. **Normalização de Nomes e Hierarquia**:
   - O prefixo é removido do nome final do segredo.
   - O separador de hierarquia padrão do .NET para variáveis (`__`) é convertido para o padrão do TEC.Vault (`--`), permitindo suporte a seções do `IConfiguration` (ex.: `TECVAULT_ConnectionStrings__Database` vira `ConnectionStrings--Database`).
3. **Limites Rígidos Contra Negação de Serviço (DoS)**:
   - Teto configurável de itens (`MaxItems`, padrão 1.000, limite máximo 10.000).
   - Teto configurável de tamanho por valor (`MaxValueBytes`, padrão 64 KB, limite máximo 1 MB).
4. **Versionamento Criptográfico por HMAC**:
   - Como variáveis não possuem metadados de versão, a `Version` é calculada dinamicamente como o HMAC-SHA256 truncado do valor, utilizando uma chave criptográfica efêmera gerada aleatoriamente por instância do store.
   - Isso permite detectar alterações de valor para recarga de configuração sem expor hashes comparáveis fora do processo.

## Consequências
### Positivas
- Total conformidade com workflows de injeção CLI (`bws run`, `infisical run`, K8s `envFrom`).
- Zero risco de expor variáveis de sistema do SO como segredos gerenciados.
- Integração transparente com o sistema de recarga incremental do `IConfiguration`.

### Neutras / Negativas
- Segredos em variáveis de ambiente não sofrem atualização atômica no SO após a subida do processo sem reinicialização do Pod (a menos que a ferramenta externa reescreva o ambiente e o store reler a cada chamada). Para rotação dinâmica contínua sem restart, recomenda-se o provedor `Directory` com volumes montados.
