# ADR 0004: Provedor Synced para Ambientes Kubernetes e Agentes Externos

## Status
Aprovado

## Data
2026-10-08

## Contexto
Em ambientes modernos de orquestração de containers (Kubernetes, OpenShift) e em modelos DevSecOps de menor privilégio, a melhor prática arquitetural para entrega de segredos dita que a aplicação em execução **não deve possuir credenciais diretas do cofre central**.

Em vez disso, agentes e operadores especializados executados no cluster cuidam da autenticação mútua, rotação e sincronização dos segredos:
- **External Secrets Operator (ESO)**: Sincroniza segredos de dezenas de provedores (AWS Secrets Manager, Google Secret Manager, Bitwarden Secrets Manager, 1Password, etc.) para objetos nativos `Secret` do Kubernetes.
- **Secrets Store CSI Driver**: Monta segredos diretamente como volumes de arquivos na inicialização do Pod.
- **Vault Agent / Infisical Agent**: Executados como sidecars ou init-containers que renderizam segredos em arquivos no filesystem local.
- **Utilitários de inicialização CLI** (`infisical run`, `bws run`, `op run`): Injetam segredos como variáveis de ambiente na inicialização do processo da aplicação.

Se o componente de cofre exigisse conexão direta de rede com uma API de nuvem ou credencial estática, esse modelo de segurança seria inviabilizado.

## Decisão
Criar o pacote dedicado **TEC.Vault.Synced**, contendo implementações especializadas de leitura de segredos entregues por agentes externos:
1. `DirectorySecretStore` (provedor `"Directory"`):
   - Lê segredos mapeados como arquivos individuais em um diretório montado (padrão Kubernetes Secrets e CSI Driver).
   - Suporta navegação segura em symlinks atômicos criados pelo kubelet (`..data`), ignorando pastas ocultas.
2. `FileSecretStore` (provedor `"SecretsFile"`):
   - Lê segredos agregados em um único arquivo de configuração nos formatos **JSON** ou **.env** com suporte a objetos aninhados.
3. `EnvironmentSecretStore` (provedor `"EnvironmentVariables"`):
   - Lê segredos injetados diretamente no ambiente do processo a partir de um prefixo obrigatório.

Todos os stores do pacote `TEC.Vault.Synced` herdam de `SyncedSecretStoreBase` e implementam `ISecretReader` e `IVaultHealthProbe`, integrando-se nativamente ao `IConfiguration` e ao cache do ecossistema TEC.

## Consequências
### Positivas
- A aplicação opera com **zero credenciais do cofre**, minimizando drasticamente o risco de vazamento de credenciais mestre em dumps de memória ou exceções.
- Suporte imediato a qualquer cofre do mercado (inclusive Bitwarden Secrets Manager, Doppler, 1Password e AWS Secrets Manager) sem necessidade de implementar provedores nativos adicionais em código C#.
- Rotação contínua e desacoplada gerenciada inteiramente pelos operadores do cluster.

### Neutras / Negativas
- Provedores sincronizados operam em modo **apenas leitura** (`ISecretReader`), não oferecendo interfaces de mutação (`ISecretStore`) nem gestão de chaves/certificados.
