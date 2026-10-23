# ADR 0001: API Unificada de Cofres Segregada por Responsabilidade

## Status
Aprovado

## Data
2026-10-08

## Contexto
Em arquiteturas de microsserviços distribuídos corporativos, cada ambiente ou provedor de nuvem frequentemente utiliza um mecanismo de cofre diferente:
- Ambientes em Azure utilizam Azure Key Vault.
- Ambientes multicloud ou on-premises utilizam HashiCorp Vault ou OpenBao.
- Ambientes com foco em Developer Experience ou equipes ágeis utilizam Infisical ou Bitwarden.
- Ambientes de testes locais ou CI utilizam simulações em memória.

Se cada microsserviço depender diretamente do SDK específico do provedor (como `Azure.Security.KeyVault.Secrets`, `VaultSharp` ou SDKs proprietários), surgem problemas graves:
1. **Acoplamento tecnológico**: A migração de nuvem ou troca de fornecedor exige reescrever clientes, injeção de dependências e tratamento de erros.
2. **Violação do Princípio da Segregação de Interfaces (ISP)**: Uma classe de serviço que necessita apenas ler um segredo (`ISecretReader`) recebe um cliente monolítico que também permite deletar chaves criptográficas ou gerar certificados.
3. **Disparidade de comportamento**: Retentativas, logs, telemetria e tratamento de exceções diferem entre cada biblioteca.

## Decisão
Criar o componente **TEC.Vault** com uma arquitetura de API unificada, fortemente tipada e segregada em contratos de granularidade fina:
- **Segredos:**
  - `ISecretReader`: apenas leitura de segredos (`GetSecretAsync`, `ListSecretNamesAsync`, `ListSecretVersionsAsync`).
  - `ISecretStore`: gravação, rotação e exclusão (`SetSecretAsync`, `DeleteSecretAsync`, `RotateSecretAsync`).
  - `ISecretRecycleBin` e `ISecretBackup`: operações avançadas de recuperação e backup.
- **Chaves Criptográficas:**
  - `IKeyReader`: leitura de metadados e chave pública.
  - `IKeyStore`: criação, rotação e deleção de chaves mestras.
  - `IKeyCryptography`: operações criptográficas delegadas ao cofre (cifra, decifra, *wrap*, *unwrap*, assinatura, envelope).
- **Certificados Digitais:**
  - `ICertificateReader`: leitura e download de cadeias públicas.
  - `ICertificateStore`: criação, importação (PFX/PEM) e emissão via CSR/PKI.
- **Saúde do Cofre:**
  - `IVaultHealthProbe`: verificação operacional leve sem leitura de valores confidenciais.

Todos os provedores suportados implementam rigorosamente esses contratos sobre uma classe base padronizada (`VaultProviderBase`).

## Consequências
### Positivas
- Código de negócio desacoplado de qualquer nuvem ou infraestrutura de cofre.
- Princípio de Menor Privilégio garantido via injeção de dependência (ex.: serviços injetam apenas `ISecretReader`).
- Troca transparente de cofre via arquivo de configuração (`appsettings.json`), sem recompilação.
- Facilidade imediata de testes com o provedor `InMemory`.

### Neutras / Negativas
- Necessidade de mapear particularidades de cada provedor subjacente para um modelo conceitual comum.
- Funcionalidades ultra-específicas de um cofre que não façam sentido no padrão da plataforma não são expostas nas interfaces universais.
