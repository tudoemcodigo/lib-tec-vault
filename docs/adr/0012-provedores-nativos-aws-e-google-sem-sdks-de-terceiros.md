# ADR 0012: Provedores Nativos AWS e Google Cloud Sem SDKs de Terceiros

## Status
Aprovado

## Data
2026-10-23

## Contexto
Os SDKs oficiais da Amazon (`AWSSDK.SecretsManager`) e do Google (`Google.Cloud.SecretManager.V1`) trazem consigo dezenas de megabytes de dependências transitivas, gRPC monolítico e incompatibilidades frequentes com compilação antecipada (**Native AOT**) no .NET 8 e .NET 10.
Para clientes corporativos rodando em containers ultraleves (ex.: Chiseled ou Distroless), essa sobrecarga degrada o tempo de inicialização a frio (*cold start*) e amplia a superfície de ataque da cadeia de suprimentos de software.

## Decisão
Implementar os provedores **`TEC.Vault.AwsSecretsManager`** e **`TEC.Vault.GoogleSecretManager`** utilizando HTTP puro sobre `SocketsHttpHandler` e `System.Text.Json` (com serialização e parsing seguros para Native AOT):
1. **AWS Secrets Manager**:
   - Assinatura criptográfica nativa de requisições **AWS Signature Version 4 (SigV4)** usando `HMACSHA256` e `SHA256` nativos do .NET.
   - Suporte a credenciais estáticas, variáveis de ambiente padrão AWS e IAM Roles for Service Accounts (IRSA/STS).
2. **Google Cloud Secret Manager**:
   - Integração com a API REST v1 do Google Secret Manager.
   - Suporte nativo ao Servidor de Metadados do Google Cloud (GKE, Cloud Run, Compute Engine) sem necessidade de credenciais manuais.
   - Suporte a Service Account JSON com geração e assinatura de JWT RSA-SHA256 diretamente no processo.

## Consequências
### Positivas
- Binários extremamente leves e zero dependências pesadas de terceiros.
- Totalmente compatível com Native AOT (zero warnings de trimming/reflection).
- Inicialização praticamente instantânea e desempenho máximo de throughput HTTP/2.

### Neutras / Negativas
- Exige governança própria das chamadas REST das APIs de segredos da AWS e do Google Cloud.
