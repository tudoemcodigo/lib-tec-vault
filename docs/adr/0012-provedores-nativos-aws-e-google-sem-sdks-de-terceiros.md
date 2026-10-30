# ADR 0012: Provedores Nativos AWS e Google Cloud Sem SDKs de Terceiros

## Status
Aprovado

## Data
2026-10-23

## Contexto
Os SDKs oficiais da Amazon (`AWSSDK.SecretsManager`) e do Google (`Google.Cloud.SecretManager.V1`) trazem consigo dezenas de megabytes de dependências transitivas, gRPC monolítico e incompatibilidades frequentes com compilação antecipada (**Native AOT**).
Para clientes corporativos rodando em containers ultraleves (ex.: Chiseled ou Distroless), essa sobrecarga degrada o tempo de inicialização a frio (*cold start*) e amplia a superfície de ataque da cadeia de suprimentos de software.

## Decisão
Implementar os provedores **`TEC.Vault.AwsSecretsManager`** e **`TEC.Vault.GoogleSecretManager`** utilizando HTTP puro sobre `SocketsHttpHandler` e `System.Text.Json` (com serialização e parsing seguros para Native AOT):
1. **AWS Secrets Manager**:
   - Assinatura criptográfica nativa de requisições **AWS Signature Version 4 (SigV4)** usando `HMACSHA256` e `SHA256` nativos do .NET.
   - Suporte a credenciais estáticas e às variáveis de ambiente padrão da AWS, inclusive `AWS_SESSION_TOKEN` de uma credencial temporária. Não faz parte desta decisão (e não está implementado): IAM Roles for Service Accounts (IRSA, `AssumeRoleWithWebIdentity`), credenciais de task do ECS, serviço de metadados do EC2 e renovação de credenciais.
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
- A cadeia de credenciais da AWS (STS, container, IMDS) e a troca do JWT do Google são código próprio, que precisa acompanhar as mudanças das APIs.

## Revisão de 2026-10-29

A primeira versão usava um `HttpClient` próprio em cada provedor, sem as garantias do ADR 0003 (validação de endereço, teto de resposta, retentativa, tempo limite como indisponibilidade), aceitava credencial em texto na configuração e, na AWS, lia as chaves uma vez, sem renovação. Decisão revista:

1. **Mesmo transporte dos demais provedores HTTP**: `VaultHttpClient` (endereço validado por `VaultEndpoint.Validate`, `MaxResponseBytes`, tempo limite também na leitura do corpo, retentativa idempotente, redirecionamento desligado) e `VaultTokenSource` (cache, renovação antes de expirar, login único, intervalo de falha, teto de duração). Na AWS, o tipo do erro (`__type` em HTTP 400) vira o status equivalente por `VaultHttpClient.ErrorStatusMapper`, e as gravações levam `ClientRequestToken` para poderem ser repetidas.
2. **AWS com cadeia de credenciais renovável**: web identity (IRSA, `AssumeRoleWithWebIdentity` relendo o arquivo do token), credenciais de container (ECS e EKS Pod Identity), IMDSv2 e, como último recurso, chaves estáticas.
3. **Google**: `token_uri` da Service Account conferido (HTTPS e host permitido) antes de o JWT sair do processo; Metadata Server sem falhas engolidas e conferido pelo `Metadata-Flavor`.
4. **Credencial em texto recusada na configuração** (`SecretAccessKey`, `SessionToken`, `AccessToken`), como nos demais provedores.
5. **Nada de sucesso sem aplicar**: tags (AWS `TagResource`/`UntagResource`, Google labels por `PATCH`) aplicadas de verdade ou recusadas com `VAULT_ENTRADA_INVALIDA`; listagem acima de `MaxListItems` falha com `VAULT_LISTAGEM_ACIMA_DO_LIMITE`.

## Atualização de 2026-10-29

O texto original da Decisão e das Consequências ficou mantido como registro, mas dois trechos não valem mais:

- O item 1 da Decisão diz que IRSA, credenciais de task do ECS e o serviço de metadados do EC2 não estão implementados. Os três existem hoje em `AwsCredentialSource`, com renovação, como descreve o item 2 da revisão acima.
- As Consequências citam throughput HTTP/2. O `VaultHttpClient` não define a versão do protocolo, então as requisições usam o padrão do `HttpClient` (HTTP/1.1).
