# ADR 0009: Segregação de Chaves Privadas de Certificados no HashiCorp Vault

## Status
Aprovado

## Data
2026-10-19

## Contexto
Na versão inicial do provedor HashiCorp Vault, os certificados digitais importados ou emitidos eram persistidos no motor KV v2 reunindo sob a mesma rota (`Kv.CertificatesPath`) tanto os dados públicos (`cer`, `chain`, validade) quanto o pacote binário PKCS#12 protegido contendo a chave privada correspondente.

Essa abordagem apresentou uma falha arquitetural crítica durante a revisão técnica (achado RT-01):
1. **Quebra do Princípio do Menor Privilégio**: Políticas de autorização ACL do HashiCorp Vault concedidas a serviços que necessitam apenas listar ou ler certificados públicos (ex.: para validação de assinatura ou consulta de expiração) acabavam concedendo, por tabela, permissão de leitura sobre a chave privada do certificado.
2. **Inaplicabilidade da flag `Exportable`**: Não era possível restringir o download da chave privada sem também bloquear a leitura do certificado público.

## Decisão
Segregar o armazenamento de certificados em dois caminhos independentes no motor KV v2 do HashiCorp Vault:
1. **Caminho Público dos Certificados (`Kv.CertificatesPath`)**:
   - Armazena exclusivamente o certificado público codificado em base64 (`cer`), a cadeia pública (`chain`), metadados de validade e a flag indicando se a chave é exportável (`exportable`).
   - Serviços comuns recebem política ACL do Vault de leitura apenas sobre esse caminho (`read` em `<CertificatesPath>/*`).
2. **Caminho Privado das Chaves (`Kv.CertificateKeysPath`)**:
   - Armazena em item isolado o pacote PKCS#12 com a chave privada criptografada.
   - O caminho padrão passa a ser `_certificates-keys` (configurável via `HashiCorpVaultKvOptions.CertificateKeysPath`).
   - Política ACL restritiva: apenas identidades autorizadas e auditadas que precisam efetuar o download da chave privada completa recebem permissão nesse prefixo.
3. **Mecanismo de Migração Transparente**:
   - Disponibilização do método `HashiCorpVaultCertificateStore.MigrateCertificateKeysAsync` para migrar dados legados de itens antigos de forma atômica e controlada.

## Consequências
### Positivas
- Total conformidade com o princípio de menor privilégio e RBAC granular no HashiCorp Vault.
- Eliminação do risco de vazamento de chaves privadas em operações rotineiras de inspeção de certificados.
- Compatibilidade retroativa para leitura de itens criados no formato anterior.

### Neutras / Negativas
- Serviços que necessitam do certificado com a chave privada (ex.: servidores web HTTPS com terminação TLS própria) precisam de permissão explícita concedida também ao path `_certificates-keys`.
