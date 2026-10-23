# ADR 0008: Criptografia Envelope no Cliente com Chaves Mestras no Cofre

## Status
Aprovado

## Data
2026-10-08

## Contexto
Aplicações corporativas que processam volumes expressivos de dados sensíveis (arquivos, payloads de cartão, dados pessoais LGPD/GDPR) enfrentam um dilema arquitetural ao proteger esses dados:
1. **Cifrar tudo no cofre (Remote Cryptography)**: Enviar grandes volumes de dados para a API do cofre cifrar via HTTP/gRPC gera sobrecarga brutal de largura de banda, latência inaceitável e atinge limites de tamanho de payload (payload limit).
2. **Cifrar tudo localmente com chave simétrica no código**: Guardar a chave de cifragem no `appsettings` ou memória local expõe a chave mestra em caso de comprometimento do servidor ou vazamento de imagem.

## Decisão
Implementar o padrão de **Criptografia Envelope** (*Envelope Encryption*) através da extensão `EncryptEnvelopeAsync` e `DecryptEnvelopeAsync` em `IKeyCryptography`:
1. **Geração de Chave de Dados Efêmera (DEK - Data Encryption Key)**:
   - Para cada operação de cifragem, a aplicação gera localmente uma chave simétrica efêmera de 256 bits via gerador criptográfico seguro (`RandomNumberGenerator`).
2. **Cifragem Local de Alta Performance (AES-256-GCM)**:
   - Os dados volumosos são cifrados localmente no processo utilizando AES-GCM autenticado (com tag de integridade e nonce criptográfico), garantindo confidencialidade e autenticidade com throughput de gigabits por segundo e zero tráfego de rede.
3. **Proteção da DEK no Cofre (Key Wrapping)**:
   - Apenas a pequena chave efêmera de dados (32 bytes) é enviada ao cofre remoto para ser cifrada (*wrapped*) pela Chave Mestra de Cifragem (KEK - Key Encryption Key) residente no cofre (HSM ou KMS do provedor).
4. **Armazenamento Seguro do Pacote Envelope**:
   - O payload final armazenado contém os dados cifrados acompanhados apenas da DEK cifrada (*wrapped DEK*) e metadados de algoritmo.
   - Para decifrar, a aplicação envia a DEK cifrada para o cofre desempacotar (*unwrap*), decifra os dados localmente com AES-GCM e descarta a DEK da memória.

## Consequências
### Positivas
- A Chave Mestra (KEK) **nunca sai do cofre** de segurança nem transita pela rede.
- Cifragem e decifragem de grandes volumes de dados com velocidade máxima nativa do processador (instruções AES-NI).
- Rotação simples: rotacionar a KEK no cofre não exige recifrar todos os terabytes de dados históricos armazenados.

### Neutras / Negativas
- Cada documento ou registro requer guardar a chave de dados cifrada junto ao payload.
