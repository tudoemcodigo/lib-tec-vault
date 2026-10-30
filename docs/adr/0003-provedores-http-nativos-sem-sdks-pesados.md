# ADR 0003: Provedores HTTP Nativos sem SDKs Pesados de Terceiros

## Status
Aprovado

## Data
2026-10-08

## Contexto
SDKs de terceiros para HashiCorp Vault (ex.: `VaultSharp`) ou Infisical frequentemente trazem consigo:
1. Árvores extensas de dependências transitivas com versões divergentes de `Newtonsoft.Json` ou bibliotecas legadas.
2. Incompatibilidade com compilação antecipada (**Native AOT**) e *trimming*, gerando avisos de reflexão não segura ou quebras em tempo de execução.
3. Gerenciamento interno de conexões HTTP inadequado para microsserviços de alta escala (ex.: esgotamento de sockets (*socket exhaustion*), ausência de reciclagem de DNS, ausência de retentativas idempotentes estritas).
4. Sobrecarga desnecessária de memória e tamanho do binário.

## Decisão
Implementar os clientes de rede para **HashiCorp Vault / OpenBao** e **Infisical** de forma nativa e sem SDKs de terceiros:
- Uso direto do pipeline HTTP padrão do runtime .NET com `SocketsHttpHandler` de ciclo de vida longo (`PooledConnectionLifetime = 5 minutos`) e desativação de redirecionamentos automáticos por segurança. O AWS e o Google (ADR 0012) usam um `HttpClient` próprio, com 15 minutos.
- Serialização estrita e de alta performance baseada em `System.Text.Json` com geradores de código e contratos imutáveis, garantindo 100% de compatibilidade com **Native AOT**.
- Implementação de clientes dedicados (`VaultHttpClient`) com proteção contra respostas gigantescas via teto rígido (`MaxResponseBytes`), evitando exaustão de memória em respostas maliciosas ou anômalas.
- Autenticação nativa implementada do zero: Kubernetes Auth, JWT, AppRole, Token e Universal Auth.

## Consequências
### Positivas
- Binários enxutos, inicialização ultrarrápida e compatibilidade total com Native AOT e containers mínimos (ex.: Chiseled Ubuntu / Distroless).
- Redução drástica da superfície de ataque e eliminação de alertas de vulnerabilidades transitivas na cadeia de suprimentos (Supply Chain Security).
- Controle absoluto sobre timeouts, retentativas e sanitização de logs de chamadas HTTP.

### Neutras / Negativas
- Exige manutenção própria das integrações com as APIs REST do HashiCorp Vault e Infisical conforme essas plataformas evoluem suas versões de API (por exemplo, KV v2 vs KV v1).
