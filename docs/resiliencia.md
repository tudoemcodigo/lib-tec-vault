[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › 🔁 Resiliência

# 🔁 Resiliência

> Retentativa nas falhas passageiras e circuit breaker nas quedas longas: com o cofre fora do ar, a aplicação falha em milissegundos em vez de esperar tempo limite e retentativas em cada chamada.

## 📑 Sumário

- [🎯 Visão geral](#-visão-geral)
- [🚀 Uso](#-uso)
- [⚙️ Opções](#️-opções)
- [📈 Observabilidade](#-observabilidade)
- [❓ Perguntas frequentes](#-perguntas-frequentes)

---

## 🎯 Visão geral

São duas camadas, uma dentro da outra:

| Camada | Onde | O que faz |
|---|---|---|
| **Retentativa** | Dentro de cada chamada ao cofre (Azure SDK; `VaultHttpClient` nos provedores HTTP) | Repete falhas passageiras com backoff exponencial e jitter, respeitando `Retry-After`. Nos provedores HTTP, só repete operações idempotentes |
| **Circuit breaker** | Em volta da chamada inteira, já com as retentativas (`VaultProviderBase`, [Polly](https://www.pollydocs.org/) `Polly.Core`) | Conta as chamadas que terminaram em `VAULT_INDISPONIVEL` ou `VAULT_LIMITE_EXCEDIDO`. Com falhas demais na janela, **abre**: as chamadas seguintes devolvem `VAULT_CIRCUITO_ABERTO` na hora, sem consultar o cofre |

Ciclo do circuito:

```
Fechado ──(falhas ≥ FailureRatio, com ≥ MinimumThroughput chamadas em SamplingDuration)──▶ Aberto
Aberto ──(passou BreakDuration)──▶ Meio-aberto: uma chamada de teste vai ao cofre
Meio-aberto ──(sucesso)──▶ Fechado        Meio-aberto ──(falha)──▶ Aberto de novo
```

- **Um circuito por cofre**, compartilhado pelos stores que falam com ele: no Azure Key Vault, segredos, chaves e certificados do mesmo cofre abrem e fecham juntos; no HashiCorp Vault, os stores do mesmo cliente.
- **Não abrem o circuito:** item não encontrado, acesso negado, autenticação, entrada inválida, conflito, falha não classificada (`VAULT_FALHA`) e cancelamento. Esses erros não indicam cofre fora do ar.
- **Chamada de teste (meia-abertura):** só uma resposta do cofre a fecha (sucesso ou erro do item, como não encontrado). Se ela for cancelada ou terminar em `VAULT_FALHA`, conta como falha e o circuito volta a abrir. Enquanto a chamada de teste não termina, as demais continuam recebendo `VAULT_CIRCUITO_ABERTO`.
- **Provedores locais** (em memória e Synced) não têm circuit breaker.
- **Health check:** com o circuito aberto, a verificação responde na hora como não saudável (`VAULT_CIRCUITO_ABERTO` no log, evento 2007) e tira a instância do balanceamento sem pressionar o cofre.
- **`IConfiguration`:** a recarga periódica com o circuito aberto falha rápido e mantém os valores anteriores (evento 2101).

## 🚀 Uso

Nada a fazer: o circuit breaker já vem ligado nos provedores de rede (Azure Key Vault, HashiCorp Vault, Infisical). Para ajustar:

```csharp
builder.Services.AddTecVault(vault => vault.UseAzureKeyVault(o =>
{
    o.VaultUri = new Uri("https://kv-minha-api.vault.azure.net/");
    o.CircuitBreaker.BreakDuration = TimeSpan.FromSeconds(15);
}));

// Provedores HTTP: em Http.CircuitBreaker
builder.Services.AddTecVault(vault => vault.UseHashiCorpVault(o =>
{
    o.Address = new Uri("https://vault.interno:8200");
    o.Http.CircuitBreaker.MinimumThroughput = 20;
}));
```

Pela configuração, na subseção `CircuitBreaker` do provedor:

```json
{
  "Vault": {
    "Provider": "AzureKeyVault",
    "AzureKeyVault": {
      "VaultUri": "https://kv-minha-api.vault.azure.net/",
      "CircuitBreaker": { "FailureRatio": 0.5, "MinimumThroughput": 10, "SamplingDuration": "00:00:30", "BreakDuration": "00:00:30" }
    }
  }
}
```

Tratando o erro:

```csharp
var result = await secrets.GetSecretAsync("db-senha", cancellationToken: ct);
if (result.Error?.Code is VaultErrors.CircuitOpenCode or VaultErrors.UnavailableCode)
{
    // Cofre fora do ar: use um valor em cache, degrade a funcionalidade ou devolva 503
}
```

## ⚙️ Opções

`VaultCircuitBreakerOptions`, em `AzureKeyVaultOptions.CircuitBreaker` e em `Http.CircuitBreaker` (`HashiCorpVaultOptions`, `InfisicalOptions`). Na configuração: `Vault:<Provedor>:CircuitBreaker:<Chave>`.

| Opção | Tipo | Padrão | Faixa | O que faz |
|---|---|---|---|---|
| `Enabled` | `bool` | `true` | — | Liga o circuit breaker |
| `FailureRatio` | `double` | `0.5` | > 0 e ≤ 1 | Proporção de falhas que abre o circuito |
| `MinimumThroughput` | `int` | `10` | 2 a 10.000 | Mínimo de chamadas na janela antes de avaliar a proporção |
| `SamplingDuration` | `TimeSpan` | `30 s` | 0,5 s a 1 h | Janela de amostragem |
| `BreakDuration` | `TimeSpan` | `30 s` | 0,5 s a 1 h | Tempo aberto antes da chamada de teste |

Valor fora da faixa, ou chave desconhecida na subseção, falha na subida com `InvalidOperationException` citando o caminho da chave. O relógio é o `TimeProvider` das opções do provedor.

Para escrever um provedor novo com circuit breaker: crie um `VaultCircuitBreaker` por cofre com `VaultCircuitBreaker.Create(...)` e passe-o ao construtor de `VaultProviderBase`/`VaultHttpProviderBase` (veja [🧱 Novo provedor](novo-provedor.md)).

## 📈 Observabilidade

| Sinal | Nome | Detalhe |
|---|---|---|
| Métrica | `vault.circuit.state_changes` | Contador com `vault.provider` e `vault.circuit.state` = `open`, `half_open` ou `closed` |
| Métrica | `vault.operation.duration` | Chamadas recusadas aparecem com `error.type` = `VAULT_CIRCUITO_ABERTO` (duração próxima de zero) |
| Log 2011 | Warning | Circuito aberto (com a duração da pausa) |
| Log 2012 | Information | Circuito meio-aberto (chamada de teste) |
| Log 2013 | Information | Circuito fechado (cofre voltou) |
| Log 2014 | Debug | Chamada recusada com o circuito aberto. Fica em Debug para não inundar o log durante a queda |

## ❓ Perguntas frequentes

<details>
<summary>Por que o circuit breaker fica por fora das retentativas, e não o contrário?</summary>

Assim cada chamada da aplicação conta uma vez: uma leitura que esgotou 3 retentativas é **uma** falha. Com o circuito por dentro, cada retentativa contaria e o circuito abriria com poucas chamadas reais.
</details>

<details>
<summary>Uma escrita pode ser repetida por causa do circuit breaker?</summary>

Não. O circuit breaker nunca repete nada: só decide se a chamada vai ao cofre. A regra de retentativa (só operações idempotentes nos provedores HTTP) continua a mesma.
</details>

<details>
<summary>Por que <code>VAULT_LIMITE_EXCEDIDO</code> abre o circuito?</summary>

Com o cofre limitando requisições, insistir piora o problema (o limite costuma valer para o cofre inteiro, não só para esta instância). A pausa dá fôlego ao cofre e às outras aplicações que o usam.
</details>

---

[⬆️ Voltar ao topo](#-resiliência)
