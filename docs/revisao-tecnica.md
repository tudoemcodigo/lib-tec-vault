[🏠 TEC.Vault](../README.md) › [📚 Documentação](README.md) › 🔎 Revisão técnica

# 🔎 Revisão técnica

> Revisão de segurança, correção e organização dos seis pacotes do TEC.Vault, feita no código: cada achado cita `arquivo:linha` conferido no fonte. Não altera código; aponta problemas, impacto e correção sugerida. As correções aplicadas estão em [Status dos achados](#-status-dos-achados).

## 📑 Sumário

- [🎯 Escopo](#-escopo)
- [🧪 Build e testes](#-build-e-testes)
- [📊 Resumo dos achados](#-resumo-dos-achados)
- [🔍 Achados](#-achados)
  - [RT-01 — Chave privada de certificado no mesmo item do KV que a parte pública](#rt-01--chave-privada-de-certificado-no-mesmo-item-do-kv-que-a-parte-pública)
  - [RT-02 — 5xx/429 no login viram falha de autenticação](#rt-02--5xx429-no-login-viram-falha-de-autenticação)
  - [RT-03 — Login com falha não é compartilhado: comboio no semáforo](#rt-03--login-com-falha-não-é-compartilhado-comboio-no-semáforo)
  - [RT-04 — 403 de política força um novo login a cada chamada (HashiCorp)](#rt-04--403-de-política-força-um-novo-login-a-cada-chamada-hashicorp)
  - [RT-05 — Cadeia do certificado descartada no HashiCorp Vault](#rt-05--cadeia-do-certificado-descartada-no-hashicorp-vault)
  - [RT-06 a RT-14 — Baixa](#rt-06--token-com-vida-curta-gera-login-a-cada-chamada)
  - [RT-15 a RT-17 — Info](#rt-15--health-check-de-readiness-derruba-todas-as-instâncias-na-queda-do-cofre)
- [✅ Status dos achados](#-status-dos-achados)
- [🛠️ Correções aplicadas — 2026-10-19](#️-correções-aplicadas--2026-10-19)
- [✨ Melhorias sugeridas](#-melhorias-sugeridas)
- [📝 Ajustes na documentação](#-ajustes-na-documentação)

---

## 🎯 Escopo

| Item | Valor |
|---|---|
| Data | 2026-10-19 |
| Commit analisado | `2ac4bea Circuit breaker por cofre com Polly.Core (0.1.0) (#5)` |
| Pacotes | `TEC.Vault`, `TEC.Vault.AzureKeyVault`, `TEC.Vault.HashiCorpVault`, `TEC.Vault.Infisical`, `TEC.Vault.Synced`, `TEC.Vault.InMemory` |
| Também lidos | `TEC.Vault.Tests` (categorias, lacunas), `samples/`, `.github/scripts/*.sh`, `.github/workflows/*.yml`, `build/`, `Directory.*.props`, `docs/` |
| Foco | Abstrações de segredos/chaves/certificados; provedores; cache; health check; configuração por `appsettings`; certificados; chaves; resiliência (retentativa e circuit breaker); erros; observabilidade; scripts |
| Fora do escopo | Publicação Native AOT de um app real (só o build com `IsAotCompatible` e avisos como erro); testes de integração e de carga |

O código já passou por endurecimento visível (testes `SecurityTests`, `HardeningRegressionTests`, `ReviewFixesTests`): validação de endereço e de nomes contra *path traversal*, redirecionamento desligado, buffers zerados, `ToString` mascarado, nada de nome de item em métricas e traces, segredos de login recusados em texto na configuração, provedor em memória e credencial de desenvolvedor travados fora de Development. Os achados abaixo são o que sobrou.

---

## 🧪 Build e testes

| Passo | Comando | Resultado |
|---|---|---|
| Build com o feed `tec-interno` | `dotnet build TEC.Vault.slnx -c Release` | **Falhou na restauração** (`NU1301`, 401 no GitHub Packages): a máquina da revisão não tem credencial do feed. Não é defeito do código |
| Build no modo local | `dotnet build TEC.Vault.slnx -c Debug -p:TecUseLocalProjects=true --no-incremental` | ✅ **0 avisos, 0 erros** (pacotes com `TreatWarningsAsErrors`, analisadores de segurança e `IsAotCompatible=true`: nenhum aviso de AOT/trimming) |
| Testes unitários net8.0 | `dotnet run -c Debug --no-build -f net8.0 -- --treenode-filter '/*/*/*/*[Category!=Integracao]'` | ✅ **614 aprovados**, 0 falhas, 0 ignorados |
| Testes unitários net10.0 | idem, `-f net10.0` | ✅ **614 aprovados**, 0 falhas, 0 ignorados |

> [!NOTE]
> Uma primeira execução com `--no-build` sobre o `bin/Release` antigo (de 8/10) rodou 595 testes: era binário desatualizado e foi descartada. Os números acima são do build feito na revisão.

---

## 📊 Resumo dos achados

| Severidade | Quantidade |
|---|:-:|
| Crítica | 0 |
| Alta | 0 |
| Média | 5 |
| Baixa | 9 |
| Info | 3 |

| ID | Severidade | Categoria | Local | Resumo |
|---|---|---|---|---|
| RT-01 | Média | Segurança | `TEC.Vault.HashiCorpVault/HashiCorpVaultCertificateStore.cs:317-327` | PKCS#12 sem senha no mesmo item do KV que a parte pública: toda leitura de metadados exige (e trafega) a chave privada; `Exportable=false` não é aplicável pela política do Vault |
| RT-02 | Média | Bug / resiliência | `TEC.Vault.HashiCorpVault/Internal/HashiCorpVaultClient.cs:206-207`, `TEC.Vault.Infisical/InfisicalSecretStore.cs:267-268` | 5xx/429 no login (após as retentativas) viram `VAULT_AUTENTICACAO_FALHOU`; o circuit breaker não conta e o alerta aponta para a identidade |
| RT-03 | Média | Concorrência | `TEC.Vault/Providers/Http/VaultTokenSource.cs:47-67` | Falha de login não é compartilhada: cada chamada enfileirada no semáforo refaz o login inteiro, em série |
| RT-04 | Média | Segurança / DoS | `TEC.Vault/Providers/Http/VaultHttpClient.cs:197-206` | No HashiCorp, todo 403 (inclusive falta de política) descarta o token compartilhado e faz novo login: tempestade de logins e tokens órfãos no Vault |
| RT-05 | Média | Bug / funcional | `TEC.Vault.HashiCorpVault/HashiCorpVaultCertificateStore.cs:100-105, 317` | Intermediárias da importação e `ca_chain` do PKI são descartadas: só a folha é guardada |
| RT-06 | Baixa | Bug | `TEC.Vault/Providers/Http/VaultTokenSource.cs:59-64` | Token com vida menor que ~11 s nasce "vencido": login a cada requisição |
| RT-07 | Baixa | Implementação | `TEC.Vault.HashiCorpVault/Internal/HashiCorpVaultClient.cs:172-216` | Sem `renew-self`: cada expiração é um login novo (consome usos do `secret_id` do AppRole) |
| RT-08 | Baixa | Validação | `TEC.Vault/Configuration/VaultConfiguration.cs:44, 196` | `ReloadInterval` sem teto: acima de 49,7 dias o `Timer` lança na subida; `"30"` vira 30 dias |
| RT-09 | Baixa | Organização / recursos | `TEC.Vault/Configuration/VaultConfiguration.cs:482` | A fonte de `IConfiguration` cria um segundo cliente (login, token e circuito próprios) que nunca é descartado |
| RT-10 | Baixa | Dispose | `TEC.Vault.HashiCorpVault/HashiCorpVaultExtensions.cs:41-42, 132-135` | Cliente criado no registro e descartado por qualquer container montado com a mesma coleção |
| RT-11 | Baixa | Segurança | `TEC.Vault.HashiCorpVault/HashiCorpVaultKeyStore.cs:190-198` | `deletion_allowed = true` fica ligado se o `DELETE` falhar |
| RT-12 | Baixa | DoS / consistência | `TEC.Vault.Infisical/InfisicalSecretStore.cs:289-292, 317-328` | Listagem sem `MaxListItems`; cada nome não encontrado lista a pasta inteira |
| RT-13 | Baixa | Observabilidade | `TEC.Vault/Providers/Http/VaultTokenSource.cs:29` | `record Entry(string Value, ...)` imprime o token em `ToString` e no depurador |
| RT-14 | Baixa | Testes | `TEC.Vault.Tests/` | Sem testes para RT-02, RT-03, RT-04 e RT-05 |
| RT-15 | Info | Design | `TEC.Vault/HealthChecks/VaultHealthCheck.cs:22-23, 90` | Padrão `Unhealthy` + tag `ready`: queda do cofre tira todas as instâncias do balanceamento |
| RT-16 | Info | Organização | `Directory.Build.props:12-14` | `InternalsVisibleTo("TEC.Vault.LoadGenerator")` em todos os pacotes publicados (não assinados) |
| RT-17 | Info | Scripts | `.github/scripts/vault-dev.sh:11, 14-17` | Espera do Vault sem falha explícita; token root na linha de comando do `curl` |

---

## 🔍 Achados

### RT-01 — Chave privada de certificado no mesmo item do KV que a parte pública

**Severidade:** Média · **Categoria:** Segurança · **Provedor:** HashiCorp Vault

**Problema.** Cada versão de certificado é **um** item do KV com `cer`, `pkcs12` (PKCS#12 com a chave privada, exportado **sem senha**) e `exportable`. O KV devolve o item inteiro em toda leitura, então qualquer operação que só precisa da parte pública lê também a chave privada.

**Evidência.**

```csharp
// HashiCorpVaultCertificateStore.cs:317-327 — StoreAsync
var pkcs12 = certificate.Export(X509ContentType.Pkcs12);        // sem senha
var pkcs12Text = Convert.ToBase64String(pkcs12);
...
var written = await Kv.WriteAsync(target, new Dictionary<string, string>
{
    [CerField] = Convert.ToBase64String(cer),
    [Pkcs12Field] = pkcs12Text,
    [ExportableField] = exportable ? "true" : "false"
}, ct)
```

- `GetCertificateAsync` (`:133-139`), `ListCertificatesAsync` (`:173-178`, via `PropertiesAsync` em `:354-361`), `ListCertificateVersionsAsync` (`:197-200`) e `RecoverDeletedCertificateAsync` (`:284-289`) leem o item completo e só depois zeram o PKCS#12 decodificado; a cópia em Base64 (`string`, no `Dictionary` de `KvFolder.ReadAsync`) não pode ser zerada.
- `DownloadCertificateAsync` (`:154-158`) decide `Exportable` só na biblioteca.

**Impacto.** A recomendação da própria documentação ("restrinja `_certificates/*` a quem precisa da chave privada", `provedor-hashicorp-vault.md:357`) é inaplicável: a aplicação que só lista ou lê certificados precisa de `read` em `secret/data/<pasta>/_certificates/*`, e com isso o token dela lê a chave privada direto pela API (`vault kv get`), inclusive de certificados com `Exportable = false`. Um `ListCertificatesAsync` com 200 certificados traz 200 chaves privadas pela rede e para a memória gerenciada.

**Sugestão.** Separar o material privado do público, para que a política do Vault, e não a biblioteca, aplique o `Exportable`:

```text
secret/data/minha-api/_certificates/<nome>          → cer, exportable          (read para quem lê certificados)
secret/data/minha-api/_certificates-keys/<nome>     → pkcs12                   (read só para quem baixa)
```

Alternativa mais forte: cifrar o PKCS#12 em envelope com uma chave do Transit antes de gravar (`KeyCryptographyExtensions.EncryptEnvelopeAsync`); baixar passa a exigir `update` em `transit/decrypt/<chave>`, auditável e revogável no Vault. Em ambos os casos, migrar itens existentes na leitura (se `pkcs12` estiver no item público, mover).

---

### RT-02 — 5xx/429 no login viram falha de autenticação

**Severidade:** Média · **Categoria:** Bug / resiliência · **Provedores:** HashiCorp Vault, Infisical

**Problema.** O login é enviado com retentativa (`idempotent: true`). Esgotadas as tentativas, `VaultHttpClient.SendAsync` **devolve** a resposta 5xx/429, e o login a converte em `VaultLoginException`, que a base mapeia para `VAULT_AUTENTICACAO_FALHOU`.

**Evidência.**

```csharp
// HashiCorpVaultClient.cs:205-207 (igual em InfisicalSecretStore.cs:262-268)
using var response = await _login.SendAsync(() => Request(HttpMethod.Post, path, body), idempotent: true, ct)...;
if (!response.IsSuccessStatusCode)
    throw new VaultLoginException($"o Vault recusou o login ({(int)response.StatusCode})");

// VaultHttpProviderBase.cs:42
VaultLoginException login => new VaultFailure(VaultErrors.AuthenticationFailed(), "login: " + login.Message),
```

**Impacto.** Cenário: o Vault é selado (503) ou o endpoint de login limita (429) no momento em que o token vence. Todas as chamadas passam a falhar com `VAULT_AUTENTICACAO_FALHOU` (tipo `ExternalService`, HTTP 502): o alerta vai para "identidade/credencial", e o circuit breaker, que só conta `VAULT_INDISPONIVEL` e `VAULT_LIMITE_EXCEDIDO` (`VaultCircuitBreaker.cs:107`), **não abre**: cada chamada repete o login com retentativas. Diverge da tabela da documentação ("5xx, inclusive 503 de Vault selado → `VAULT_INDISPONIVEL`").

**Sugestão.** Só 400/401/403 são "login recusado"; o resto mantém o status real:

```csharp
if (!response.IsSuccessStatusCode)
{
    var status = response.StatusCode;
    if (status is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        throw new VaultLoginException($"o Vault recusou o login ({(int)status})");
    VaultHttpClient.EnsureSuccess(response);   // 429 → Throttled, 5xx/408 → Unavailable (conta no circuito)
}
```

Melhor ainda: um método comum em `VaultHttpProviderBase`/`VaultHttpClient` (ex.: `EnsureLoginSuccess`) para que provedores novos herdem a regra.

---

### RT-03 — Login com falha não é compartilhado: comboio no semáforo

**Severidade:** Média · **Categoria:** Concorrência · **Local:** núcleo (HashiCorp e Infisical)

**Problema.** `VaultTokenSource` garante um único login **bem-sucedido** para chamadas simultâneas, mas uma falha não é compartilhada: quem estava esperando no `SemaphoreSlim` encontra `_current == null` e faz **outro** login completo (com as retentativas do `VaultHttpClient`), um de cada vez.

**Evidência.**

```csharp
// VaultTokenSource.cs:47-54
await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
try
{
    if (Valid(_current) is { } other)
        return other;
    var now = _time.GetUtcNow();
    var token = await _login(cancellationToken).ConfigureAwait(false);   // falhou? o próximo da fila tenta de novo
```

**Impacto.** Com o login fora do ar e 100 requisições simultâneas, cada login leva até `NetworkTimeout × (MaxRetries + 1)` mais o backoff (padrão: 30 s × 4 + ~5,6 s). As requisições ficam em fila, em série, até o próprio cancelamento; threads e conexões de entrada da aplicação se acumulam, e o endpoint de login recebe uma carga contínua. O circuit breaker não ajuda: as chamadas já estão dentro dele.

**Sugestão.** Compartilhar o desfecho do login em andamento (sucesso **ou** falha) e guardar a falha por um intervalo curto:

```csharp
private Task<Entry>? _pending;          // login em andamento, compartilhado
private (Exception Error, long At)? _lastFailure;

// Dentro do gate: se _lastFailure tem menos de N segundos (ex.: 2-5 s), relança sem novo login.
// Fora do gate: quem chega enquanto _pending existe aguarda a mesma Task (WaitAsync(ct)), como o CachingSecretReader.
```

---

### RT-04 — 403 de política força um novo login a cada chamada (HashiCorp)

**Severidade:** Média · **Categoria:** Segurança / DoS · **Provedor:** HashiCorp Vault

**Problema.** O Vault responde 403 tanto para token inválido quanto para **falta de capacidade na política**. Com `reauthenticateOnForbidden: true`, todo 403 descarta o token compartilhado (`Invalidate`) e faz um novo login antes de devolver `VAULT_ACESSO_NEGADO`.

**Evidência.**

```csharp
// VaultHttpClient.cs:198-205
if (token is not null && !reauthenticated &&
    (response.StatusCode == HttpStatusCode.Unauthorized || (_reauthenticateOnForbidden && response.StatusCode == HttpStatusCode.Forbidden)))
{
    response.Dispose();
    _tokens!.Invalidate(token);   // derruba o token de TODAS as chamadas
    ...

// HashiCorpVaultClient.cs:70-71
_http = new VaultHttpClient(address, options.Http, _tokens, ..., reauthenticateOnForbidden: true);
```

**Impacto.** Uma aplicação que consulta um caminho fora da política (erro de configuração, ou o fallback de nome sem diferenciar maiúsculas em `KvFolder.ResolveAsync:142`, que faz `LIST` e exige `list` em `metadata/`) gera **um login por chamada**. No método Kubernetes/JWT/AppRole cada login cria um token novo no Vault, que vive até o TTL: em carga, milhares de tokens/leases órfãos (pressão no storage do Vault, auditoria inflada). E o token bom das demais chamadas é descartado, que também refazem login (somando com RT-03).

**Sugestão.** Antes de refazer o login em 403, confirmar que o token é o problema, com uma chamada barata e limitada no tempo:

```csharp
// 403 → GET v1/auth/token/lookup-self com o mesmo token
//   200 → token válido: é política; devolve 403 sem login (e sem Invalidate)
//   403 → token inválido: Invalidate + novo login (comportamento atual)
// Guardar o resultado do lookup por alguns segundos por token evita repetir a checagem em rajadas de 403.
```

Alternativa mínima: limitar a reautenticação por 403 a uma vez a cada N segundos por token.

---

### RT-05 — Cadeia do certificado descartada no HashiCorp Vault

**Severidade:** Média · **Categoria:** Bug / funcional · **Provedor:** HashiCorp Vault

**Problema.** O armazenamento usa `X509Certificate2.Export(X509ContentType.Pkcs12)`, que exporta **só o certificado da instância** (e a chave). Na importação, `LoadPkcs12`/`LoadPem` devolvem só a folha; na emissão pelo PKI, só o campo `certificate` da resposta é lido (o `ca_chain`/`issuing_ca` é ignorado).

**Evidência.**

```csharp
// HashiCorpVaultCertificateStore.cs:100-105 — emissão pelo PKI
pem = VaultJson.String(response!.Data, "certificate") ?? throw ...;   // ca_chain ignorado
using var issued = X509Certificate2.CreateFromPem(pem);

// :120-123 — importação: só a folha é carregada
// :317 — certificate.Export(X509ContentType.Pkcs12): só a folha + chave
```

**Impacto.** Um PFX importado com intermediárias, ou um certificado emitido por uma CA intermediária do PKI, volta de `DownloadCertificateAsync` sem a cadeia. Usado em TLS de servidor, clientes que não têm a intermediária falham na validação. Diverge do Azure Key Vault (guarda o PFX inteiro) e de `certificados.md`, que aceita "`CERTIFICATE` (+ cadeia)".

**Sugestão.** Guardar a cadeia junto: exportar um `X509Certificate2Collection` (folha com chave + intermediárias) em vez da instância, e no PKI acrescentar `ca_chain`:

```csharp
var collection = new X509Certificate2Collection { leafWithKey };
collection.AddRange(intermediates);                 // da importação (LoadPkcs12Collection / PEM) ou do ca_chain do PKI
byte[] pkcs12 = collection.Export(X509ContentType.Pkcs12)!;
```

No download, `X509CertificateLoader.LoadPkcs12Collection` devolve a folha (com `HasPrivateKey`) e a cadeia; expor a cadeia exigiria um método novo (ver Melhorias).

---

### RT-06 — Token com vida curta gera login a cada chamada

**Severidade:** Baixa · **Categoria:** Bug · **Local:** `TEC.Vault/Providers/Http/VaultTokenSource.cs:59-64`

O adiantamento da renovação é `clamp(vida/10, 10 s, 5 min)`. Com `lease_duration` (HashiCorp) ou `expiresIn` (Infisical) abaixo de ~11 s, `renewAt = expires - 10 s` já está no passado: `Valid()` nunca aceita o token e **toda** requisição faz login. Sugestão: limitar o adiantamento a uma fração da vida (`Math.Min(skew, life / 2)`) e registrar um aviso quando a vida do token for curta demais.

### RT-07 — Sem renovação de token (`renew-self`) no HashiCorp Vault

**Severidade:** Baixa · **Categoria:** Implementação · **Local:** `TEC.Vault.HashiCorpVault/Internal/HashiCorpVaultClient.cs:172-216`

Ao vencer, o token é trocado por um **novo login**; o anterior não é renovado nem revogado. No AppRole, cada login consome um uso do `secret_id`: com `secret_id_num_uses` ou `secret_id_ttl` (configurações comuns de hardening), a aplicação deixa de autenticar depois de N renovações. Sugestão: renovar com `POST auth/token/renew-self` enquanto o token for `renewable` e abaixo do `token_max_ttl`, e só então refazer o login; documentar a interação com `secret_id_num_uses`.

### RT-08 — `ReloadInterval` sem teto

**Severidade:** Baixa · **Categoria:** Validação · **Local:** `TEC.Vault/Configuration/VaultConfiguration.cs:44, 196`

O setter só exige mínimo de 1 minuto. `TimeSpan.TryParse("30")` é **30 dias** (conferido), aceito em silêncio; acima de ~49,7 dias, `TimeProvider.System.CreateTimer` lança `ArgumentOutOfRangeException` (conferido) dentro de `Load()`, na subida, sem o caminho da chave na mensagem. Sugestão: teto (ex.: 24 h) no setter, com mensagem que cite `Vault:Configuration:ReloadInterval`.

### RT-09 — Fonte de `IConfiguration` cria um segundo cliente, nunca descartado

**Severidade:** Baixa · **Categoria:** Organização / recursos · **Local:** `TEC.Vault/Configuration/VaultConfiguration.cs:482`; `TEC.Vault.HashiCorpVault/HashiCorpVaultExtensions.cs:81`

`IConfigurationBuilder.AddTecVault(section, providers)` cria um store novo (`CreateSecretReader`), independente do registrado no container: no HashiCorp e no Infisical são **dois logins, dois tokens, dois `HttpClient` e dois circuit breakers** para o mesmo cofre, e o `VaultConfigurationProvider` não descarta o store (o `Dispose` só para o timer). Sugestão: documentar o custo e descartar o store junto com o provedor de configuração (`VaultConfigurationProvider.Dispose`), ou permitir reaproveitar o store do container após o `Build` (recarga pelo store compartilhado).

### RT-10 — Cliente do HashiCorp criado no registro e descartado por qualquer container

**Severidade:** Baixa · **Categoria:** Dispose · **Local:** `TEC.Vault.HashiCorpVault/HashiCorpVaultExtensions.cs:41-42, 132-135`

`UseHashiCorpVault` cria o `HashiCorpVaultClient` na hora do registro e cada container monta o seu `ClientOwner(client)` sobre a **mesma** instância. Se a coleção gerar dois `ServiceProvider` (ex.: `BuildServiceProvider()` temporário em código de inicialização, ou testes), o descarte do primeiro descarta o `HttpClient` do segundo, que passa a falhar com `ObjectDisposedException` → `VAULT_FALHA` (exceção inesperada). Sugestão: criar o cliente dentro da fábrica singleton (`sp => new HashiCorpVaultClient(options)`), validando as opções no registro como hoje.

### RT-11 — `deletion_allowed` fica ligado se a exclusão falhar

**Severidade:** Baixa · **Categoria:** Segurança · **Local:** `TEC.Vault.HashiCorpVault/HashiCorpVaultKeyStore.cs:190-198`

`DeleteKeyAsync` grava `deletion_allowed = true` e depois envia o `DELETE`. Se o `DELETE` falhar (rede, 5xx, cancelamento), a chave fica sem a proteção contra exclusão, sem log específico. Sugestão: em falha do `DELETE`, tentar reverter (`deletion_allowed = false`) e registrar o estado no detalhe do erro.

### RT-12 — Infisical sem limite de itens na listagem

**Severidade:** Baixa · **Categoria:** DoS / consistência · **Local:** `TEC.Vault.Infisical/InfisicalSecretStore.cs:289-292, 317-328`

Os demais provedores têm `MaxListItems`; o Infisical só é limitado por `MaxResponseBytes` (4 MB). Além disso, todo nome não encontrado dispara a listagem completa da pasta (fallback sem diferenciar maiúsculas), inclusive em leituras repetidas de um segredo opcional inexistente. Sugestão: `InfisicalOptions.MaxListItems` (mesma regra dos outros) e opção para desligar o fallback de maiúsculas.

### RT-13 — `VaultTokenSource.Entry` imprime o token

**Severidade:** Baixa · **Categoria:** Observabilidade · **Local:** `TEC.Vault/Providers/Http/VaultTokenSource.cs:29`

`private sealed record Entry(string Value, DateTimeOffset? RenewAt)` usa o `ToString` gerado (mostra o token) e aparece no depurador em `_current`. O resto do código mascara (`VaultToken`, `VaultSecret`, `SyncedEntry`, `Snapshot`). Sugestão: sobrescrever `ToString` e `[DebuggerDisplay]` como em `VaultToken`.

### RT-14 — Testes faltando para os achados acima

**Severidade:** Baixa · **Categoria:** Testes · **Local:** `TEC.Vault.Tests/`

Não há teste para: login com 503/429 após as retentativas (RT-02); várias chamadas concorrentes com login falhando (RT-03); 403 de política no HashiCorp (contagem de logins, RT-04); PFX com intermediárias e PKI com `ca_chain` (RT-05). Os *fakes* (`FakeHashiCorpVault`, `FakeInfisical`) já permitem escrever todos eles.

### RT-15 — Health check de readiness derruba todas as instâncias na queda do cofre

**Severidade:** Info · **Categoria:** Design · **Local:** `TEC.Vault/HealthChecks/VaultHealthCheck.cs:22-23, 90`

Padrão: `Unhealthy` com as tags `ready` e `vault`. Com o cofre fora do ar (ou o circuito aberto), **todas** as réplicas saem do balanceamento ao mesmo tempo, mesmo as que já têm os segredos carregados no `IConfiguration` ou no cache. É uma escolha válida, mas deve ser consciente: documentar `failureStatus: HealthStatus.Degraded` para aplicações que toleram o cofre fora do ar depois da subida.

### RT-16 — `InternalsVisibleTo` de um sample em todos os pacotes

**Severidade:** Info · **Categoria:** Organização · **Local:** `Directory.Build.props:12-14`

Todos os pacotes publicados expõem os internos a `TEC.Vault.LoadGenerator` (assemblies não assinados: qualquer assembly com esse nome os acessa, ex.: `AzureKeyVaultOptions.Transport`). Não é fronteira de segurança dentro do processo, mas acopla a API interna dos pacotes a um sample. Sugestão: limitar ao `TEC.Vault.AzureKeyVault` (o único usado) ou expor um ponto de extensão de teste explícito.

### RT-17 — Scripts do Vault de testes

**Severidade:** Info · **Categoria:** Scripts · **Local:** `.github/scripts/vault-dev.sh:11, 14-17`

O laço de espera termina em silêncio após 60 s e o erro aparece depois, no primeiro `api` (mensagem pouco clara). O token root vai na linha de comando do `curl` (visível em `ps` no runner); é efêmero e mascarado, mas `-H @-` ou `--config` evitaria. Sugestão: `curl ... || { echo "Vault não respondeu"; exit 1; }` após o laço.

---

## ✅ Status dos achados

Testes de regressão em `TEC.Vault.Tests/TechnicalReviewRegressionTests.cs` (34 casos; 20 deles falham no código anterior, conferido num worktree do commit `2ac4bea`; os demais são controle ou dependem de API nova).

| ID | Status | Arquivos alterados | Teste |
|---|---|---|---|
| RT-01 | ✅ Corrigido (**incompatível**: formato de armazenamento) | `HashiCorpVaultCertificateStore.cs`, `HashiCorpVaultOptions.cs` (`Kv.CertificateKeysPath`), `HashiCorpVaultExtensions.cs`, `Internal/HashiCorpVaultClient.cs`, `Internal/KvFolder.cs` (`DestroyVersionsAsync`) | `Private_key_is_stored_apart_from_the_public_item`, `Policy_denying_the_keys_folder_still_allows_reading_and_listing`, `Non_exportable_certificate_never_reads_the_keys_folder`, `Legacy_item_is_readable_and_migrates_to_the_new_layout`, `Delete_recover_and_purge_also_apply_to_the_private_key`, `Keys_folder_inside_or_equal_to_certificates_folder_is_rejected` |
| RT-02 | ✅ Corrigido | `VaultHttpClient.cs` (`EnsureLoginSuccess`), `HashiCorpVaultClient.cs`, `InfisicalSecretStore.cs` | `HashiCorp_login_failure_keeps_real_status`, `Infisical_login_failure_keeps_real_status`, `Login_unavailable_opens_the_circuit` |
| RT-03 | ✅ Corrigido | `VaultTokenSource.cs` (login compartilhado, falha guardada 2 s) | `Concurrent_calls_share_one_failed_login_and_the_failure_is_kept_briefly`, `Caller_cancellation_does_not_cancel_the_shared_login` |
| RT-04 | ✅ Corrigido | `VaultHttpClient.cs` (construtor com `isTokenRejected`, cache de 5 s), `HashiCorpVaultClient.cs` (`lookup-self`) | `Policy_forbidden_does_not_log_in_again_nor_drop_the_shared_token` |
| RT-05 | ✅ Corrigido | `HashiCorpVaultCertificateStore.cs` (`DownloadCertificateWithChainAsync`), `VaultCertificateLoader.cs`, `VaultCertificateRules.cs` | `Imported_pfx_keeps_its_intermediates`, `Imported_pem_keeps_its_intermediates`, `Pki_issued_certificate_keeps_the_ca_chain` |
| RT-06 | ✅ Corrigido | `VaultTokenSource.cs` (adiantamento ≤ metade da vida) | `Short_lived_token_is_reused_until_half_of_its_life` |
| RT-07 | ✅ Corrigido | `HashiCorpVaultClient.cs` (`renew-self` até não estender mais) | `Renewable_token_is_renewed_instead_of_a_new_login_until_max_ttl` |
| RT-08 | ✅ Corrigido (incompatível: > 24 h recusado) | `VaultConfiguration.cs` | `Reload_interval_above_24_hours_is_rejected`, `Reload_interval_as_plain_number_points_to_the_key` |
| RT-09 | ✅ Corrigido (descarte; o store continua separado do container) | `VaultConfiguration.cs` (fonte dona do leitor, um por provedor montado) | `Store_created_by_the_configuration_source_is_disposed_with_it`, `Rebuilt_configuration_providers_get_their_own_store`, `Store_passed_by_the_application_is_not_disposed_by_the_source` |
| RT-10 | ✅ Corrigido | `HashiCorpVaultExtensions.cs` (cliente criado na fábrica singleton) | `Disposing_one_container_does_not_break_another_built_from_the_same_collection` |
| RT-11 | ✅ Corrigido | `HashiCorpVaultKeyStore.cs` | `Failed_key_deletion_restores_deletion_protection` |
| RT-12 | ✅ Corrigido | `InfisicalOptions.cs`, `InfisicalExtensions.cs`, `InfisicalSecretStore.cs` (`MaxListItems`, `CaseInsensitiveNames`) | `Infisical_listing_respects_MaxListItems`, `Infisical_without_case_insensitive_names_does_not_list_the_folder`, `Infisical_MaxListItems_out_of_range_fails_at_startup` |
| RT-13 | ✅ Corrigido | `VaultTokenSource.cs` (`ToString` + `DebuggerDisplay`) | `Cached_token_entry_does_not_print_the_token` |
| RT-14 | ✅ Corrigido | `TEC.Vault.Tests/TechnicalReviewRegressionTests.cs`, `Fakes/FakeHashiCorpVault.cs` (lookup/renew-self, políticas, falhas de login, destroy, CA intermediária), `Fakes/FakeInfisical.cs` | — |
| RT-15 | ✅ Corrigido (documentação) | `cache-e-health-check.md` (`failureStatus: HealthStatus.Degraded`) | — |
| RT-16 | ✅ Corrigido | `Directory.Build.props` (só `TEC.Vault` e `TEC.Vault.AzureKeyVault`, os dois usados pelo sample) | build |
| RT-17 | ✅ Corrigido | `.github/scripts/vault-dev.sh` (falha explícita; token por `-H @-`) | executado contra o Vault em container |
| I3 (tec-workflows) | ⛔ Não corrigido (bloqueado) | — | Subir `TEC.Core` 0.0.1 → 0.1.0 exige regenerar os `packages.lock.json` com o feed `tec-interno` (401 nesta máquina, sem token). Comando: alterar `<PackageVersion Include="TEC.Core" Version="0.1.0" />` em `Directory.Packages.props` e rodar `dotnet restore TEC.Vault.slnx --force-evaluate` |

---

## 🛠️ Correções aplicadas — 2026-10-19

Branch `fix/revisao-tecnica-2026-10-19`; versão `0.2.0` (MINOR em `0.x`: RT-01 muda o formato de armazenamento e RT-08 recusa valores antes aceitos). Detalhes e migração no [CHANGELOG](../CHANGELOG.md) e em [Provedor HashiCorp Vault](provedor-hashicorp-vault.md#migração-da-chave-privada-dos-certificados-020).

| Passo | Comando | Resultado |
|---|---|---|
| Build Release no modo local | `dotnet build TEC.Vault.slnx -c Release -p:TecUseLocalProjects=true --no-incremental` | ✅ 0 avisos, 0 erros (analisadores de AOT/trimming como erro) |
| Pacotes | `dotnet pack TEC.Vault.slnx -c Release -p:TecUseLocalProjects=true --no-build` | ✅ validação de pacote entre TFMs sem erros |
| Testes unitários net8.0 | `dotnet run -c Release --no-build -f net8.0 -- --treenode-filter '/*/*/*/*[Category!=Integracao]'` | ✅ 648 aprovados, 0 falhas, 0 ignorados |
| Testes unitários net10.0 | idem, `-f net10.0` | ✅ 648 aprovados, 0 falhas, 0 ignorados |
| Integração HashiCorp Vault (container `hashicorp/vault` por digest + `vault-dev.sh`) | `--treenode-filter '/*/*/*/*[Category=Integracao]'`, net8.0 e net10.0 | ✅ 29 aprovados, 0 falhas, 8 ignorados (Key Vault, sem credencial Azure) em cada TFM |
| Build com o feed `tec-interno` | `dotnet build TEC.Vault.slnx -c Release` | ⛔ não executado: 401 no feed nesta máquina |

---

## ✨ Melhorias sugeridas

Em ordem de prioridade:

| # | Melhoria | Por quê |
|:-:|---|---|
| 1 | **Login resiliente** em `VaultTokenSource`: falha compartilhada e guardada por poucos segundos, classificação 5xx/429 correta, `renew-self` no HashiCorp | Fecha RT-02, RT-03, RT-06 e RT-07 de uma vez; é o caminho crítico de todos os provedores HTTP |
| 2 | **Separar material privado** de certificados no HashiCorp (item próprio ou envelope com Transit) | Fecha RT-01; permite política de menor privilégio real |
| 3 | **Confirmação de token em 403** (`auth/token/lookup-self`) com cache curto | Fecha RT-04 sem perder a renovação em token revogado |
| 4 | **Cadeia de certificados**: guardar e devolver intermediárias (ex.: `DownloadCertificateChainAsync` ou `X509Certificate2Collection`) | Fecha RT-05 e alinha os provedores |
| 5 | **Opção de CA interna** (`Http.TrustedCaFile` / `CustomTrustStore` com `X509ChainTrustMode.CustomRootTrust`) | Hoje CA interna exige `Http.Handler` próprio; é onde aparecem `ServerCertificateCustomValidationCallback = (...) => true` e `AllowAutoRedirect` esquecido. A biblioteca pode montar o handler seguro e recusar handler com redirecionamento ligado |
| 6 | **Cache negativo opcional** (`NotFound` por poucos segundos) no `CachingSecretReader` | Leituras repetidas de segredo opcional inexistente custam metadados + `LIST` no HashiCorp e listagem completa no Infisical |
| 7 | **Store único para container e `IConfiguration`** | Fecha RT-09: um login, um circuito e um descarte |
| 8 | **Métrica de login** (`vault.login.duration` com `error.type`) | Login é a falha mais comum em produção e hoje só aparece dentro da duração da operação |
| 9 | **Lease de segredos dinâmicos** (database/aws engines do Vault) | Fora do modelo atual (KV); só se houver demanda: exige renovação de lease em segundo plano |

---

## 📝 Ajustes na documentação

Correções feitas nesta revisão:

| Arquivo | Ajuste |
|---|---|
| `docs/README.md` | A linha 15 da tabela de temas (🔁 Resiliência) estava solta **na primeira linha do arquivo**, antes do breadcrumb; voltou para o lugar entre 14 e 16. Acrescentada a linha 20 (esta revisão) e o nó no mapa |
| `docs/desenvolvimento.md` | Rodapé com link para esta revisão |
| `docs/provedor-hashicorp-vault.md` | Tabela de certificados: importação e emissão pelo PKI guardam **só a folha** (RT-05). Tabela de erros: 5xx/429 **no login** saem hoje como `VAULT_AUTENTICACAO_FALHOU` (RT-02) |

Pendentes listados abaixo: **todos atendidos em 2026-10-19** (ver [Status](#-status-dos-achados)); `provedor-hashicorp-vault.md`, `provedor-infisical.md`, `certificados.md`, `resiliencia.md`, `erros.md`, `configuracao.md`, `cache-e-health-check.md` e `novo-provedor.md` foram atualizados.

Pendentes (dependiam da correção no código):

- `certificados.md` — a linha "PEM: `CERTIFICATE` (+ cadeia)" vale para o Azure Key Vault; no HashiCorp a cadeia é descartada até RT-05 ser corrigido.
- `provedor-hashicorp-vault.md` — após RT-04, explicar a checagem `lookup-self` no 403; após RT-07, a renovação com `renew-self` e a interação com `secret_id_num_uses`.
- `cache-e-health-check.md` — mencionar `failureStatus: HealthStatus.Degraded` como opção (RT-15).
- `configuracao.md` — teto de `ReloadInterval` e o formato `[d.]hh:mm:ss` (`"30"` = 30 dias) quando RT-08 for corrigido.

---
⬅️ [💻 Desenvolvimento local](desenvolvimento.md) · [📚 Índice](README.md)
