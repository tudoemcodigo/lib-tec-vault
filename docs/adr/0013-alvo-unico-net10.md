# ADR 0013: Alvo Único .NET 10

## Status
Aprovado

## Data
2026-10-29

## Contexto
Os pacotes saíam para `net8.0` e `net10.0`. O alvo duplo custava código condicional (`#if NET9_0_OR_GREATER` na carga de certificados), um polyfill de `System.Threading.Lock` compartilhado pelo template, duas seções em cada `packages.lock.json`, um job a mais na matriz de testes e o cuidado de manter a mesma API pública nos dois alvos. No .NET 8, a carga de PFX ainda passava pelo construtor de `X509Certificate2`, sem os limites do `X509CertificateLoader`.

## Decisão
Os componentes TEC.* passam a ter um único alvo, **`net10.0`** (LTS), definido no `build/Tec.Build.props` do template (`tec-workflows`). No TEC.Vault:
- `VaultCertificateLoader` usa só o `X509CertificateLoader` (sai o caminho do .NET 8);
- o assinador SigV4 usa `Convert.ToHexStringLower`, sem `#if`;
- os `packages.lock.json` ficam com a seção `net10.0`;
- o CI roda os unitários em `net10.0` e em `net10.0` sem ICU.

## Consequências
### Positivas
- Menos código condicional e um caminho só de carga de certificados, com os limites contra PFX malicioso.
- APIs do .NET 9 e 10 disponíveis sem polyfill (`Lock`, `Base64Url`, `Convert.ToHexStringLower`).

### Neutras / Negativas
- Aplicações em `net8.0` não podem consumir os pacotes até migrar para o .NET 10.
