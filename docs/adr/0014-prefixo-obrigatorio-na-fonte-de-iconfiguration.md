# ADR 0014: Prefixo Obrigatório na Fonte de IConfiguration

## Status
Aprovado

## Data
2026-10-29

## Contexto
A fonte de `IConfiguration` (`Configuration.AddTecVault(...)`) carregava todos os segredos visíveis para a identidade quando `VaultConfigurationOptions.Prefix` ficava vazio. Num cofre compartilhado, um segredo chamado `Logging--LogLevel--Default`, `AllowedHosts` ou `ConnectionStrings--Db`, criado por outra aplicação ou por engano, virava chave de configuração e sobrescrevia o valor da aplicação, sem aviso.

## Decisão
`Prefix` passa a ser **obrigatório** (não vazio) na fonte de `IConfiguration`, conferido na subida:
- `IConfigurationBuilder.AddTecVault(store, ...)` lança `InvalidOperationException` sem `Prefix`;
- na escolha por configuração, sem `Vault:Configuration:Prefix` (depois de conferir as chaves desconhecidas, para que um `Prefx` digitado errado apareça como tal), e o store já criado é descartado.

O registro no container (`Services.AddTecVault`) não muda: só a fonte de configuração exige o prefixo.

## Consequências
### Positivas
- Cada aplicação só carrega o que é seu; um segredo alheio não altera a configuração.

### Neutras / Negativas
- Quebra de compatibilidade (0.x): quem usava a fonte sem prefixo precisa renomear os segredos com um prefixo (`MinhaApi--...`) e informá-lo.
