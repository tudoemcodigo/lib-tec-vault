#!/usr/bin/env bash
# Prepara a integração do TEC.Vault no CI (chamado pelo dotnet-test.yml do tec-workflows, antes do build).
#   - HashiCorp Vault descartável (modo dev, só em localhost do runner, sem dado real) para o TEC.Vault.HashiCorpVault:
#     KV v2, Transit e PKI. Não precisa de segredo, por isso roda também em pull request.
#   - Key Vault de testes: as variáveis chegam por azure-env, só quando o login OIDC ocorreu (main, fora de PR).
set -euo pipefail

# Imagem fixada por digest (2.1.1); o token root é de um servidor que existe só durante o job
IMAGE="hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
TOKEN="tec-ci-$(openssl rand -hex 16)"
echo "::add-mask::$TOKEN"

docker run -d --name tec-vault-ci --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 \
  -e "VAULT_DEV_ROOT_TOKEN_ID=$TOKEN" "$IMAGE" >/dev/null

VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN="$TOKEN" bash .github/scripts/vault-dev.sh

{
  echo "TEC_TESTES_HASHICORP_ADDR=http://127.0.0.1:8200"
  echo "TEC_TESTES_HASHICORP_TOKEN=$TOKEN"
  echo "TEC_TESTES_HASHICORP_PKI_ROLE=tec-testes"
} >> "$GITHUB_ENV"
