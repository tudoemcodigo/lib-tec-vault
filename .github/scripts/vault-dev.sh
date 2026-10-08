#!/usr/bin/env bash
# Prepara um HashiCorp Vault em modo desenvolvimento (vault server -dev) para os testes de integração do TEC.Vault.HashiCorpVault:
# monta o Transit e o PKI (com CA raiz e o papel tec-testes). O KV v2 em "secret" já vem montado no modo dev.
# Uso: VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<token root do dev> .github/scripts/vault-dev.sh
# Só para servidores descartáveis de teste: usa o token root.
set -euo pipefail
: "${VAULT_ADDR:?defina VAULT_ADDR}"
: "${VAULT_TOKEN:?defina VAULT_TOKEN}"

api() {
  curl --silent --show-error --fail -H "X-Vault-Token: ${VAULT_TOKEN}" -X "$1" "${VAULT_ADDR}/v1/$2" ${3:+--data "$3"} > /dev/null
}

for _ in $(seq 1 60); do
  curl --silent --fail "${VAULT_ADDR}/v1/sys/health" > /dev/null && break
  sleep 1
done

api POST sys/mounts/transit '{"type":"transit"}'
api POST sys/mounts/pki '{"type":"pki","config":{"max_lease_ttl":"87600h"}}'
api POST pki/root/generate/internal '{"common_name":"TEC Testes CA","ttl":"87600h"}'
api POST pki/roles/tec-testes '{"allow_any_name":true,"enforce_hostnames":false,"key_type":"any","max_ttl":"87600h"}'

echo "Vault de testes pronto em ${VAULT_ADDR} (Transit, PKI com papel tec-testes)."
