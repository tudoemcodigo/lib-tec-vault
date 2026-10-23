#!/usr/bin/env bash
# Remove o HashiCorp Vault descartável da integração (chamado sempre no fim do job, mesmo com falha).
docker rm -f tec-vault-ci >/dev/null 2>&1 || true
