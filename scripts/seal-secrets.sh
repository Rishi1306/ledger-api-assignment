#!/usr/bin/env bash
# Encrypts plaintext secrets into a SealedSecret using kubeseal.
# Run this once per environment, commit the output — never commit plaintext.
#
# Prerequisites:
#   kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/latest/download/controller.yaml
#   brew install kubeseal
#
# Usage:
#   STRIPE_API_KEY=sk_live_xxx DB_PASSWORD=secret ./scripts/seal-secrets.sh

set -euo pipefail

if [[ -z "${STRIPE_API_KEY:-}" || -z "${DB_PASSWORD:-}" ]]; then
  echo "Set STRIPE_API_KEY and DB_PASSWORD before running."
  exit 1
fi

kubectl create secret generic ledger-api-secrets \
  --namespace=payments \
  --from-literal=STRIPE_API_KEY="${STRIPE_API_KEY}" \
  --from-literal=DB_PASSWORD="${DB_PASSWORD}" \
  --dry-run=client -o yaml \
| kubeseal --format=yaml > deploy/sealed-secret.yaml

echo "SealedSecret written to deploy/sealed-secret.yaml — safe to commit."
