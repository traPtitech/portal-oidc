#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

PORTAL_OIDC_URL="${PORTAL_OIDC_URL:-http://localhost:8080}"
CONFORMANCE_SERVER="${CONFORMANCE_SERVER:-https://localhost:8443}"
CONFORMANCE_TOKEN="${CONFORMANCE_TOKEN-}"
DISCOVERY_URL="${DISCOVERY_URL:-http://host.docker.internal:8080/.well-known/openid-configuration}"
REDIRECT_URI="https://localhost.emobix.co.uk:8443/test/a/portal-oidc/callback"
OIDC_SERVER_LOCAL="${OIDC_SERVER_LOCAL:-localhost:8080}"

TEST_PLAN="oidcc-basic-certification-test-plan"
TEST_VARIANT='{"server_metadata":"discovery","client_registration":"static_client"}'

mkdir -p "$SCRIPT_DIR/results"

echo "==> Creating test client..."
RESPONSE=$(curl -sf -X POST "$PORTAL_OIDC_URL/api/v1/admin/clients" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"conformance-suite\",
    \"client_type\": \"confidential\",
    \"redirect_uris\": [\"$REDIRECT_URI\"]
  }")

CLIENT_ID=$(echo "$RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.client_secret')

if [[ -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ]]; then
  echo "Error: Failed to extract client credentials from response"
  exit 1
fi

echo "    client_id=$CLIENT_ID"
echo "    client_secret=***"

echo "==> Generating test config..."
sed \
  -e "s|\${DISCOVERY_URL}|$DISCOVERY_URL|g" \
  -e "s|\${CLIENT_ID}|$CLIENT_ID|g" \
  -e "s|\${CLIENT_SECRET}|$CLIENT_SECRET|g" \
  "$SCRIPT_DIR/config.template.json" > "$SCRIPT_DIR/results/config.json"

echo "==> Running conformance test plan: $TEST_PLAN"
python3 "$REPO_DIR/.github/scripts/run-test-plan.py" \
  --server "$CONFORMANCE_SERVER" \
  --token "$CONFORMANCE_TOKEN" \
  --plan "$TEST_PLAN" \
  --variant "$TEST_VARIANT" \
  --config "$SCRIPT_DIR/results/config.json" \
  --output "$SCRIPT_DIR/results" \
  --oidc-server "$OIDC_SERVER_LOCAL" \
  --expected-skips "$SCRIPT_DIR/expected-skips.json"

echo "==> Done. Results saved to $SCRIPT_DIR/results/"
