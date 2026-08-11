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
# The suite's own browser reaches portal-oidc under the discovery origin, not
# under PORTAL_OIDC_URL, so the browser overrides have to match that one.
OIDC_ORIGIN="${DISCOVERY_URL%/.well-known/openid-configuration}"

TEST_PLAN="oidcc-basic-certification-test-plan"
TEST_VARIANT='{"server_metadata":"discovery","client_registration":"static_client"}'

mkdir -p "$SCRIPT_DIR/results"

create_client() {
  local name="$1"
  curl -sf -X POST "$PORTAL_OIDC_URL/api/v1/admin/clients" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"$name\",
      \"client_type\": \"confidential\",
      \"redirect_uris\": [\"$REDIRECT_URI\"]
    }"
}

echo "==> Creating test clients..."
CLIENT_RESPONSE=$(create_client "conformance-suite")
CLIENT_SECRET_POST_RESPONSE=$(create_client "conformance-suite-client-secret-post")
CLIENT2_RESPONSE=$(create_client "conformance-suite-client-2")

CLIENT_ID=$(echo "$CLIENT_RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$CLIENT_RESPONSE" | jq -r '.client_secret')
CLIENT_SECRET_POST_ID=$(echo "$CLIENT_SECRET_POST_RESPONSE" | jq -r '.client_id')
CLIENT_SECRET_POST_SECRET=$(echo "$CLIENT_SECRET_POST_RESPONSE" | jq -r '.client_secret')
CLIENT2_ID=$(echo "$CLIENT2_RESPONSE" | jq -r '.client_id')
CLIENT2_SECRET=$(echo "$CLIENT2_RESPONSE" | jq -r '.client_secret')

for value in \
  "$CLIENT_ID" "$CLIENT_SECRET" \
  "$CLIENT_SECRET_POST_ID" "$CLIENT_SECRET_POST_SECRET" \
  "$CLIENT2_ID" "$CLIENT2_SECRET"; do
  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "Error: Failed to extract client credentials from response"
    exit 1
  fi
done

echo "    client_id=$CLIENT_ID"
echo "    client_secret_post client_id=$CLIENT_SECRET_POST_ID"
echo "    client2 client_id=$CLIENT2_ID"
echo "    client_secret=***"

echo "==> Generating test config..."
# Each browser flow is written once in the template; _override_flows names which
# module uses which, and jq fans them out into the `override` the suite reads.
sed \
  -e "s|\${DISCOVERY_URL}|$DISCOVERY_URL|g" \
  -e "s|\${OIDC_ORIGIN}|$OIDC_ORIGIN|g" \
  -e "s|\${CLIENT_ID}|$CLIENT_ID|g" \
  -e "s|\${CLIENT_SECRET}|$CLIENT_SECRET|g" \
  -e "s|\${CLIENT_SECRET_POST_ID}|$CLIENT_SECRET_POST_ID|g" \
  -e "s|\${CLIENT_SECRET_POST_SECRET}|$CLIENT_SECRET_POST_SECRET|g" \
  -e "s|\${CLIENT2_ID}|$CLIENT2_ID|g" \
  -e "s|\${CLIENT2_SECRET}|$CLIENT2_SECRET|g" \
  "$SCRIPT_DIR/config.template.json" \
  | jq '. as $config
        | .override = (
            ._override_flows
            | with_entries(.value = {browser: $config._browser_flows[.value]})
          )
        | del(._browser_flows, ._override_flows)' \
  > "$SCRIPT_DIR/results/config.json"

echo "==> Running conformance test plan: $TEST_PLAN"
uv run --project "$REPO_DIR/.github/scripts" --locked python "$REPO_DIR/.github/scripts/run-test-plan.py" \
  --server "$CONFORMANCE_SERVER" \
  --token "$CONFORMANCE_TOKEN" \
  --plan "$TEST_PLAN" \
  --variant "$TEST_VARIANT" \
  --config "$SCRIPT_DIR/results/config.json" \
  --output "$SCRIPT_DIR/results" \
  --oidc-server "$OIDC_SERVER_LOCAL" \
  --expected-skips "$SCRIPT_DIR/expected-skips.json"

echo "==> Done. Results saved to $SCRIPT_DIR/results/"
