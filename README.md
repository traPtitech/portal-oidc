# traPortal OIDC Provider

[![GitHub release](https://img.shields.io/github/release/traPtitech/portal-oidc.svg?logo=github)](https://GitHub.com/traPtitech/portal-oidc/releases/) [![CI](https://github.com/traPtitech/portal-oidc/actions/workflows/ci.yaml/badge.svg)](https://github.com/traPtitech/portal-oidc/actions/workflows/ci.yaml) [![codecov](https://codecov.io/gh/traPtitech/portal-oidc/branch/main/graph/badge.svg)](https://codecov.io/gh/traPtitech/portal-oidc) [![swagger](https://img.shields.io/badge/swagger-docs-brightgreen)](https://portal-v2-dev.trapti.tech/api/)

OAuth 2.1 / OpenID Connect provider for traP, providing SSO for traP services.

- Frontend repositories
  - [traPtitech/portal-UI](https://github.com/traPtitech/portal-UI)
- Backend repositories
  - [traPtitech/portal](https://github.com/traPtitech/portal)
  - [traPtitech/portal-oidc](https://github.com/traPtitech/portal-oidc) (this repository)

## Quick Start

Requires [mise](https://mise.jdx.dev/) and Docker.

```bash
mise install     # Install tools
mise run start   # Start DB and server
```

Now you can access to

- <http://localhost:8080> for OIDC server
- <http://localhost:3001> for adminer
  - username: `root`
  - password: `password`
  - database: `portal` (port 3306) / `oidc` (port 3307)

## Documentation

- [Specification](./docs/spec.md)
- [API schema](https://portal-v2-dev.trapti.tech/api/)
- [DB schema (portal-oidc)](./docs/db/oidc)
- [DB schema (traPortal v2)](./docs/db/portal)

## Development

```bash
mise run         # Run tasks (with fuzzy search)
mise run gen     # Generate code
mise run lint    # Run linter
mise run docs    # Generate DB schema docs
```

## Conformance Suite Testing

How to test locally with the OIDC Conformance Suite.

### Setup

```bash
# Clone and build Conformance Suite (first time only)
git clone https://gitlab.com/openid/conformance-suite.git /tmp/conformance-suite
cd /tmp/conformance-suite
mvn clean package -DskipTests
```

### Run Tests

```bash
# 1. Start OIDC server
docker compose up -d

# 2. Start Conformance Suite
cd /tmp/conformance-suite
docker compose up -d

# 3. Create test client
curl -X POST http://localhost:8080/api/v1/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "name": "conformance-test",
    "client_type": "confidential",
    "redirect_uris": ["https://localhost.emobix.co.uk:8443/test/a/portal-oidc/callback"]
  }'
```

4. Open https://localhost.emobix.co.uk:8443
5. Select "Create a new test plan" → "OpenID Connect Core: Basic Certification Profile Authorization server test"
6. Enter configuration:
   - `server.discoveryUrl`: `http://host.docker.internal:8080/.well-known/openid-configuration`
   - `client.client_id`: The client ID from step 3
   - `client.client_secret`: The client secret from step 3

## License

Code licensed under [the MIT License](https://github.com/traPtitech/portal-oidc/blob/master/LICENSE).
