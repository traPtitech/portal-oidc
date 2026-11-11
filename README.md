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
git clone https://github.com/traPtitech/portal-oidc.git
cd portal-oidc
mise trust       # Trust mise configuration
mise run setup   # Install pre-commit hooks
mise run dev     # Start development environment (Docker + hot-reload)
```

Access:

| Service | URL | Credentials |
|---------|-----|-------------|
| OIDC Server | http://localhost:8080 | - |
| Adminer | http://localhost:3001 | root / password |
| OIDC DB | localhost:5433 | root / password |

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

### Local login

Use these steps only with a disposable development or test database.

1. Apply `db/schema.sql` to the OIDC database. When Docker Compose creates the database, it applies this file.
2. Start the server with `OIDC_INTERNAL__TOKEN` set. Docker Compose sets it from `PORTAL_INTERNAL_TOKEN` in your shell.
3. Send the fixture to the internal provision API:

   ```bash
   curl -X POST http://localhost:8080/internal/users/provision \
     -H "X-Portal-Internal-Token: <token>" \
     -H "Content-Type: application/json" \
     --data @development/provision.json
   ```

4. Log in as `TestUser_01` with the password `password`.

### Login assets

The server embeds the built login files in `internal/router/v1/loginassets`. If you change `web/src`, rebuild them and commit the output. The build needs Node.js 20.19 or later.

```bash
npm --prefix web ci --ignore-scripts
npm --prefix web run build
npm --prefix web test   # Check the auth secret test vector
```

To run the browser tests, follow these steps:

1. Install Chromium with `cd web && npx playwright install chromium`.
2. Start the server on port 8080 with the internal token `browser-test-internal-token`.
3. Run `npm --prefix web run test:browser`.

`OIDC_TEST_URL` and `OIDC_TEST_INTERNAL_TOKEN` override the URL and the token.

## License

Code licensed under [the MIT License](https://github.com/traPtitech/portal-oidc/blob/master/LICENSE).
