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
| Adminer (portal) | http://localhost:3001 | root / password |
| Portal DB | localhost:3306 | root / password |
| OIDC DB | localhost:3307 | root / password |

> **Note**: Run `docker compose --profile tools up` to include Adminer.

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

## License

Code licensed under [the MIT License](https://github.com/traPtitech/portal-oidc/blob/master/LICENSE).
