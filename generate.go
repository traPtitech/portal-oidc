//go:generate go tool sqlc generate --file ./db/sqlc.yaml

//go:generate go tool oapi-codegen --config ./api/oapi.models.yaml ./api/openapi.yaml
//go:generate go tool oapi-codegen --config ./api/oapi.server.yaml ./api/openapi.yaml
package portaloidc
