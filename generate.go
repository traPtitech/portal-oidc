// TODO: generate.goを分割すると一部だけ更新したいときに便利なので分割を検討する

//go:generate go tool sqlc generate --file ./sqlc.yaml

//go:generate go tool oapi-codegen --config ./oapi.config.yaml ./docs/openapi.yaml
package portaloidc
