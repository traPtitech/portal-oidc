env "oidc" {
  src = "file://schema.sql"
  url = "postgres://root:password@localhost:5433/oidc?sslmode=disable"
  dev = "docker://postgres/17/dev"
}
