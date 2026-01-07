env "local" {
  src = "file://schema.sql"
  url = "postgres://postgres:password@localhost:5433/oidc?sslmode=disable"
  dev = "docker://postgres/18/oidc"
  migration {
    dir = "file://migrations"
  }
}
