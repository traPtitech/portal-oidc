env "oidc" {
  src = "file://schema.sql"
  url = "postgres://root:password@localhost:3307/oidc?sslmode=disable"
  dev = "docker://postgres/17/dev"
}

env "portal" {
  src = "file://portal-schema.sql"
  url = "postgres://root:password@localhost:3306/portal?sslmode=disable"
  dev = "docker://postgres/17/dev"
}
