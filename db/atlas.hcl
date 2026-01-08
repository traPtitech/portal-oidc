env "oidc" {
  src = "file://schema.sql"
  url = "mariadb://root:password@localhost:3307/oidc"
  dev = "docker://mariadb/latest/dev"
}

env "portal" {
  src = "file://portal-schema.sql"
  url = "mariadb://root:password@localhost:3306/portal"
  dev = "docker://mariadb/latest/dev"
}
