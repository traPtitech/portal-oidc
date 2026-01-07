env "local" {
  src = "file://schema.sql"
  url = "maria://root:password@localhost:3307/oidc"
  dev = "docker://mariadb/11.8.5/oidc"
  migration {
    dir = "file://migrations"
  }
}
