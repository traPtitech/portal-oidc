-- OIDC Schema

-- updated_at auto-update trigger function
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS clients (
  client_id UUID NOT NULL,
  client_secret_hash TEXT NULL,
  name TEXT NOT NULL,
  client_type TEXT NOT NULL,
  redirect_uris JSONB NOT NULL,
  -- traPortal v2 spec: per-client OAuth metadata
  client_uri TEXT NULL,
  logo_uri TEXT NULL,
  post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
  allowed_origins JSONB NOT NULL DEFAULT '[]'::jsonb,
  grant_types JSONB NOT NULL DEFAULT '["authorization_code","refresh_token"]'::jsonb,
  response_types JSONB NOT NULL DEFAULT '["code"]'::jsonb,
  scopes JSONB NOT NULL DEFAULT '["openid","profile","email"]'::jsonb,
  token_endpoint_auth TEXT NOT NULL DEFAULT 'client_secret_basic',
  jwks_uri TEXT NULL,
  jwks JSONB NULL,
  id_token_alg TEXT NOT NULL DEFAULT 'RS256',
  status TEXT NOT NULL DEFAULT 'active',
  owner_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (client_id)
);

CREATE TRIGGER trg_clients_set_updated_at
BEFORE UPDATE ON clients FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE IF NOT EXISTS authorization_codes (
  code TEXT NOT NULL,
  client_id UUID NOT NULL,
  user_id UUID NOT NULL,
  redirect_uri TEXT NOT NULL,
  scopes TEXT NOT NULL,
  code_challenge TEXT NULL,
  code_challenge_method TEXT NULL,
  nonce TEXT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (code),
  CONSTRAINT fk_authorization_codes_client FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes (client_id);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS tokens (
  id UUID NOT NULL,
  request_id TEXT NOT NULL,
  client_id UUID NOT NULL,
  user_id UUID NOT NULL,
  access_token TEXT NOT NULL,
  refresh_token TEXT NULL,
  scopes TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT idx_tokens_access_token UNIQUE (access_token),
  CONSTRAINT fk_tokens_client FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_refresh_token ON tokens (refresh_token);
CREATE INDEX IF NOT EXISTS idx_tokens_client_id ON tokens (client_id);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_request_id ON tokens (request_id);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens (expires_at);

CREATE TABLE IF NOT EXISTS oidc_sessions (
  authorize_code TEXT NOT NULL,
  client_id UUID NOT NULL,
  user_id UUID NOT NULL,
  scopes TEXT NOT NULL,
  nonce TEXT NULL,
  auth_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  requested_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (authorize_code),
  CONSTRAINT fk_oidc_sessions_client FOREIGN KEY (client_id)
    REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_client_id ON oidc_sessions (client_id);
