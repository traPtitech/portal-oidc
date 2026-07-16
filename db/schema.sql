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

-- traPortal v2 spec §access_tokens
-- jti is the fosite-issued signature of the opaque access token and serves as
-- the lookup key. user_id is nullable because the client_credentials grant
-- (future) issues tokens without a subject. revoked_at is the source of truth
-- for revocation; expired tokens are pruned by a separate sweep.
CREATE TABLE IF NOT EXISTS access_tokens (
  id UUID NOT NULL,
  jti TEXT NOT NULL,
  request_id TEXT NOT NULL,
  client_id UUID NOT NULL,
  user_id UUID NULL,
  scopes TEXT NOT NULL,
  audience JSONB NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL,
  PRIMARY KEY (id),
  CONSTRAINT idx_access_tokens_jti UNIQUE (jti),
  CONSTRAINT fk_access_tokens_client FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens (client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_request_id ON access_tokens (request_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens (expires_at);

-- traPortal v2 spec §refresh_tokens
-- token_hash is the fosite signature. previous_token_id links rotation
-- generations so OAuth 2.1 §4.13.2 family-revocation can walk the chain when
-- a leaked refresh token is detected. revoked_at + rotated_at separate "we
-- intentionally retired this token" from "the user explicitly revoked it".
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID NOT NULL,
  token_hash TEXT NOT NULL,
  request_id TEXT NOT NULL,
  client_id UUID NOT NULL,
  user_id UUID NOT NULL,
  scopes TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMPTZ NOT NULL,
  rotated_at TIMESTAMPTZ NULL,
  previous_token_id UUID NULL,
  revoked_at TIMESTAMPTZ NULL,
  PRIMARY KEY (id),
  CONSTRAINT idx_refresh_tokens_token_hash UNIQUE (token_hash),
  CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE,
  CONSTRAINT fk_refresh_tokens_previous FOREIGN KEY (previous_token_id) REFERENCES refresh_tokens (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens (client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_request_id ON refresh_tokens (request_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_previous_token ON refresh_tokens (previous_token_id);

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
    REFERENCES clients (client_id) ON DELETE CASCADE,
  CONSTRAINT fk_oidc_sessions_authorize_code FOREIGN KEY (authorize_code)
    REFERENCES authorization_codes (code) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_client_id ON oidc_sessions (client_id);
