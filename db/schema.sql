-- OIDC Schema

-- updated_at auto-update trigger function
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = GREATEST(clock_timestamp(), OLD.updated_at + INTERVAL '1 microsecond');
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
  grant_types JSONB NOT NULL DEFAULT '["authorization_code","refresh_token"]'::jsonb,
  response_types JSONB NOT NULL DEFAULT '["code"]'::jsonb,
  scopes JSONB NOT NULL DEFAULT '["openid","profile","email"]'::jsonb,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (client_id),
  CONSTRAINT clients_status_check CHECK (status IN ('active', 'suspended'))
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
  access_token TEXT NULL,
  refresh_token TEXT NULL,
  scopes TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT idx_tokens_access_token UNIQUE (access_token),
  CONSTRAINT chk_tokens_at_least_one_token CHECK (access_token IS NOT NULL OR refresh_token IS NOT NULL),
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
    REFERENCES clients (client_id) ON DELETE CASCADE,
  CONSTRAINT fk_oidc_sessions_authorize_code FOREIGN KEY (authorize_code)
    REFERENCES authorization_codes (code) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_client_id ON oidc_sessions (client_id);

-- Suspension permanently revokes credentials in the same transaction as the
-- status change, including changes made outside the application repository.
CREATE OR REPLACE FUNCTION revoke_suspended_client_credentials()
RETURNS TRIGGER AS $$
BEGIN
  IF OLD.status IS DISTINCT FROM NEW.status AND NEW.status <> 'active' THEN
    DELETE FROM tokens WHERE client_id = NEW.client_id;
    DELETE FROM authorization_codes WHERE client_id = NEW.client_id;
    DELETE FROM oidc_sessions WHERE client_id = NEW.client_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_clients_revoke_credentials
AFTER UPDATE OF status ON clients
FOR EACH ROW EXECUTE FUNCTION revoke_suspended_client_credentials();

-- Serialize credential issuance with suspension. An issuance that finishes
-- first is removed by suspension; an issuance that loses the race is rejected.
CREATE OR REPLACE FUNCTION require_active_client()
RETURNS TRIGGER AS $$
DECLARE
  client_status TEXT;
BEGIN
  SELECT status INTO client_status FROM clients
  WHERE client_id = NEW.client_id FOR SHARE;
  IF client_status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'cannot issue credentials for an inactive client'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tokens_require_active_client
BEFORE INSERT ON tokens
FOR EACH ROW EXECUTE FUNCTION require_active_client();

CREATE TRIGGER trg_authorization_codes_require_active_client
BEFORE INSERT ON authorization_codes
FOR EACH ROW EXECUTE FUNCTION require_active_client();

CREATE TRIGGER trg_oidc_sessions_require_active_client
BEFORE INSERT ON oidc_sessions
FOR EACH ROW EXECUTE FUNCTION require_active_client();
