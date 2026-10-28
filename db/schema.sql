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
  post_logout_redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
  allowed_origins JSONB NOT NULL DEFAULT '[]'::jsonb,
  grant_types JSONB NOT NULL DEFAULT '["authorization_code"]'::jsonb,
  response_types JSONB NOT NULL DEFAULT '["code"]'::jsonb,
  scopes JSONB NOT NULL DEFAULT '["openid","profile","email"]'::jsonb,
  token_endpoint_auth TEXT NOT NULL DEFAULT 'client_secret_basic',
  id_token_alg TEXT NOT NULL DEFAULT 'RS256',
  status TEXT NOT NULL DEFAULT 'active',
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

-- traPortal v2 spec §user_consents
-- Persists which scopes a user has granted to which client. The (user_id,
-- client_id) UNIQUE constraint enforces a single live consent per pair: a new
-- grant overwrites the prior set rather than accumulating duplicates.
CREATE TABLE IF NOT EXISTS user_consents (
  id UUID NOT NULL,
  user_id UUID NOT NULL,
  client_id UUID NOT NULL,
  scopes JSONB NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  PRIMARY KEY (id),
  CONSTRAINT idx_user_consents_user_client UNIQUE (user_id, client_id),
  CONSTRAINT fk_user_consents_client FOREIGN KEY (client_id)
    REFERENCES clients (client_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_consents_user_id ON user_consents (user_id);

-- Revoke stored credentials atomically, including status changes made directly
-- in the database while client metadata is not exposed by the admin API.
CREATE OR REPLACE FUNCTION revoke_inactive_client_sessions()
RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM tokens WHERE client_id = NEW.client_id;
  DELETE FROM authorization_codes WHERE client_id = NEW.client_id;
  DELETE FROM oidc_sessions WHERE client_id = NEW.client_id;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_clients_revoke_sessions
AFTER UPDATE OF status ON clients
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status <> 'active')
EXECUTE FUNCTION revoke_inactive_client_sessions();

-- Serialize issuance against status updates. The shared row lock is held until
-- the issuing transaction ends, so suspension either deletes its credentials
-- after commit or prevents their creation in the first place.
CREATE OR REPLACE FUNCTION require_active_client()
RETURNS TRIGGER AS $$
BEGIN
  PERFORM 1 FROM clients
  WHERE client_id = NEW.client_id AND status = 'active'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'client is not active' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_authorization_codes_require_active_client
BEFORE INSERT ON authorization_codes
FOR EACH ROW EXECUTE FUNCTION require_active_client();

CREATE TRIGGER trg_tokens_require_active_client
BEFORE INSERT ON tokens
FOR EACH ROW EXECUTE FUNCTION require_active_client();

CREATE TRIGGER trg_oidc_sessions_require_active_client
BEFORE INSERT ON oidc_sessions
FOR EACH ROW EXECUTE FUNCTION require_active_client();
