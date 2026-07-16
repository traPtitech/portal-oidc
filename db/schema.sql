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
    REFERENCES clients (client_id) ON DELETE CASCADE,
  CONSTRAINT fk_oidc_sessions_authorize_code FOREIGN KEY (authorize_code)
    REFERENCES authorization_codes (code) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_oidc_sessions_client_id ON oidc_sessions (client_id);

-- traPortal v2 spec §webauthn_credentials
-- WebAuthn (FIDO2 / Passkey) credentials registered by users. credential_id
-- is the rawId returned by the authenticator and is used as the lookup key
-- on each authentication ceremony. public_key is the COSE-encoded form so it
-- can be re-fed verbatim to a WebAuthn library at sign-in time. sign_count
-- is monotonically increasing per credential (RFC W3C-WebAuthn-Level-3 §6.1)
-- and a non-monotonic increment indicates a cloned authenticator.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id UUID NOT NULL,
  user_id UUID NOT NULL,
  credential_id BYTEA NOT NULL,
  public_key BYTEA NOT NULL,
  public_key_alg INT NOT NULL,
  attestation_format TEXT NULL,
  aaguid UUID NULL,
  sign_count BIGINT NOT NULL DEFAULT 0,
  transports JSONB NULL,
  device_name TEXT NULL,
  backed_up BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at TIMESTAMPTZ NULL,
  PRIMARY KEY (id),
  CONSTRAINT idx_webauthn_credentials_credential_id UNIQUE (credential_id)
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials (user_id);

-- traPortal v2 spec §webauthn_challenges
-- One-shot challenge tracker for an in-flight registration or authentication
-- ceremony. user_id is nullable because the discoverable-credential
-- (a.k.a. usernameless) flow starts authentication without knowing who is
-- about to log in. session_id pairs the challenge with the cookie session
-- that initiated it so cross-session replay is impossible.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id UUID NOT NULL,
  challenge BYTEA NOT NULL,
  user_id UUID NULL,
  session_id TEXT NULL,
  type TEXT NOT NULL,
  data JSONB NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT idx_webauthn_challenges_challenge UNIQUE (challenge),
  CONSTRAINT chk_webauthn_challenges_type CHECK (type IN ('register', 'authenticate'))
);

-- Composite index covers ConsumeWebAuthnChallenge's WHERE on (session_id, type)
-- which is the hot path during every WebAuthn ceremony.
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_session_type ON webauthn_challenges (session_id, type);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires_at ON webauthn_challenges (expires_at);
