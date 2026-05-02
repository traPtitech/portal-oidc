-- Portal Schema

-- updated_at auto-update trigger function (mimics MySQL's ON UPDATE CURRENT_TIMESTAMP)
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Users
CREATE TABLE users (
  id UUID NOT NULL,
  trap_id VARCHAR(32) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email BYTEA NULL,
  personal_info BYTEA NULL,
  student_number VARCHAR(8) NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT uq_users_trap_id UNIQUE (trap_id),
  CONSTRAINT uq_users_student_number UNIQUE (student_number)
);

CREATE TRIGGER trg_users_set_updated_at
BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- User statuses
CREATE TABLE user_statuses (
  user_id UUID NOT NULL,
  status VARCHAR(64) NOT NULL,
  detail VARCHAR(255) NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, status),
  CONSTRAINT fk_user_statuses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);

-- User links (SNS connections)
CREATE TABLE user_links (
  user_id UUID NOT NULL,
  service VARCHAR(64) NOT NULL,
  external_id VARCHAR(255) NULL,
  account_name VARCHAR(255) NULL,
  access_token BYTEA NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, service),
  CONSTRAINT fk_user_links_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TRIGGER trg_user_links_set_updated_at
BEFORE UPDATE ON user_links FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Invitations
CREATE TABLE invitations (
  id UUID NOT NULL,
  code VARCHAR(20) NOT NULL,
  created_by UUID NULL,
  used_by UUID NULL,
  expires_at TIMESTAMPTZ NULL,
  used_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT uq_invitations_code UNIQUE (code),
  CONSTRAINT fk_invitations_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT fk_invitations_used_by FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_invitations_created_by ON invitations (created_by);
CREATE INDEX IF NOT EXISTS idx_invitations_used_by ON invitations (used_by);

-- Groups
CREATE TABLE groups (
  id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  parent_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_groups_parent FOREIGN KEY (parent_id) REFERENCES groups(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_groups_parent ON groups (parent_id);

CREATE TRIGGER trg_groups_set_updated_at
BEFORE UPDATE ON groups FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Group members
CREATE TABLE group_members (
  group_id UUID NOT NULL,
  user_id UUID NOT NULL,
  roles JSONB NOT NULL DEFAULT '[]'::JSONB,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, user_id),
  CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_group_members_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members (user_id);

-- Group member logs (audit trail)
CREATE TABLE group_member_logs (
  id UUID NOT NULL,
  group_id UUID NOT NULL,
  user_id UUID NOT NULL,
  action VARCHAR(32) NOT NULL,
  actor_id UUID NULL,
  old_roles JSONB NULL,
  new_roles JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_group_member_logs_group ON group_member_logs (group_id);
CREATE INDEX IF NOT EXISTS idx_group_member_logs_user ON group_member_logs (user_id);

-- Group permissions
CREATE TABLE group_permissions (
  group_id UUID NOT NULL,
  permission VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, permission),
  CONSTRAINT fk_group_permissions_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE
);

-- User keys (E2E encryption)
CREATE TABLE user_keys (
  user_id UUID NOT NULL,
  key_id UUID NOT NULL,
  public_key BYTEA NOT NULL,
  encrypted_private_key BYTEA NOT NULL,
  algorithm VARCHAR(32) NOT NULL DEFAULT 'RSA-OAEP-SHA256',
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, key_id),
  CONSTRAINT fk_user_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Group keys (E2E encryption for group secrets)
CREATE TABLE group_keys (
  group_id UUID NOT NULL,
  user_id UUID NOT NULL,
  key_id UUID NOT NULL,
  encrypted_key BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, user_id, key_id),
  CONSTRAINT fk_group_keys_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_group_keys_user_key FOREIGN KEY (user_id, key_id) REFERENCES user_keys(user_id, key_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_group_keys_user_key ON group_keys (user_id, key_id);

-- Secrets (E2E encrypted secrets)
CREATE TABLE secrets (
  id UUID NOT NULL,
  group_id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  encrypted_value BYTEA NOT NULL,
  created_by UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_secrets_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_secrets_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_secrets_group ON secrets (group_id);
CREATE INDEX IF NOT EXISTS idx_secrets_created_by ON secrets (created_by);

CREATE TRIGGER trg_secrets_set_updated_at
BEFORE UPDATE ON secrets FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Secret logs (audit trail)
CREATE TABLE secret_logs (
  id UUID NOT NULL,
  secret_id UUID NOT NULL,
  action VARCHAR(32) NOT NULL,
  actor_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_secret_logs_secret ON secret_logs (secret_id);

-- Webhooks
CREATE TABLE webhooks (
  id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  url VARCHAR NOT NULL,
  secret BYTEA NULL,
  owner_id UUID NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_webhooks_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_webhooks_owner ON webhooks (owner_id);

CREATE TRIGGER trg_webhooks_set_updated_at
BEFORE UPDATE ON webhooks FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Webhook subscribe events
CREATE TABLE webhook_subscribe_events (
  webhook_id UUID NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (webhook_id, event_type),
  CONSTRAINT fk_webhook_events_webhook FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE ON UPDATE CASCADE
);

-- Namecards
CREATE TABLE namecards (
  student_prefix VARCHAR(32) NOT NULL,
  color VARCHAR(32) NULL,
  PRIMARY KEY (student_prefix)
);

-- Mails
CREATE TABLE mails (
  id UUID NOT NULL,
  "to" TEXT NULL,
  subject VARCHAR(255) NULL,
  body TEXT NULL,
  operator_id UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_mails_operator FOREIGN KEY (operator_id) REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mails_operator ON mails (operator_id);

-- Mail logs
CREATE TABLE mail_logs (
  id UUID NOT NULL,
  mail_id UUID NOT NULL,
  status VARCHAR(32) NOT NULL,
  error TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_mail_logs_mail FOREIGN KEY (mail_id) REFERENCES mails(id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_mail_logs_mail ON mail_logs (mail_id);
