-- =============================================================================
-- Portal Schema (external database - copy for sqlc generation)
-- =============================================================================

-- Trigger function for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Users
CREATE TABLE users (
  id UUID NOT NULL,
  trap_id VARCHAR(32) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  email BYTEA,
  personal_info BYTEA,
  student_number VARCHAR(8),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT uq_users_trap_id UNIQUE (trap_id),
  CONSTRAINT uq_users_student_number UNIQUE (student_number)
);

CREATE INDEX idx_users_created_at ON users (created_at);

CREATE TRIGGER update_users_updated_at
  BEFORE UPDATE ON users
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- User statuses
CREATE TABLE user_statuses (
  user_id UUID NOT NULL,
  status VARCHAR(64) NOT NULL,
  detail VARCHAR(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, status),
  CONSTRAINT fk_user_statuses_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_statuses_status ON user_statuses (status);

-- User links (SNS connections)
CREATE TABLE user_links (
  user_id UUID NOT NULL,
  service VARCHAR(64) NOT NULL,
  external_id VARCHAR(255),
  account_name VARCHAR(255),
  access_token BYTEA,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, service),
  CONSTRAINT uq_user_links_service_external UNIQUE (service, external_id),
  CONSTRAINT fk_user_links_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TRIGGER update_user_links_updated_at
  BEFORE UPDATE ON user_links
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Invitations
CREATE TABLE invitations (
  id UUID NOT NULL,
  code VARCHAR(20) NOT NULL,
  created_by UUID,
  used_by UUID,
  expires_at TIMESTAMPTZ,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT uq_invitations_code UNIQUE (code),
  CONSTRAINT uq_invitations_used_by UNIQUE (used_by),
  CONSTRAINT fk_invitations_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_invitations_used_by FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_invitations_created_by ON invitations (created_by);
CREATE INDEX idx_invitations_expires_at ON invitations (expires_at);

-- Groups
CREATE TABLE groups (
  id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  parent_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT uq_groups_name_parent UNIQUE (name, parent_id),
  CONSTRAINT fk_groups_parent FOREIGN KEY (parent_id) REFERENCES groups(id) ON DELETE SET NULL
);

CREATE INDEX idx_groups_parent ON groups (parent_id);

CREATE TRIGGER update_groups_updated_at
  BEFORE UPDATE ON groups
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Group members
CREATE TABLE group_members (
  group_id UUID NOT NULL,
  user_id UUID NOT NULL,
  roles JSONB NOT NULL DEFAULT '[]',
  joined_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, user_id),
  CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
  CONSTRAINT fk_group_members_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_group_members_user ON group_members (user_id);
CREATE INDEX idx_group_members_joined_at ON group_members (joined_at);

-- Group member logs (audit trail)
CREATE TABLE group_member_logs (
  id UUID NOT NULL,
  group_id UUID NOT NULL,
  user_id UUID NOT NULL,
  action VARCHAR(32) NOT NULL,
  actor_id UUID,
  old_roles JSONB,
  new_roles JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_group_member_logs_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
  CONSTRAINT fk_group_member_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_group_member_logs_actor FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_group_member_logs_group ON group_member_logs (group_id);
CREATE INDEX idx_group_member_logs_user ON group_member_logs (user_id);
CREATE INDEX idx_group_member_logs_actor ON group_member_logs (actor_id);
CREATE INDEX idx_group_member_logs_created_at ON group_member_logs (created_at);

-- Group permissions
CREATE TABLE group_permissions (
  group_id UUID NOT NULL,
  permission VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, permission),
  CONSTRAINT fk_group_permissions_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE INDEX idx_group_permissions_permission ON group_permissions (permission);

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
  CONSTRAINT fk_user_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_keys_active ON user_keys (user_id, is_active);

-- Group keys (E2E encryption for group secrets)
CREATE TABLE group_keys (
  group_id UUID NOT NULL,
  user_id UUID NOT NULL,
  key_id UUID NOT NULL,
  encrypted_key BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (group_id, user_id, key_id),
  CONSTRAINT fk_group_keys_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
  CONSTRAINT fk_group_keys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_group_keys_user_key FOREIGN KEY (user_id, key_id) REFERENCES user_keys(user_id, key_id) ON DELETE CASCADE
);

CREATE INDEX idx_group_keys_user ON group_keys (user_id);

-- Secrets (E2E encrypted secrets)
CREATE TABLE secrets (
  id UUID NOT NULL,
  group_id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  encrypted_value BYTEA NOT NULL,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT uq_secrets_group_name UNIQUE (group_id, name),
  CONSTRAINT fk_secrets_group FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
  CONSTRAINT fk_secrets_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_secrets_created_by ON secrets (created_by);

CREATE TRIGGER update_secrets_updated_at
  BEFORE UPDATE ON secrets
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Secret logs (audit trail)
CREATE TABLE secret_logs (
  id UUID NOT NULL,
  secret_id UUID NOT NULL,
  action VARCHAR(32) NOT NULL,
  actor_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_secret_logs_secret FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE,
  CONSTRAINT fk_secret_logs_actor FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_secret_logs_secret ON secret_logs (secret_id);
CREATE INDEX idx_secret_logs_actor ON secret_logs (actor_id);
CREATE INDEX idx_secret_logs_created_at ON secret_logs (created_at);

-- Webhooks
CREATE TABLE webhooks (
  id UUID NOT NULL,
  name VARCHAR(255) NOT NULL,
  url VARCHAR(2048) NOT NULL,
  secret BYTEA,
  owner_id UUID,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_webhooks_owner FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_webhooks_owner ON webhooks (owner_id);
CREATE INDEX idx_webhooks_active ON webhooks (is_active);

CREATE TRIGGER update_webhooks_updated_at
  BEFORE UPDATE ON webhooks
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Webhook subscribe events
CREATE TABLE webhook_subscribe_events (
  webhook_id UUID NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (webhook_id, event_type),
  CONSTRAINT fk_webhook_events_webhook FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);

CREATE INDEX idx_webhook_events_type ON webhook_subscribe_events (event_type);

-- Namecards
CREATE TABLE namecards (
  student_prefix VARCHAR(32) NOT NULL,
  color VARCHAR(7) NOT NULL,
  PRIMARY KEY (student_prefix),
  CONSTRAINT chk_namecards_color CHECK (color ~ '^#[0-9A-Fa-f]{6}$')
);

-- Mails
CREATE TABLE mails (
  id UUID NOT NULL,
  "to" TEXT NOT NULL,
  subject VARCHAR(255) NOT NULL,
  body TEXT NOT NULL,
  operator_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_mails_operator FOREIGN KEY (operator_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_mails_operator ON mails (operator_id);
CREATE INDEX idx_mails_created_at ON mails (created_at);

-- Mail logs
CREATE TABLE mail_logs (
  id UUID NOT NULL,
  mail_id UUID NOT NULL,
  status VARCHAR(32) NOT NULL,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  CONSTRAINT fk_mail_logs_mail FOREIGN KEY (mail_id) REFERENCES mails(id) ON DELETE CASCADE,
  CONSTRAINT chk_mail_logs_status CHECK (status IN ('unsent', 'sent', 'failed'))
);

CREATE INDEX idx_mail_logs_mail ON mail_logs (mail_id);
CREATE INDEX idx_mail_logs_status ON mail_logs (status);
CREATE INDEX idx_mail_logs_created_at ON mail_logs (created_at);
