-- OIDCクライアント
CREATE TABLE clients (
  client_id CHAR(36) PRIMARY KEY,
  client_secret_hash VARCHAR(255),
  name VARCHAR(255) NOT NULL,
  client_type VARCHAR(20) NOT NULL,
  redirect_uris JSON NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- セッション (認可後のユーザーセッション)
CREATE TABLE sessions (
  session_id CHAR(36) PRIMARY KEY,
  user_id VARCHAR(32) NOT NULL,
  client_id CHAR(36) NOT NULL,
  allowed_scopes JSON NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

-- ログインセッション (認可フロー中の一時セッション)
CREATE TABLE login_sessions (
  login_session_id CHAR(36) PRIMARY KEY,
  forms TEXT NOT NULL,
  allowed_scopes JSON NOT NULL,
  user_id VARCHAR(32) NOT NULL,
  client_id CHAR(36) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);
