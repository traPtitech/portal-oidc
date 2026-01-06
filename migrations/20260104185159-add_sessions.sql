-- +migrate Up

-- ログインセッション (spec.md sessions テーブル準拠)
CREATE TABLE `sessions` (
    `id` CHAR(36) NOT NULL,
    `user_id` VARCHAR(32) NOT NULL,
    `user_agent` TEXT,
    `ip_address` VARCHAR(45),
    `auth_time` DATETIME(6) NOT NULL,
    `last_active_at` DATETIME(6) NOT NULL,
    `expires_at` DATETIME(6) NOT NULL,
    `revoked_at` DATETIME(6),
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    INDEX `sessions_user_id_index` (`user_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- ユーザー同意情報 (spec.md user_consents テーブル準拠)
CREATE TABLE `user_consents` (
    `id` CHAR(36) NOT NULL,
    `user_id` VARCHAR(32) NOT NULL,
    `client_id` CHAR(36) NOT NULL,
    `scopes` JSON NOT NULL,
    `granted_at` DATETIME(6) NOT NULL,
    `expires_at` DATETIME(6),
    `revoked_at` DATETIME(6),
    PRIMARY KEY (`id`),
    UNIQUE KEY `user_consents_user_client_unique` (`user_id`, `client_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- OAuth認可フロー一時状態
CREATE TABLE `login_sessions` (
    `id` CHAR(36) NOT NULL,
    `client_id` CHAR(36) NOT NULL,
    `redirect_uri` TEXT NOT NULL,
    `form_data` TEXT NOT NULL,
    `scopes` JSON NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `expires_at` DATETIME(6) NOT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- +migrate Down
DROP TABLE `login_sessions`;
DROP TABLE `user_consents`;
DROP TABLE `sessions`;
