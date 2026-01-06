-- +migrate Up

-- ログインセッション (認証済みユーザー)
CREATE TABLE `sessions` (
    `id` CHAR(36) NOT NULL,
    `user_id` VARCHAR(32) NOT NULL,
    `user_agent` TEXT,
    `ip_address` VARCHAR(45),
    `auth_time` DATETIME(6) NOT NULL,
    `last_active_at` DATETIME(6) NOT NULL,
    `expires_at` DATETIME(6) NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`),
    INDEX `sessions_user_id_index` (`user_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- 認可リクエスト一時保存 (ログインリダイレクト用、15分TTL)
CREATE TABLE `authorization_requests` (
    `id` CHAR(36) NOT NULL,
    `client_id` VARCHAR(64) NOT NULL,
    `redirect_uri` TEXT NOT NULL,
    `scope` TEXT NOT NULL,
    `state` VARCHAR(255),
    `code_challenge` VARCHAR(128) NOT NULL,
    `code_challenge_method` VARCHAR(10) NOT NULL,
    `user_id` VARCHAR(32),
    `expires_at` DATETIME(6) NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- 認可コード (10分TTL)
CREATE TABLE `authorization_codes` (
    `code` VARCHAR(64) NOT NULL,
    `client_id` VARCHAR(64) NOT NULL,
    `user_id` VARCHAR(32) NOT NULL,
    `redirect_uri` TEXT NOT NULL,
    `scope` TEXT NOT NULL,
    `code_challenge` VARCHAR(128) NOT NULL,
    `code_challenge_method` VARCHAR(10) NOT NULL,
    `session_data` TEXT NOT NULL,
    `used` BOOLEAN NOT NULL DEFAULT FALSE,
    `expires_at` DATETIME(6) NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`code`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- +migrate Down
DROP TABLE `authorization_codes`;
DROP TABLE `authorization_requests`;
DROP TABLE `sessions`;
