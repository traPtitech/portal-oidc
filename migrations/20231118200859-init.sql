-- +migrate Up
SELECT 'up SQL query';
CREATE TABLE `clients` (
    `id` CHAR(36) NOT NULL,
    `user_id` VARCHAR(36) NOT NULL,
    `name` TEXT NOT NULL,
    `type` TEXT NOT NULL,
    `description` TEXT NOT NULL,
    `secret_key` TEXT NOT NULL,
    `redirect_uris` JSON NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `clients_user_id_index` (`user_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

CREATE TABLE `authorization_sessions` (
    `id` CHAR(36) NOT NULL,
    `type` VARCHAR(255) NOT NULL,
    `signature` VARCHAR(48) NOT NULL COMMENT 'SHA384',
    `client_id` CHAR(36) NOT NULL,
    `user_id` VARCHAR(32) NOT NULL,
    `scope` TEXT NOT NULL,
    `granted_scope` TEXT NOT NULL,
    `form_data` LONGTEXT NOT NULL,
    `session` LONGTEXT NOT NULL,
    `active` TINYINT(1) NOT NULL DEFAULT 1,
    `requested_audience` TEXT NOT NULL,
    `granted_audience` TEXT NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;
CREATE INDEX `authorization_sessions_type_and_signature_idx` ON `authorization_sessions` (`type`, `signature`);


CREATE TABLE `blacklisted_jtis` (
    `jti` CHAR(36) NOT NULL,
    `after` DATETIME(6) NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`jti`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- +migrate Down
SELECT 'down SQL query';
DROP TABLE `authorization_sessions`;
DROP TABLE `redirect_uri`;
DROP TABLE `clients`;

