-- +migrate Up

CREATE TABLE `clients` (
    `client_id` CHAR(36) NOT NULL,
    `client_secret_hash` VARCHAR(255) NULL,
    `name` VARCHAR(255) NOT NULL,
    `client_type` VARCHAR(20) NOT NULL,
    `redirect_uris` JSON NOT NULL,
    `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    `updated_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (`client_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_general_ci;

-- +migrate Down
DROP TABLE `clients`;
