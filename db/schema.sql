-- OIDC Schema

CREATE TABLE IF NOT EXISTS `clients` (
  `client_id` char(36) NOT NULL,
  `client_secret_hash` varchar(255) NULL,
  `name` varchar(255) NOT NULL,
  `client_type` varchar(20) NOT NULL,
  `redirect_uris` json NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `authorization_codes` (
  `code` varchar(64) NOT NULL,
  `client_id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `redirect_uri` text NOT NULL,
  `scopes` text NOT NULL,
  `code_challenge` varchar(128) NULL,
  `code_challenge_method` varchar(10) NULL,
  `nonce` varchar(255) NULL,
  `used` BOOLEAN NOT NULL DEFAULT FALSE,
  `expires_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`code`),
  INDEX `idx_authorization_codes_client_id` (`client_id`),
  INDEX `idx_authorization_codes_expires_at` (`expires_at`),
  CONSTRAINT `fk_authorization_codes_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`client_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `tokens` (
  `id` char(36) NOT NULL,
  `request_id` varchar(64) NOT NULL,
  `client_id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `access_token` varchar(64) NOT NULL,
  `refresh_token` varchar(64) NULL,
  `scopes` text NOT NULL,
  `expires_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE INDEX `idx_tokens_access_token` (`access_token`),
  UNIQUE INDEX `idx_tokens_refresh_token` (`refresh_token`),
  INDEX `idx_tokens_client_id` (`client_id`),
  INDEX `idx_tokens_user_id` (`user_id`),
  INDEX `idx_tokens_request_id` (`request_id`),
  INDEX `idx_tokens_expires_at` (`expires_at`),
  CONSTRAINT `fk_tokens_client` FOREIGN KEY (`client_id`) REFERENCES `clients` (`client_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `oidc_sessions` (
  `authorize_code` varchar(255) NOT NULL,
  `client_id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `scopes` text NOT NULL,
  `nonce` varchar(255) NULL,
  `auth_time` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `requested_at` datetime(6) NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`authorize_code`),
  INDEX `idx_oidc_sessions_client_id` (`client_id`),
  CONSTRAINT `fk_oidc_sessions_client` FOREIGN KEY (`client_id`)
    REFERENCES `clients` (`client_id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
