-- OIDC Schema (MariaDB 10.11+)

CREATE TABLE `clients` (
  `client_id` uuid NOT NULL DEFAULT uuid(),
  `client_secret_hash` varchar(255) NULL,
  `name` varchar(255) NOT NULL,
  `client_type` ENUM('public', 'confidential') NOT NULL,
  `redirect_uris` json NOT NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
