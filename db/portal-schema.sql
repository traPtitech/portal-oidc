-- Portal Schema

-- Users
CREATE TABLE `users` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `trap_id` varchar(32) NOT NULL COMMENT 'traP ID (unique username)',
  `password_hash` varchar(255) NOT NULL COMMENT 'PBKDF2-SHA512 hash',
  `email` varbinary(512) NULL COMMENT 'AES-GCM encrypted email',
  `personal_info` blob NULL COMMENT 'AES-GCM encrypted JSON (name, phone, address, etc.)',
  `student_number` varchar(8) NULL COMMENT 'Student number (plaintext for lookup)',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_trap_id` (`trap_id`),
  UNIQUE KEY `uq_users_student_number` (`student_number`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- User statuses
CREATE TABLE `user_statuses` (
  `user_id` char(36) NOT NULL,
  `status` varchar(64) NOT NULL COMMENT 'Status type: active, suspended, email-unconfirmed, etc.',
  `detail` varchar(255) NULL COMMENT 'Additional detail/reason',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`user_id`, `status`),
  CONSTRAINT `fk_user_statuses_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- User links (SNS connections)
CREATE TABLE `user_links` (
  `user_id` char(36) NOT NULL,
  `service` varchar(64) NOT NULL COMMENT 'Service name: twitter, github, discord, etc.',
  `external_id` varchar(255) NULL COMMENT 'External service user ID',
  `account_name` varchar(255) NULL COMMENT 'Display name/handle on the service',
  `access_token` varbinary(1024) NULL COMMENT 'Encrypted OAuth access token (if stored)',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`user_id`, `service`),
  CONSTRAINT `fk_user_links_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Invitations
CREATE TABLE `invitations` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `code` varchar(20) NOT NULL COMMENT 'Invitation code (e.g., XXXX-XXXX-XXXX)',
  `created_by` char(36) NULL COMMENT 'User who created this invitation',
  `used_by` char(36) NULL COMMENT 'User who used this invitation',
  `expires_at` datetime(6) NULL COMMENT 'Expiration time (NULL = never expires)',
  `used_at` datetime(6) NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_invitations_code` (`code`),
  CONSTRAINT `fk_invitations_created_by` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_invitations_used_by` FOREIGN KEY (`used_by`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Groups
CREATE TABLE `groups` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `name` varchar(255) NOT NULL,
  `description` text NULL,
  `parent_id` char(36) NULL COMMENT 'Parent group for hierarchical structure',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_groups_parent` FOREIGN KEY (`parent_id`) REFERENCES `groups`(`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Group members
CREATE TABLE `group_members` (
  `group_id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `roles` json NOT NULL DEFAULT ('[]') COMMENT 'Member roles within group: ["admin", "owner", "member"]',
  `joined_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`group_id`, `user_id`),
  CONSTRAINT `fk_group_members_group` FOREIGN KEY (`group_id`) REFERENCES `groups`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_group_members_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Group member logs (audit trail)
CREATE TABLE `group_member_logs` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `group_id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `action` varchar(32) NOT NULL COMMENT 'Action: added, removed, role_changed',
  `actor_id` char(36) NULL COMMENT 'User who performed the action',
  `old_roles` json NULL,
  `new_roles` json NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `idx_group_member_logs_group` (`group_id`),
  KEY `idx_group_member_logs_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Group permissions
CREATE TABLE `group_permissions` (
  `group_id` char(36) NOT NULL,
  `permission` varchar(64) NOT NULL COMMENT 'Permission: user:read, user:update, invitation:create, etc.',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`group_id`, `permission`),
  CONSTRAINT `fk_group_permissions_group` FOREIGN KEY (`group_id`) REFERENCES `groups`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- User keys (E2E encryption)
CREATE TABLE `user_keys` (
  `user_id` char(36) NOT NULL,
  `key_id` char(36) NOT NULL COMMENT 'UUID v4',
  `public_key` varbinary(4096) NOT NULL COMMENT 'User public key (DER format)',
  `encrypted_private_key` blob NOT NULL COMMENT 'Private key encrypted with user password-derived key',
  `algorithm` varchar(32) NOT NULL DEFAULT 'RSA-OAEP-SHA256' COMMENT 'Key algorithm',
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`user_id`, `key_id`),
  CONSTRAINT `fk_user_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Group keys (E2E encryption for group secrets)
CREATE TABLE `group_keys` (
  `group_id` char(36) NOT NULL,
  `user_id` char(36) NOT NULL,
  `key_id` char(36) NOT NULL COMMENT 'UUID v4',
  `encrypted_key` blob NOT NULL COMMENT 'Group symmetric key encrypted with user public key',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`group_id`, `user_id`, `key_id`),
  CONSTRAINT `fk_group_keys_group` FOREIGN KEY (`group_id`) REFERENCES `groups`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_group_keys_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Secrets (E2E encrypted secrets)
CREATE TABLE `secrets` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `group_id` char(36) NOT NULL COMMENT 'Owning group',
  `name` varchar(255) NOT NULL,
  `encrypted_value` blob NOT NULL COMMENT 'AES-GCM encrypted with group key',
  `created_by` char(36) NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `idx_secrets_group` (`group_id`),
  CONSTRAINT `fk_secrets_group` FOREIGN KEY (`group_id`) REFERENCES `groups`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_secrets_created_by` FOREIGN KEY (`created_by`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Secret logs (audit trail)
CREATE TABLE `secret_logs` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `secret_id` char(36) NOT NULL,
  `action` varchar(32) NOT NULL COMMENT 'Action: created, updated, deleted, accessed',
  `actor_id` char(36) NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `idx_secret_logs_secret` (`secret_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Webhooks
CREATE TABLE `webhooks` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `name` varchar(255) NOT NULL,
  `url` varchar(2048) NOT NULL,
  `secret` varbinary(512) NULL COMMENT 'HMAC signing secret (encrypted)',
  `owner_id` char(36) NULL COMMENT 'User who owns this webhook',
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_webhooks_owner` FOREIGN KEY (`owner_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Webhook subscribe events
CREATE TABLE `webhook_subscribe_events` (
  `webhook_id` char(36) NOT NULL,
  `event_type` varchar(64) NOT NULL COMMENT 'Event type: user.created, group.member_added, etc.',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`webhook_id`, `event_type`),
  CONSTRAINT `fk_webhook_events_webhook` FOREIGN KEY (`webhook_id`) REFERENCES `webhooks`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Namecards
CREATE TABLE `namecards` (
  `student_prefix` varchar(32) NOT NULL COMMENT 'Student number prefix (e.g., 15B, 24B)',
  `color` varchar(32) NULL COMMENT 'Hex color code',
  PRIMARY KEY (`student_prefix`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Mails
CREATE TABLE `mails` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `to` text NULL COMMENT 'Recipients (format: @trap_id;@trap_id2)',
  `subject` varchar(255) NULL,
  `body` text NULL,
  `operator_id` char(36) NULL COMMENT 'User who sent this mail',
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_mails_operator` FOREIGN KEY (`operator_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Mail logs
CREATE TABLE `mail_logs` (
  `id` char(36) NOT NULL COMMENT 'UUID v4',
  `mail_id` char(36) NOT NULL,
  `status` varchar(32) NOT NULL COMMENT 'Status: unsent, sent, failed',
  `error` text NULL,
  `created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`id`),
  KEY `idx_mail_logs_mail` (`mail_id`),
  CONSTRAINT `fk_mail_logs_mail` FOREIGN KEY (`mail_id`) REFERENCES `mails`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
