-- ==========================================================
-- SecureCloud Monitor - Centralized Security Monitoring Database
-- Target Engine: MySQL 5.7+ / MySQL 8.0 / MariaDB (XAMPP Default)
-- ==========================================================

CREATE DATABASE IF NOT EXISTS `securecloud_monitor`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `securecloud_monitor`;

-- Disable foreign key checks for clean teardown/recreation if needed
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------------------------------------
-- 1. Users Table
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `email` VARCHAR(100) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `role` ENUM('user', 'admin') NOT NULL DEFAULT 'user',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_users_role` (`role`),
  INDEX `idx_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 2. Files Table (User Encrypted/Monitored File Vault)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `files`;
CREATE TABLE `files` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `original_name` VARCHAR(255) NOT NULL,
  `stored_name` VARCHAR(255) NOT NULL,
  `file_size` BIGINT NOT NULL,
  `checksum` VARCHAR(64) NOT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
  INDEX `idx_files_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 3. Activity Log (Audit Trail)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `activity_log`;
CREATE TABLE `activity_log` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NULL,
  `action` VARCHAR(100) NOT NULL,
  `details` TEXT,
  `ip_address` VARCHAR(45) DEFAULT '127.0.0.1',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL,
  INDEX `idx_activity_action` (`action`),
  INDEX `idx_activity_user` (`user_id`),
  INDEX `idx_activity_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 4. Security Rules
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `security_rules`;
CREATE TABLE `security_rules` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `rule_code` VARCHAR(50) NOT NULL UNIQUE,
  `name` VARCHAR(255) NOT NULL,
  `description` TEXT,
  `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
  `enabled` BOOLEAN NOT NULL DEFAULT TRUE,
  `category` VARCHAR(100) NOT NULL DEFAULT 'General',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_rules_code` (`rule_code`),
  INDEX `idx_rules_severity` (`severity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 5. Security Alerts
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `security_alerts`;
CREATE TABLE `security_alerts` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `rule_id` INT NULL,
  `title` VARCHAR(255) NOT NULL,
  `description` TEXT,
  `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
  `status` ENUM('OPEN', 'ACKNOWLEDGED', 'RESOLVED') NOT NULL DEFAULT 'OPEN',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `resolved_at` TIMESTAMP NULL,
  FOREIGN KEY (`rule_id`) REFERENCES `security_rules`(`id`) ON DELETE SET NULL,
  INDEX `idx_alerts_status` (`status`),
  INDEX `idx_alerts_severity` (`severity`),
  INDEX `idx_alerts_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 6. Security Incidents
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `security_incidents`;
CREATE TABLE `security_incidents` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `alert_id` INT NULL,
  `title` VARCHAR(255) NOT NULL,
  `description` TEXT,
  `severity` ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
  `status` ENUM('OPEN', 'INVESTIGATING', 'RESOLVED') NOT NULL DEFAULT 'OPEN',
  `investigation_notes` TEXT,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `resolved_at` TIMESTAMP NULL,
  FOREIGN KEY (`alert_id`) REFERENCES `security_alerts`(`id`) ON DELETE SET NULL,
  INDEX `idx_incidents_status` (`status`),
  INDEX `idx_incidents_severity` (`severity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 7. Cloud Resources (Simulated AWS Infrastructure)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `cloud_resources`;
CREATE TABLE `cloud_resources` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `resource_type` VARCHAR(50) NOT NULL,
  `resource_name` VARCHAR(255) NOT NULL,
  `status` VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
  `config_json` JSON,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_res_type` (`resource_type`),
  INDEX `idx_res_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 8. Application Settings
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `app_settings`;
CREATE TABLE `app_settings` (
  `setting_key` VARCHAR(100) PRIMARY KEY,
  `setting_value` TEXT NOT NULL,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------
-- 9. Sessions Table (for MySQL-backed session store)
-- ----------------------------------------------------------
DROP TABLE IF EXISTS `sessions`;
CREATE TABLE `sessions` (
  `session_id` VARCHAR(128) COLLATE utf8mb4_bin NOT NULL,
  `expires` INT(11) UNSIGNED NOT NULL,
  `data` MEDIUMTEXT COLLATE utf8mb4_bin,
  PRIMARY KEY (`session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- ==========================================================
-- SEED DATA
-- ==========================================================

-- 1. Initial Admin User (password: 'Admin@12345' with bcrypt 10 rounds)
-- Hash: $2a$10$tZ2P3oY7sM1k1mK6eD5Wq.gO3iBwLz6cVuY3iCqK9qX1A6QvFmB6K (or auto-synced by Node)
INSERT INTO `users` (`id`, `username`, `email`, `password`, `role`)
VALUES
  (1, 'admin', 'admin@securecloud.local', '$2a$10$sX9Zg7RvhZJ4Z6jPqJ2f6OB2aM0T.Z2bS6z.nJ4J9rA9C7cR3b8E6', 'admin')
ON DUPLICATE KEY UPDATE `username` = `username`;

-- 2. Default Security Rules
INSERT INTO `security_rules` (`id`, `rule_code`, `name`, `description`, `severity`, `enabled`, `category`)
VALUES
  (1, 'RULE_S3_PUBLIC', 'Public S3 Bucket Detected', 'Scans AWS S3 storage buckets for public access ACLs or permissive bucket policies allowing unauthenticated read/write.', 'CRITICAL', 1, 'Storage Security'),
  (2, 'RULE_FAILED_LOGINS', 'Excessive Failed Login Attempts', 'Detects brute-force credential stuffing or password spray attacks exceeding 5 failed attempts within 15 minutes.', 'HIGH', 1, 'Identity & Access'),
  (3, 'RULE_EC2_CPU_HIGH', 'EC2 High Compute Utilization Spike', 'Identifies virtual compute instances operating above 85% CPU load for extended periods (potential crypto-mining or DoS).', 'MEDIUM', 1, 'Compute Security'),
  (4, 'RULE_UNENCRYPTED_DB', 'Unencrypted RDS Database Storage', 'Identifies relational database instances provisioned without KMS encryption at rest.', 'HIGH', 1, 'Database Security'),
  (5, 'RULE_OPEN_SECURITY_GROUP', 'Unrestricted Ingress (0.0.0.0/0 on Port 22/3306)', 'Detects VPC Security Groups allowing direct inbound traffic from the open internet to management or database ports.', 'CRITICAL', 1, 'Network Security')
ON DUPLICATE KEY UPDATE `rule_code` = `rule_code`;

-- 3. Default Cloud Resources (Simulated AWS Infrastructure)
INSERT INTO `cloud_resources` (`id`, `resource_type`, `resource_name`, `status`, `config_json`)
VALUES
  (1, 'AWS::S3::Bucket', 'securecloud-customer-backups-east', 'VULNERABLE', '{"bucket_name": "securecloud-customer-backups-east", "region": "us-east-1", "is_public": true, "public_policy": "public-read", "versioning": false, "kms_encrypted": false}'),
  (2, 'AWS::EC2::Instance', 'i-098af34bc1230de44 (prod-web-01)', 'CRITICAL', '{"instance_id": "i-098af34bc1230de44", "instance_type": "t3.xlarge", "region": "us-east-1", "cpu_utilization": 94.5, "public_ip": "54.210.88.19", "state": "running"}'),
  (3, 'AWS::RDS::DBInstance', 'db-mysql-prod-primary', 'SECURE', '{"db_identifier": "db-mysql-prod-primary", "engine": "aurora-mysql", "multi_az": true, "storage_encrypted": true, "backup_retention_days": 30}'),
  (4, 'AWS::EC2::SecurityGroup', 'sg-0a44fe88b12e09cc (web-dmz-sg)', 'VULNERABLE', '{"group_id": "sg-0a44fe88b12e09cc", "vpc_id": "vpc-018f23aa", "open_ports": [22, 3306], "cidr_ingress": "0.0.0.0/0"}'),
  (5, 'AWS::IAM::Role', 'role-lambda-data-processor', 'SECURE', '{"role_name": "role-lambda-data-processor", "attached_policies": ["AWSLambdaBasicExecutionRole"], "mfa_enforced": true, "unused_days": 12}')
ON DUPLICATE KEY UPDATE `resource_name` = `resource_name`;

-- 4. Initial Baseline Security Alerts
INSERT INTO `security_alerts` (`id`, `rule_id`, `title`, `description`, `severity`, `status`, `created_at`)
VALUES
  (1, 1, 'Public Read Access Allowed on S3 Bucket', 'S3 Bucket "securecloud-customer-backups-east" has public-read ACL enabled. Sensitive enterprise archives exposed to internet.', 'CRITICAL', 'OPEN', NOW() - INTERVAL 2 HOUR),
  (2, 2, 'Brute Force Attack Detected against Admin Portal', '6 failed authentication attempts recorded within 10 minutes originating from remote IP 198.51.100.42.', 'HIGH', 'OPEN', NOW() - INTERVAL 1 HOUR),
  (3, 3, 'EC2 CPU Load Exceeded Threshold (94.5%)', 'EC2 instance "i-098af34bc1230de44" has sustained 94.5% CPU utilization for over 30 minutes.', 'MEDIUM', 'ACKNOWLEDGED', NOW() - INTERVAL 3 HOUR),
  (4, 5, 'Port 22 (SSH) Open to Entire Internet', 'Security Group "sg-0a44fe88b12e09cc" allows 0.0.0.0/0 ingress on TCP Port 22 without bastion restriction.', 'CRITICAL', 'OPEN', NOW() - INTERVAL 45 MINUTE)
ON DUPLICATE KEY UPDATE `title` = `title`;

-- 5. Initial Baseline Security Incidents
INSERT INTO `security_incidents` (`id`, `alert_id`, `title`, `description`, `severity`, `status`, `investigation_notes`, `created_at`)
VALUES
  (1, 1, 'CRITICAL: Data Leakage Risk - Public S3 Bucket', 'Investigation into exposed backup repository "securecloud-customer-backups-east". Potential exposure of customer records.', 'CRITICAL', 'INVESTIGATING', '[2026-08-20 18:30] SOC Analyst assigned. Bucket policy quarantined via simulated AWS CLI.\n[2026-08-20 18:45] Initiating access log review to verify whether external downloads occurred.', NOW() - INTERVAL 2 HOUR),
  (2, 4, 'CRITICAL: Perimeter Vulnerability - SSH Ingress Exposed', 'Management port 22 exposed to 0.0.0.0/0 on DMZ security group. High risk of automated credential brute force.', 'CRITICAL', 'OPEN', '[2026-08-20 20:00] Automated rule engine escalation. Recommended remediation: Restrict CIDR block to corporate VPN IP.', NOW() - INTERVAL 45 MINUTE)
ON DUPLICATE KEY UPDATE `title` = `title`;

-- 6. Default App Settings
INSERT INTO `app_settings` (`setting_key`, `setting_value`)
VALUES
  ('failed_login_threshold', '5'),
  ('cpu_alert_threshold', '85'),
  ('scan_interval_seconds', '60'),
  ('auto_resolve_alerts', 'false'),
  ('retention_days_audit', '90'),
  ('soc_alert_notification_email', 'soc-alerts@securecloud.local'),
  ('system_banner_message', 'PRODUCTION SOC MONITORING ACTIVE - SIMULATED AWS CLOUD TARGETS')
ON DUPLICATE KEY UPDATE `setting_value` = `setting_value`;

-- 7. Seed Initial System Activity
INSERT INTO `activity_log` (`user_id`, `action`, `details`, `ip_address`, `created_at`)
VALUES
  (1, 'SYSTEM_INIT', 'SecureCloud Monitor platform initialized with baseline security policies.', '127.0.0.1', NOW() - INTERVAL 6 HOUR),
  (1, 'AUTH_LOGIN_SUCCESS', 'Administrator initial session login from SOC Console.', '127.0.0.1', NOW() - INTERVAL 5 HOUR),
  (NULL, 'AUTH_FAILED_LOGIN', 'Failed login attempt for username: root from external probe.', '198.51.100.42', NOW() - INTERVAL 1 HOUR);
