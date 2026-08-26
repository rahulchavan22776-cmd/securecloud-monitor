# 🛡️ SecureCloud Monitor - Enterprise Cloud Security Monitoring Platform

A centralized, local-first Cloud Security Operations Center (SOC) and encrypted User File Vault built with **Node.js, Express, MySQL (XAMPP)**, and high-performance **Vanilla HTML5/CSS3/JavaScript**.

---

## 📋 Table of Contents
1. [Overview & Key Features](#overview--key-features)
2. [Tech Stack & Architecture](#tech-stack--architecture)
3. [XAMPP & Database Setup](#xampp--database-setup)
4. [Installation & Startup](#installation--startup)
5. [Default Credentials](#default-credentials)
6. [AWS Services Architecture Mapping](#aws-services-architecture-mapping)
7. [Security Controls & Hardening](#security-controls--hardening)
8. [API Route Reference](#api-route-reference)
9. [Step-by-Step Testing & Verification Workflow](#step-by-step-testing--verification-workflow)

---

## 🌟 Overview & Key Features

**SecureCloud Monitor** provides end-to-end cloud infrastructure monitoring, automated security rule evaluation, threat correlation, incident triage, and tenant-isolated file management.

### SOC & Administrator Features
- **Dynamic Security Posture Score (0-100%)**: Dynamically calculated based on open critical/high alerts, vulnerable assets, and active incidents.
- **Automated Rule Engine**: Scans simulated cloud resources and activity logs every 60 seconds for public S3 buckets, excessive EC2 CPU load, unencrypted databases, unrestricted security group ingress, and brute-force logins.
- **Auto-Escalation**: Automatically escalates `CRITICAL` and `HIGH` alerts into formal `security_incidents` with auto-populated triage details.
- **Incident Response Console**: Document forensics notes, track triage timelines, and advance incident statuses (`OPEN` → `INVESTIGATING` → `RESOLVED`).
- **Simulated AWS Cloud Asset Inventory**: Provision and manage simulated EC2, S3, RDS, IAM, and Security Group resources with live JSON configurations.
- **Enterprise Forensic Audit Trail**: System-wide activity logging with IP tracking and one-click CSV export.

### User Workspace Features
- **Zero-Trust Encrypted File Vault**: Store documents with SHA-256 integrity hashing and strict tenant data isolation (`WHERE user_id = ?`).
- **Extension & Executable Blacklist**: Restricts dangerous script and binary extensions (`.exe`, `.sh`, `.bat`, `.php`, `.vbs`, `.js`, etc.).
- **Personal Audit Trail**: Track personal logins, downloads, uploads, and profile modifications.

---

## 🛠️ Tech Stack & Architecture

- **Backend**: Node.js, Express.js
- **Database**: MySQL 5.7+ / 8.0 / MariaDB via `mysql2/promise` connection pool
- **Session Management**: `express-session` with `express-mysql-session` store
- **Security & Cryptography**: `bcryptjs` (10 salt rounds), Node.js `crypto` (SHA-256)
- **File Uploads**: `multer` with cryptographically randomized filenames
- **Frontend**: Vanilla HTML5, Modern CSS3 (Dark SOC Cyber Theme), ES6 JavaScript (Fetch API) — *No React/Vue/Tailwind/Docker dependencies*.

---

## 🗄️ XAMPP & Database Setup

The platform is pre-configured to connect to the default **XAMPP Windows MySQL** setup:
- **Host**: `127.0.0.1`
- **Port**: `3306`
- **User**: `root`
- **Password**: *(empty string)*
- **Database**: `securecloud_monitor`

### Automatic DB Bootstrapping (Zero-Config)
When you start the Node.js server (`npm start`), `db.js` will automatically:
1. Connect to MySQL.
2. Create database `securecloud_monitor` if it doesn't exist.
3. Automatically execute `database/schema.sql` to generate all 8 tables, indexes, constraints, baseline security rules, simulated cloud resources, and initial admin account.

### Manual Import via phpMyAdmin (Optional)
If preferred, you can also import the database manually:
1. Open **XAMPP Control Panel** and click **Start** on **Apache** and **MySQL**.
2. Open `http://localhost/phpmyadmin` in your browser.
3. Click **Import** > Choose `database/schema.sql` > Click **Import**.

---

## 🚀 Installation & Startup

```bash
# 1. Navigate to the project directory
cd c:\Users\Lenovo\Desktop\aws_CP

# 2. Install dependencies (if not already installed)
npm install

# 3. Start the application
npm start
```

Once running, access the portals at:
- **Landing Page**: [http://localhost:3000](http://localhost:3000)
- **Sign In Portal**: [http://localhost:3000/login.html](http://localhost:3000/login.html)
- **SOC Admin Command Center**: [http://localhost:3000/admin-dashboard.html](http://localhost:3000/admin-dashboard.html)
- **User Workspace**: [http://localhost:3000/user-dashboard.html](http://localhost:3000/user-dashboard.html)

---

## 🔑 Default Credentials

| Role | Username | Password | Email | Access |
| :--- | :--- | :--- | :--- | :--- |
| **SOC Administrator** | `admin` | `Admin@12345` | `admin@securecloud.local` | Full SOC & Admin Controls |
| **Standard User** | *(Register via UI)* | *(User Defined)* | *(User Defined)* | Personal File Vault & Activity |

> *Tip: The login portal includes a convenient **Auto-Fill** button for instant admin authentication.*

---

## 🌐 AWS Services Architecture Mapping

This local platform is modeled directly after enterprise AWS cybersecurity reference architectures:

| Local Component / Simulation | Target AWS Service | Enterprise Integration Model |
| :--- | :--- | :--- |
| **Security Rule Engine (`securityEngine.js`)** | **Amazon GuardDuty & AWS Config** | Continuous compliance rule evaluation & ML threat detection. |
| **EC2 CPU & Compute Rules** | **Amazon CloudWatch & Alarms** | Metric filters streaming instance telemetry via CloudWatch Agent. |
| **Activity Log (`activity_log`)** | **AWS CloudTrail** | Immutable event history of all API calls, logins, and management events. |
| **File Vault (`uploads/`)** | **Amazon S3 + AWS KMS** | S3 object storage with server-side encryption (SSE-KMS) and bucket versioning. |
| **Relational Database (`db.js`)** | **Amazon Aurora / RDS (MySQL)** | Multi-AZ managed database cluster with automated snapshots and storage encryption. |
| **Role-Based Authorization** | **AWS IAM (Identity & Access Management)** | Least-privilege IAM policies, SCPs, and permission boundaries. |

---

## 🔒 Security Controls & Hardening

1. **Timing-Safe Password Hashing**: Utilizes `bcryptjs` with 10 salt rounds to resist offline dictionary attacks.
2. **Session Security & Fixation Prevention**: Sessions are regenerated upon successful authentication (`req.session.regenerate`) and stored securely in MySQL with `httpOnly` flags.
3. **Database-Verified Sessions**: The `requireAuth` middleware verifies user status against the live MySQL database on every request to prevent stale session hijacking.
4. **Parameterized SQL Queries**: All database interactions use prepared statements (`?` placeholders) to completely eliminate SQL Injection vectors.
5. **Cryptographic File Storage**: Uploaded files receive cryptographically random 32-character hex names to prevent directory traversal and collision attacks.
6. **Integrity Checksums**: Generates a SHA-256 hash for every uploaded file to guarantee tamper-proof data verification.
7. **Strict Multi-Tenant Isolation**: All user endpoints explicitly scope data queries by `WHERE user_id = req.user.id`.

---

## 📡 API Route Reference

### Authentication (`/api`)
- `POST /api/register` - Create user account (strictly enforces `role = 'user'`).
- `POST /api/login` - Authenticate user, regenerate session, and log audit.
- `POST /api/logout` - Destroy session and clear cookies.
- `GET /api/me` - Get current session profile details.

### User Workspace (`/api`)
- `GET /api/files` - List files in user's vault.
- `POST /api/files` - Upload document (Multer, SHA-256, extension check).
- `GET /api/files/download/:id` - Securely download file (validates ownership).
- `DELETE /api/files/:id` - Delete record and disk file (validates ownership).
- `GET /api/activity` - Fetch personal user audit trail.
- `GET /api/profile` - View user statistics and usage.
- `PUT /api/profile` - Update email or password (prevents role tampering).

### SOC Administration (`/api/admin`)
- `GET /api/admin/metrics` - Real-time SOC metrics and Security Posture Score.
- `GET /api/admin/alerts` - List alerts (with filters).
- `PUT /api/admin/alerts/:id` - Update status (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`).
- `POST /api/admin/alerts` - Create manual security alert.
- `GET /api/admin/incidents` - List security incidents.
- `PUT /api/admin/incidents/:id` - Update incident status & investigation notes.
- `POST /api/admin/incidents` - Escalate alert or create manual incident.
- `GET /api/admin/rules` - List all detection rules.
- `PUT /api/admin/rules/:id` - Toggle active status (`enabled = 1/0`) or modify rule.
- `POST /api/admin/rules` - Add custom detection rule.
- `GET /api/admin/resources` - List simulated AWS cloud inventory.
- `POST /api/admin/resources` - Provision simulated cloud resource.
- `DELETE /api/admin/resources/:id` - Remove simulated cloud resource.
- `GET /api/admin/audit-logs` - Query application-wide audit trail.
- `GET / PUT /api/admin/settings` - Fetch/update SOC thresholds and configuration.
- `POST /api/admin/run-security-scan` - Trigger immediate rule engine scan.

---

## 🧪 Step-by-Step Testing & Verification Workflow

### 1. Test Admin Authentication & SOC Console
1. Open `http://localhost:3000/login.html`.
2. Click **Auto-Fill** to populate `admin` / `Admin@12345` and sign in.
3. Verify redirection to `admin-dashboard.html`.
4. Inspect the **Perimeter Health Index** score gauge and alert summary.
5. Click **⚡ Run Security Scan** to execute the security engine manually.

### 2. Test Alert & Incident Triage Workflow
1. Navigate to **Security Alerts** (`/alerts.html`).
2. Click **Acknowledge** on an open alert.
3. Click **Resolve** to close the alert; verify the Security Posture Score updates dynamically on the dashboard.
4. Navigate to **Incidents** (`/incidents.html`) and click **Triage & Notes** to update incident investigation logs.

### 3. Test Detection Rule Engine
1. Navigate to **Cloud Inventory** (`/resources.html`).
2. Click **+ Provision Simulated Resource** and add a bucket named `s3-public-test` with `{"is_public": true, "public_policy": "public-read"}`.
3. Click **⚡ Run Security Scan** on the SOC Dashboard.
4. Verify that the rule engine automatically generates a `CRITICAL` alert and escalates it to an Incident.

### 4. Test User File Vault & Isolation
1. Open an incognito/private browser window and go to `http://localhost:3000/register.html`.
2. Register a new user: `security_analyst` / `Password@123`.
3. Sign in to view `user-dashboard.html`.
4. Go to `files.html`, upload a sample `.pdf` or `.png` file.
5. Verify that the SHA-256 integrity hash is computed and displayed.
6. Test downloading and deleting the file.
7. Verify that non-admin users cannot access `admin-dashboard.html` (blocked by `requireAdmin`).

---

*SecureCloud Monitor &copy; 2026. Built with precision for enterprise cloud security demonstration.*
