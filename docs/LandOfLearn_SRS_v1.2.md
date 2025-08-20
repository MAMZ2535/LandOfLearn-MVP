# LandOfLearn — Software Requirements Specification (SRS) — MVP (Version 1.2)

**Document:** LandOfLearn — Software Requirements Specification (Updated / Approved)
**Version:** 1.2
Author: Mohammed Al-Zamzami
**Approval Date:** 2025-08-19

---

## Table of Contents

1. Executive Summary
2. Introduction
3. Scope & Context
4. Naming Conventions
5. Functional Requirements (FR) with Acceptance Tests
6. Refresh Token Lifecycle & DDL
7. Security Requirements (explicit)
8. Takedown & Retention Policy
9. Database DDL (`schema_mysql.sql`) & Indexing Strategy
10. Seed Guidance & `.env.example`
11. API Errors & Responses (Standard)
12. Non-functional & Performance Test Environment
13. Change Control & Sign-off Process
14. Acceptance Checklist (for Supervisor/QA)
15. Appendices

    * A: Sample curl requests
    * B: `seed_admin.php` (safe, env-driven)
    * C: `PULL_REQUEST_TEMPLATE.md` & `CONTRIBUTING.md`
    * D: Sign-off template

---

## 1. Executive Summary

LandOfLearn (MVP) is a compact web application to centralize course-related educational resources (exams, notes, slides, projects, research) for the College of Engineering and Computer (CEC). The MVP focuses on essential features a single student can implement within the project deadline:

* JWT-based authentication (access token + refresh token rotation).
* Student upload (file + metadata), file validation and checksum, admin single-step review (approve/reject).
* Public browsing/searching of approved resources and secure downloads (counter + logs).
* Tagging, basic analytics (pending count, top downloads), and audit logs.
* Storage: local filesystem `/uploads` (MVP); DB: MySQL; Backend: PHP 8.1 (PDO); Frontend: HTML/CSS/vanilla JS.

This SRS contains testable acceptance criteria, full DB DDL (database: `landoflearn_mvp`), explicit security rules (MIME whitelist, virus-scan guidance), refresh-token lifecycle and DDL, CLI examples, and developer templates. The SRS is approved for Design phase.

---

## 2. Introduction

### 2.1 Purpose

This Software Requirements Specification defines the requirements for LandOfLearn MVP and will be used as the authoritative artifact for the Waterfall Requirements phase. The SRS provides measurable acceptance criteria used by development and QA.

### 2.2 Intended audience

Project sponsor, development team, QA/testers, course instructor(s), and the project supervisor.

### 2.3 Definitions & abbreviations

* LandOfLearn — Project name.
* MVP — Minimum Viable Product.
* JWT — JSON Web Token.
* API — Application Programming Interface.
* DDL — Data Definition Language (SQL).
* DB — Database (MySQL).

---

## 3. Scope & Context

### 3.1 Scope (In / Out)

**In scope (MVP):**

* JWT authentication (access token 15m, refresh token 7d, rotation, revocation).
* Upload resources (file + metadata) by authenticated students.
* Single-step admin review workflow (approve/reject).
* Browse/search approved resources; filters: course, instructor, type, year, tag.
* Download approved resources: stream file, increment downloads, log activity.
* Tags and resource metadata (course, instructor).
* Logs and basic analytics in admin dashboard (pending count, top downloads).
* Local file storage under config-driven path (default `/var/www/landoflearn/uploads`).

**Out of scope (MVP):**

* Multi-level approvals, SSO, native mobile app, Elasticsearch, messaging/social features, production-grade scaling.

### 3.2 Context & architecture (high-level)

* Dev domain: `landoflearn.local`.
* Backend: PHP 8.1 (PDO).
* DB: MySQL 8.0 (recommended for FULLTEXT).
* Storage: Local filesystem (`LANDOFLEARN_UPLOAD_DIR`).
* Frontend: HTML, CSS, vanilla JS (fetch + Authorization header).
* Optional: ClamAV for file scanning in production.

---

## 4. Naming Conventions

Use these conventions consistently across all artifacts:

* **Project Short Name:** `LandOfLearn` (capitalized)
* **Dev domain:** `landoflearn.local`
* **DB name:** `landoflearn_mvp`
* **Env var prefix:** `LANDOFLEARN_` (e.g., `LANDOFLEARN_JWT_SECRET`)
* **DB tables:** `snake_case` (e.g., `resource_types`, `refresh_tokens`)
* **API paths:** kebab-case (e.g., `/admin/reviews/pending`)
* **JSON fields:** snake\_case (e.g., `access_token`, `refresh_token`)
* **Filenames in repo:** kebab-case or snake\_case (consistent per team preference)
* **Config keys:** uppercase `LANDOFLEARN_*`

Document these rules in the SRS and enforce in code, SQL, and OpenAPI specs.

---

## 5. Functional Requirements (FR) — Detailed with Acceptance Tests

Each MUST requirement below has a concrete acceptance test (precondition, request, expected HTTP code/JSON, DB/log assertions). Use these as test cases.

> **Defaults:** Access token expiry: **15 minutes**; Refresh expiry: **7 days**; Max upload: **200 MB**.

---

### FR-1 — Authentication (MUST)

**Description:** Provide JWT-based authentication.
**Endpoints:**

* `POST /api/auth/login` — credentials → returns `access_token` (JWT) and sets `scms_refresh`/`landoflearn_refresh` HttpOnly cookie.
* `POST /api/auth/refresh` — exchanges refresh cookie for new access token and rotates refresh token.
* `POST /api/auth/logout` — revokes refresh token.

**Acceptance test:**

1. Precondition: `users` row exists and password hashed.
2. Request:

```bash
curl -i -X POST "http://landoflearn.local/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@landoflearn.edu","password":"Secret123!"}'
```

3. Expected:

* HTTP 200 with JSON `{ "access_token": "<jwt>" }`.
* Response sets `Set-Cookie: landoflearn_refresh=<token>; HttpOnly; Path=/; SameSite=Strict; Secure` (Secure in HTTPS).
* `refresh_tokens` table has a new row for the issued token.

4. Authorization: protected endpoints require header `Authorization: Bearer <token>`. An invalid/expired token returns 401.

---

### FR-2 — Roles & RBAC (MUST)

**Description:** Enforce roles (`admin`, `student`, `guest`). Admin-only endpoints return 403 for non-admins.

**Acceptance test:**

* Call `GET /api/admin/reviews/pending` with a student token → expected HTTP 403 `{error:"forbidden"}`.
* DB check: `SELECT role_id FROM users WHERE id = <user_id>` returns appropriate id.

---

### FR-3 — Upload Resource (MUST)

**Description:** `POST /api/resources` accepts multipart `file` + required metadata `title`, `course_id`, `type_id`. Validates MIME, size (<=200MB), computes checksum, stores file under configured `LANDOFLEARN_UPLOAD_DIR`, inserts `resources` row with `status='pending'`.

**Acceptance test:**

1. Precondition: Student authenticated (valid access token).
2. Request:

```bash
curl -v -X POST "http://landoflearn.local/api/resources" \
  -H "Authorization: Bearer <access_token>" \
  -F "file=@/path/to/notes.pdf" \
  -F "title=Final Exam 2019" \
  -F "course_id=1" \
  -F "type_id=1" \
  -F "tags[]=exam" \
  -F "tags[]=final"
```

3. Expected:

* HTTP 201 with JSON `{ "resource_id": 123 }`.
* DB: `SELECT status, uploader_id, checksum FROM resources WHERE id = 123` → `status='pending'`, `uploader_id=<student id>`, `checksum` matches computed SHA256.
* File exists at path configured and `original_filename` preserved in DB.
* Log row inserted into `logs` with `action='upload'`.

**Edge cases:**

* Oversize (>200MB) → 413 `payload_too_large`.
* Unsupported MIME/extension → 415 `unsupported_media_type`.
* Duplicate checksum → 409 `conflict` with `existing_id` in response.

---

### FR-4 — Admin Review (MUST)

**Description:** Admin lists pending `GET /api/admin/reviews/pending`. Admin approves `POST /api/admin/reviews/{id}/approve` or rejects with optional note `/reject`.

**Acceptance test:**

1. Precondition: Admin authenticated; resource with `status='pending'`.
2. Request:

```bash
curl -X POST "http://landoflearn.local/api/admin/reviews/123/approve" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"note":"OK"}'
```

3. Expected:

* HTTP 200; `resources.status` becomes `'approved'`.
* `logs` contains action `'approve'` with `user_id=<admin>`.
* Approved resource appears in `GET /api/resources` results.

---

### FR-5 — Browse & Search (MUST)

**Description:** `GET /api/resources` returns paginated approved resources. Filters: `course_id`, `instructor_id`, `type_id`, `year`, `tag`. Query param `q` searches title+description (case-insensitive, partial matches). Pagination via `page`, `per_page`.

**Acceptance test:**

* Request: `GET /api/resources?q=exam&course_id=1&per_page=20&page=1`
* Expected: HTTP 200 JSON with `items:[]`, `meta:{total,page,per_page}`; all items `status='approved'`; P95 response < 2s on test environment.

---

### FR-6 — Download (MUST)

**Description:** `GET /api/resources/{id}/download` streams file if `status='approved'`, increments `downloads` atomically, logs the download.

**Acceptance test:**

* GET request returns file with proper `Content-Type` and `Content-Disposition`, DB `downloads` incremented, and `logs` has `action='download'` with `user_id` or NULL for guests.

---

### FR-7 — Tags (SHOULD)

**Acceptance test:** Resources created with tags appear when queried via `GET /api/resources?tag=algorithms`.

---

### FR-8 — Logs & Analytics (SHOULD)

**Acceptance test:** `GET /api/admin/analytics` returns `pending_count` and `top_downloads` reflecting DB.

---

### FR-9 — Duplicate detection (MAY)

**Acceptance test:** Upload file with same SHA256 checksum yields 409 with existing resource id.

---

## 6. Refresh Token Lifecycle & DDL

**Goals:** Secure rotation & revocation of refresh tokens; support per-device/session tokens; enable logout & admin revocation.

**Rules & behaviors:**

* Refresh tokens are long random strings (≥64 bytes hex) issued as cookies `landoflearn_refresh` (HttpOnly).
* On `POST /api/auth/refresh`, server validates token, issues new access token, **rotates** the refresh token (creates new token, revokes old).
* On logout, revoke the refresh token in DB.
* Allow multiple refresh tokens per user (distinct sessions). Admin can revoke tokens.
* For production, store only a hashed fingerprint of refresh token (e.g., SHA256) and compare hashes; for MVP storing token value is acceptable but marked TODO to change.

**DDL (MySQL) for refresh tokens:**
(Part of `schema_mysql.sql` in Section 9.)

```sql
CREATE TABLE refresh_tokens (
  token CHAR(128) NOT NULL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked TINYINT(1) NOT NULL DEFAULT 0,
  ip VARCHAR(45),
  user_agent VARCHAR(255),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Implementation notes:**

* Rotate on refresh: T1 → T2; set `revoked=1` for T1 and insert T2.
* On token reuse detection (presentation of revoked token), treat as suspicious: revoke all tokens for user and require re-login (security policy optional).

---

## 7. Security Requirements (explicit)

### 7.1 Password & account policy

* Passwords hashed using `password_hash()` (BCRYPT/Argon2).
* Password policy: minimum length 8, at least one letter and one digit (stronger policy recommended for production).

### 7.2 JWT & token policy

* Access token expiry: 15m. Refresh token expiry: 7d.
* JWT secret configured via `LANDOFLEARN_JWT_SECRET`. Rotate keys per policy.

### 7.3 CORS & CSRF

* CORS: restrict to allowed origins (`http://landoflearn.local` dev); configure env `LANDOFLEARN_ALLOWED_ORIGINS`.
* CSRF: since refresh uses HttpOnly cookie, mitigate by SameSite and refresh rotation. For state-changing endpoints using cookies, add CSRF tokens if applicable.

### 7.4 Rate-limiting & brute-force protections

* Auth endpoints: limit **10 requests/minute per IP**.
* Login lockout: **5 failed attempts per 15 minutes → lock 15 minutes**. Use simple in-memory or file store for MVP; Redis preferred.

### 7.5 Upload restrictions & virus scanning

* Max file size: `LANDOFLEARN_MAX_FILE_SIZE` (default `200M`).
* MIME & extension whitelist (server-level + application check):

  * Documents: `application/pdf`, `application/msword`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `application/vnd.ms-powerpoint`, `application/vnd.openxmlformats-officedocument.presentationml.presentation`
  * Archives: `application/zip`
  * Images: `image/jpeg`, `image/png`
  * Audio/Video: `audio/mpeg`, `video/mp4`
  * Text: `text/plain`
* Reject mismatched MIME/extension combos.
* Virus scan: MVP code includes ClamAV scan hook (`clamdscan`/`clamscan`) with clear TODO if ClamAV unavailable in dev environment. If infected, return `422 Unprocessable Entity`.

### 7.6 File storage & path rules

* Files stored **outside** webroot; use generated random filenames, keep `original_filename` in DB.
* File path in DB is relative to `LANDOFLEARN_UPLOAD_DIR`.
* Ensure proper ownership and permission settings.

### 7.7 Logging & audit

* `logs` table fields: `id, created_at (UTC), user_id (nullable), action, target_table, target_id, ip, user_agent, notes`.
* Keep logs for **180 days**.

### 7.8 TLS

* Enforce TLS in production. For dev, self-signed acceptable but set cookie `Secure` only on HTTPS.

---

## 8. Takedown & Retention Policy

### 8.1 Takedown request flow & SLA

1. Submit via `POST /api/admin/takedown` with `resource_id` and reason.
2. System acknowledges to claimant.
3. Admin reviews and acts within **72 hours** (SLA).
4. If valid, mark resource `status='removed'`, archive the file (move to `archive/`) and notify uploader & claimant. Log all actions.

### 8.2 Retention

* **Live storage:** approved resources remain available unless removed by takedown/legal action.
* **Backups:** file backups retained **180 days**. DB dumps retained **90 days**.
* **Archive on takedown:** keep for 180 days by default, then delete automatically unless legal hold.

---

## 9. Database DDL (`schema_mysql.sql`) & Indexing Strategy

Save the following as `schema_mysql.sql`. Database name is `landoflearn_mvp`.

> Note: run on MySQL 5.7+/8.0.

```sql
-- schema_mysql.sql
CREATE DATABASE IF NOT EXISTS landoflearn_mvp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE landoflearn_mvp;

-- Roles
CREATE TABLE roles (
  id TINYINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(32) NOT NULL UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO roles (id, name) VALUES (1,'admin'), (2,'student'), (3,'guest')
  ON DUPLICATE KEY UPDATE name=VALUES(name);

-- Users
CREATE TABLE users (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role_id TINYINT UNSIGNED NOT NULL DEFAULT 2,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL,
  INDEX idx_role (role_id),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Refresh tokens
CREATE TABLE refresh_tokens (
  token CHAR(128) NOT NULL PRIMARY KEY,
  user_id BIGINT UNSIGNED NOT NULL,
  issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  revoked TINYINT(1) NOT NULL DEFAULT 0,
  ip VARCHAR(45),
  user_agent VARCHAR(255),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Instructors
CREATE TABLE instructors (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(150) NOT NULL,
  email VARCHAR(255) NULL,
  department VARCHAR(100) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Batches / years
CREATE TABLE batches (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  year SMALLINT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Courses
CREATE TABLE courses (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(32) NOT NULL,
  name VARCHAR(255) NOT NULL,
  level VARCHAR(32),
  semester VARCHAR(32),
  batch_id INT UNSIGNED,
  instructor_id INT UNSIGNED,
  FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE SET NULL,
  FOREIGN KEY (instructor_id) REFERENCES instructors(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Resource types
CREATE TABLE resource_types (
  id TINYINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(64) NOT NULL UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO resource_types (id,name) VALUES
  (1,'Exam'),(2,'Lecture Notes'),(3,'Slides'),(4,'Research Paper'),(5,'Project'),(6,'Book'),(7,'Video')
ON DUPLICATE KEY UPDATE name=VALUES(name);

-- Tags
CREATE TABLE tags (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Resources
CREATE TABLE resources (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(512) NOT NULL,
  description TEXT,
  type_id TINYINT UNSIGNED NOT NULL,
  file_path VARCHAR(1024) NOT NULL,
  original_filename VARCHAR(512),
  checksum CHAR(64) NOT NULL,
  uploader_id BIGINT UNSIGNED NOT NULL,
  course_id INT UNSIGNED,
  instructor_id INT UNSIGNED,
  year SMALLINT UNSIGNED,
  status ENUM('pending','approved','rejected','removed') NOT NULL DEFAULT 'pending',
  downloads INT UNSIGNED NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NULL DEFAULT NULL,
  FOREIGN KEY (type_id) REFERENCES resource_types(id) ON DELETE RESTRICT,
  FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE SET NULL,
  FOREIGN KEY (course_id) REFERENCES courses(id) ON DELETE SET NULL,
  FOREIGN KEY (instructor_id) REFERENCES instructors(id) ON DELETE SET NULL,
  INDEX idx_status (status),
  INDEX idx_course (course_id),
  INDEX idx_type (type_id),
  INDEX idx_checksum (checksum),
  FULLTEXT INDEX ft_title_desc (title, description)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Resource <-> Tag mapping
CREATE TABLE resource_tags (
  resource_id BIGINT UNSIGNED NOT NULL,
  tag_id INT UNSIGNED NOT NULL,
  PRIMARY KEY (resource_id, tag_id),
  FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Logs / audit
CREATE TABLE logs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  user_id BIGINT UNSIGNED,
  action VARCHAR(64) NOT NULL,
  target_table VARCHAR(64),
  target_id BIGINT UNSIGNED,
  ip VARCHAR(45),
  user_agent VARCHAR(255),
  notes TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_action (action),
  INDEX idx_target (target_table, target_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

**Indexing strategy (rationale):**

* `status` indexed for fast `approved` filtering.
* `course_id`, `type_id` indexed for filter queries.
* `checksum` indexed for duplicate detection.
* `FULLTEXT` on `title,description` enables efficient text search on MySQL 5.7/8.0.

---

## 10. Seed Guidance & `.env.example`

### 10.1 `.env.example`

Create `.env` from `.env.example`. **Do not commit `.env`**.

```dotenv
# .env.example (copy to .env and update)
LANDOFLEARN_DB_HOST=127.0.0.1
LANDOFLEARN_DB_NAME=landoflearn_mvp
LANDOFLEARN_DB_USER=root
LANDOFLEARN_DB_PASS=secret
LANDOFLEARN_JWT_SECRET=change_me_in_prod
LANDOFLEARN_UPLOAD_DIR=/var/www/landoflearn/uploads
LANDOFLEARN_MAX_FILE_SIZE=200M
LANDOFLEARN_ALLOWED_ORIGINS=http://landoflearn.local
LANDOFLEARN_ADMIN_EMAIL=alzamzamiMAM@alzamzami.edu
# For seeding locally only; set and then unset.
LANDOFLEARN_ADMIN_PASS=ChangeMe123
```

### 10.2 `seed_admin.php` (env-driven) — run locally

See Appendix B for the script. Recommended use:

```bash
LANDOFLEARN_ADMIN_EMAIL=alzamzamiMAM@alzamzami.edu \
LANDOFLEARN_ADMIN_PASS=A1-2am2ami \
php seed_admin.php
```

**Security note:** Immediately change admin password after first login. Do not commit real secrets to repository.

---

## 11. API Errors & Responses (Standard)

All errors use JSON with this structure:

```json
{
  "error": "error_code",
  "message": "Human readable message",
  "details": { "field": "reason" }  // optional
}
```

Common responses:

* `200 OK` — success
* `201 Created` — resource created
* `400 Bad Request` — missing/invalid parameters
* `401 Unauthorized` — missing/invalid access token
* `403 Forbidden` — role/ACL violation
* `404 Not Found` — resource missing
* `409 Conflict` — duplicate resource (includes `existing_id`)
* `415 Unsupported Media Type` — file MIME rejected
* `413 Payload Too Large` — file too big
* `422 Unprocessable Entity` — infected file / validation errors
* `429 Too Many Requests` — rate-limited
* `500 Internal Server Error` — unexpected

Examples:

```json
{ "error": "unauthorized", "message": "Access token missing or invalid." }
{ "error": "conflict", "message": "Duplicate resource", "existing_id": 55 }
{ "error": "infected_file", "message": "Uploaded file failed virus scan." }
```

---

## 12. Non-functional Requirements & Performance Test Environment

### 12.1 NFR Targets

* **Performance:** P95 page load/search latency < 2s for up to 10k resources on recommended dev VM.
* **Reliability / Backup:** DB dump daily; file backups weekly; RPO ≤ 24h; RTO ≤ 4h (demo/dev).
* **Accessibility:** WCAG 2.1 AA baseline for forms & primary flows.
* **Security:** enforce TLS in production; rotate JWT secret regularly; follow OWASP recommendations.

### 12.2 Test environment (recommended)

* CPU: 4 vCPU; RAM: 8 GB; Disk: SSD; OS: Ubuntu 22.04; MySQL 8.0; PHP-FPM 8.1; Nginx.
* Load testing tooling: `ab`, `wrk`, or `k6`. Example:

```bash
ab -n 1000 -c 50 "http://landoflearn.local/api/resources?q=exam"
```

* Measure P95 latency for sample queries.

---

## 13. Change Control & SRS Sign-off Process

**Change control:** After sign-off any MUST requirement change requires a formal change request listing: description, rationale, impact on timeline & scope. Track changes in `SRS_change_log.md`.

**Sign-off steps:**

1. Student updates SRS; adds ChangeLog entries mapping to requested items.
2. Supervisor reviews within 24–48 hours.
3. On approval, supervisor signs SRS using the Sign-off template (Appendix D).
4. Proceed to Design.

---

## 14. Acceptance Checklist (for Supervisor / QA)

Before sign-off confirm the following (mark as done and reference SRS sections):

* [ ] Acceptance tests present for each MUST FR (Section 5).
* [ ] Refresh token DDL & lifecycle documented (Section 6).
* [ ] Security requirements explicit (Section 7).
* [ ] Takedown & retention policy clarified (Section 8).
* [ ] DDL for core tables included (Section 9).
* [ ] `.env.example` and seed guidance included (Section 10).
* [ ] API error table present (Section 11).
* [ ] Test environment specified for performance NFR (Section 12).
* [ ] Change control section present (Section 13).
* [ ] Sample seed data and admin seeding instructions included (Section 10).

---

## 15. Appendices

### Appendix A — Sample curl requests

**Login**

```bash
curl -i -X POST "http://landoflearn.local/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"alzamzamiMAM@landoflearn.edu","password":"A1-2am2ami"}'
```

**Refresh**

```bash
curl -i -X POST "http://landoflearn.local/api/auth/refresh" --cookie "landoflearn_refresh=<token>"
```

**Upload**

```bash
curl -v -X POST "http://landoflearn.local/api/resources" \
  -H "Authorization: Bearer <access_token>" \
  -F "file=@/home/user/notes.pdf" \
  -F "title=Exam 2019" \
  -F "course_id=1" \
  -F "type_id=1" \
  -F "tags[]=exam" \
  -F "tags[]=final"
```

**Approve**

```bash
curl -X POST "http://landoflearn.local/api/admin/reviews/123/approve" \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"note":"Approved"}'
```

---

### Appendix B — `seed_admin.php` (env-driven example)

```php
<?php
// seed_admin.php
// Usage:
// LANDOFLEARN_ADMIN_EMAIL=alzamzamiMAM@landoflearn.edu \
// LANDOFLEARN_ADMIN_PASS=A1-2am2ami \
// php seed_admin.php

require __DIR__ . '/includes/db.php'; // $pdo (PDO) configured to use LANDOFLEARN env vars

$email = getenv('LANDOFLEARN_ADMIN_EMAIL') ?: null;
$pass  = getenv('LANDOFLEARN_ADMIN_PASS') ?: null;

if (!$email || !$pass) {
    echo "Set LANDOFLEARN_ADMIN_EMAIL and LANDOFLEARN_ADMIN_PASS environment variables.\n";
    exit(1);
}

$hash = password_hash($pass, PASSWORD_DEFAULT);

$stmt = $pdo->prepare('INSERT INTO users (name, email, password_hash, role_id, created_at) VALUES (?,?,?,?,NOW()) ON DUPLICATE KEY UPDATE email=email');
$stmt->execute(['Admin', $email, $hash, 1]);

echo "Admin seeded: $email\n";
```

**Note:** After seeding, login and change the password; do not commit `.env` or admin creds.

---

### Appendix C — `PULL_REQUEST_TEMPLATE.md` & `CONTRIBUTING.md`

**`PULL_REQUEST_TEMPLATE.md`**

```markdown
### Summary
- Brief summary of change and related issue/ticket

### Checklist
- [ ] Code compiles / runs locally
- [ ] Tests added / updated
- [ ] DB migrations included (if any)
- [ ] Documentation updated (README / SRS)
- [ ] No secrets committed (.env removed)
```

**`CONTRIBUTING.md`**

```markdown
# Contributing to LandOfLearn

## Branching
- main = stable
- dev = integration
- feature/* = feature branches

## Local setup
1. Copy `.env.example` to `.env` and update.
2. Run `composer install`.
3. Run DB migrations: `mysql -u ... < schema_mysql.sql`
4. Seed admin (env-driven): `LANDOFLEARN_ADMIN_EMAIL=... LANDOFLEARN_ADMIN_PASS=... php seed_admin.php`

## Commit message style
- Use Conventional Commits: `feat:`, `fix:`, `docs:`, etc.

## Security
- Never commit `.env` or secrets.
- Use `LANDOFLEARN_*` env vars for config.
```

---

### Appendix D — Sign-off template

```
SRS Approval — LandOfLearn (MVP)

I, [Supervisor Name], have reviewed the Software Requirements Specification v1.2 for LandOfLearn (MVP).
The required revisions have been applied and verified.

Decision: Approved.

Signature: _____________________
Name: [Supervisor Name]
Title: [Title]
Date: [YYYY-MM-DD]
```

---

## Final notes & next steps

LandOfLearn SRS v1.2 is updated with naming conventions, `.env` recommendations, safer seeding, explicit security and refresh token lifecycle, full DB DDL (`landoflearn_mvp`), acceptance tests per FR, and templates for contribution.

**Recommended next action (Design phase):**
Type one of the options below and I’ll produce those artifacts:

* `Proceed: Design (ERD + OpenAPI)` — I will produce PlantUML ERD + ASCII rendering and a complete OpenAPI 3.0 YAML for the API.
* `Proceed: Backend skeleton (PHP/PDO + docker-compose)` — produce a downloadable PHP skeleton with endpoints and minimal tests.
* `Proceed: Frontend mockups` — produce responsive HTML/CSS/JS snippets and wireframes.
* `Proceed: All` — do ERD + OpenAPI then backend skeleton then frontend mockups (longer deliverable).

If you want any text edits in the SRS above before moving to Design, tell me which sections and I’ll update immediately.

