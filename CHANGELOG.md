# Changelog

All notable changes to dagster-authkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0](https://www.google.com/search?q=%5Bhttps://github.com/demetrius-mp/dagster-authkit/compare/v0.1.0...v0.2.0%5D(https://github.com/demetrius-mp/dagster-authkit/compare/v0.1.0...v0.2.0)) - 2026-01-28

### 🚀 Major Changes

**Multi-Backend Support (SQL & Redis)**

* Added **Peewee ORM** support, enabling connection to **PostgreSQL**, **MySQL**, and **MariaDB**.
* Added **Redis** backend for production-grade session storage (fixes the issue of logouts on server restart).
* Introduced `DAGSTER_AUTH_DB_CONNECTION_URL` for flexible database configuration.

**LDAP Integration (Experimental)**

* Added `ldap3` based backend for Active Directory/LDAP integration.
* *Note: Marked as Experimental/Alpha pending community validation.*

**Refined RBAC (4 Levels)**

* **New Role:** Added `LAUNCHER` role.
* **Updated Hierarchy:**
1. **Admin:** Full control.
2. **Editor:** Can edit code/assets and manage runs.
3. **Launcher:** Can launch/retry runs but cannot modify code/assets (New).
4. **Viewer:** Read-only access (GraphQL mutations blocked).



### ✨ Enhancements

**Health & Observability**

* **Fixed:** `/auth/health` and `/auth/metrics` endpoints were previously returning 404 due to middleware misconfiguration. They are now intercepted correctly.
* Health checks now return status for the specific backend in use (SQL, Redis, or LDAP).

**Developer Experience**

* Added `examples/` directory with ready-to-use Docker Compose stacks:
* `quickstart-sqlite`: Zero config.
* `postgresql_redis`: Production reference architecture.
* `ldap`: Local OpenLDAP testing setup.


* Added `Makefile` in example directories for easy startup (`make up`).

### 🐛 Bug Fixes

* **Middleware Dispatch:** Fixed a critical bug where `call_next` was invoked for internal endpoints (`/auth/health`), causing Dagster to return 404.
* **Dependency Management:** Clarified optional dependencies in `pyproject.toml` (install via `[postgresql]`, `[redis]`, etc).

### ⚠️ Breaking Changes

* **Project Status:** Downgraded status label from "General Availability" to **BETA**. Use in production at your own risk.
* **RBAC Logic:** Existing users in database might need role migration if custom roles were manually hacked (standard roles map automatically).

---

## [0.1.0](https://www.google.com/search?q=%5Bhttps://github.com/demetrius-mp/dagster-authkit/releases/tag/v0.1.0%5D(https://github.com/demetrius-mp/dagster-authkit/releases/tag/v0.1.0)) - 2026-01-25

### 🎉 Initial Release

First working version of dagster-authkit - community authentication for Dagster OSS.

### ✨ Features

**Authentication System**
- SQLite-based authentication backend with bcrypt password hashing
- Login/logout pages with clean UI
- Session management using cryptographically signed cookies (itsdangerous)
- Rate limiting for brute-force protection (5 attempts per 5 minutes)
- Automatic session expiration (24h default, configurable)

**Role-Based Access Control (RBAC)**
- Three roles: admin, editor, viewer
- GraphQL mutation detection and blocking for non-editors
- Proper error responses that stop UI loading states
- Viewer role can see everything but cannot modify (read-only)

**User Management CLI**
- `dagster-authkit init-db` - Initialize database with optional admin user
- `dagster-authkit add-user` - Add users with roles
- `dagster-authkit list-users` - List all users
- `dagster-authkit change-password` - Change user passwords
- `dagster-authkit delete-user` - Soft-delete users

**Audit Logging**
- Structured JSON audit logs to stdout
- Tracks: login attempts, logout, access control decisions, password changes, user management
- Ready for log aggregation systems (Datadog, Splunk, CloudWatch, ELK)

**Security Features**
- Bcrypt password hashing with SHA-256 pre-hash (prevents BCrypt 72-byte limit issues)
- Constant-time password comparison (timing attack prevention)
- Security headers: X-Frame-Options, CSP, X-Content-Type-Options
- Open redirect protection
- Username sanitization
- CSRF token generation (foundation for future CSRF protection)

**Monkey-Patching System**
- Dagster API compatibility detection layer
- Non-invasive middleware injection (first layer in ASGI stack)
- Route injection for /auth/* endpoints
- UI injection - user menu in Dagster sidebar with username, role, and logout

**Health & Monitoring**
- `/auth/health` - Unified health check endpoint
- `/auth/health?type=live` - Kubernetes liveness probe
- `/auth/health?type=ready` - Kubernetes readiness probe
- `/auth/metrics` - Basic metrics (login attempts, uptime, etc.)

**Docker/Kubernetes Support**
- Admin user bootstrap via environment variables
- `DAGSTER_AUTH_ADMIN_USER`, `DAGSTER_AUTH_ADMIN_PASSWORD` for IaC deployments
- Automatic database initialization on first run

### 🏗️ Architecture

**Modular Structure**
- `dagster_authkit/core/` - Core patching and middleware
- `dagster_authkit/auth/` - Authentication backends and security
- `dagster_authkit/api/` - Routes and health checks
- `dagster_authkit/cli/` - User management CLI
- `dagster_authkit/utils/` - Config, audit, logging

**Plugin System**
- Backend discovery via setuptools entry points
- Easy to add custom backends without modifying core code
- Dummy backend for development (admin/admin, editor/editor, viewer/viewer)

### 📦 Dependencies

**Core**
- `dagster>=1.10.0,<2.0.0`
- `dagster-webserver>=1.10.0,<2.0.0`
- `starlette>=0.27.0`
- `itsdangerous>=2.1.0`
- `python-multipart>=0.0.6`

**Optional**
- `bcrypt>=4.0.0` - For SQLite backend

### 🐛 Known Issues

- **Monkey-patching fragility** - May break across Dagster versions (tested on 1.10-1.12)
- **In-memory rate limiting** - Does not work across multiple instances (use Redis for distributed)
- **GraphQL mutation detection** - Regex-based, may have edge cases
- **No fine-grained permissions** - Only 3 roles (admin/editor/viewer)
- **LDAP backend** - Stub only, not implemented
- **OAuth backend** - Stub only, not implemented

### 📝 Documentation

- README.md with quick start guide
- Inline code documentation (docstrings)
- CLI help messages (`dagster-authkit --help`)

### 🔧 Configuration

All configuration via environment variables:
- Session management (SECRET_KEY, SESSION_MAX_AGE, cookie settings)
- Backend selection (AUTH_BACKEND)
- Rate limiting (RATE_LIMIT_*, configurable attempts/window)
- Audit logging (AUDIT_LOG_ENABLED)
- Admin bootstrap (ADMIN_USER, ADMIN_PASSWORD)

### ⚠️ Breaking Changes

N/A - Initial release

---

## [Unreleased]

### Planned Features
- LDAP/Active Directory backend implementation
- OAuth 2.0 backend implementation (Google, Azure AD, Okta)
- CSRF protection for login forms
- Multi-instance support (Redis-based rate limiting and sessions)
- More granular permissions (resource-level access control)
- Password reset flow
- User self-service (change own password)
- Admin UI for user management (web-based)

---

[0.1.0]: https://github.com/demetrius-mp/dagster-authkit/releases/tag/v0.1.0