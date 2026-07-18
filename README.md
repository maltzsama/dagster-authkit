# 🛡️ Dagster AuthKit

[![Python Version](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12%20|%203.13%20|%203.14-blue.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Build Status](https://github.com/maltzsama/dagster-authkit/workflows/CI/badge.svg)](https://github.com/maltzsama/dagster-authkit/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg?logo=open-source-initiative&logoColor=white)](https://opensource.org/licenses/Apache-2.0)
[![Coverage](https://codecov.io/gh/maltzsama/dagster-authkit/branch/main/graph/badge.svg)](https://codecov.io/gh/maltzsama/dagster-authkit)
[![PyPI Version](https://img.shields.io/pypi/v/dagster-authkit?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/dagster-authkit/)
[![Downloads](https://img.shields.io/pypi/dm/dagster-authkit?logo=pypi&logoColor=white)](https://pypi.org/project/dagster-authkit/)

**Community authentication wrapper for self-hosted Dagster OSS.**

*Authentication, RBAC, and Audit logs for Dagster without touching internal code.*

---

## 🎯 What is this?

Dagster OSS has no auth. If you run it in a VPC or locally, anyone with the URL has full admin access.

**AuthKit solves this by wrapping the `dagster-webserver` command to add:**

* ✅ **Login Interface:** Simple username/password flow.
* ✅ **RBAC (4 Levels):** Granular control over who can do what.
* ✅ **Audit Logs:** JSON logs for monitoring who is doing what.
* ✅ **Multi-Backend:** Works with SQLite, Postgres, MySQL (via Peewee ORM) and Redis.

**No code changes required.** You don't touch your `repository.py` or `dagster.yaml`.

---

## ✨ What's New in v0.4.0

### 🔐 Security Hardening (Breaking Changes)
- **`SECRET_KEY` is now required in production.** The server will refuse to start if `DAGSTER_AUTH_SECRET_KEY` is not set and `DAGSTER_AUTH_ENV=production`. Auto-generated keys caused silent session breakage in multi-pod deployments.
- **Proxy mode now requires trusted IPs.** Set `DAGSTER_AUTH_PROXY_TRUSTED_IPS` (comma-separated) or explicitly opt into the insecure default with `DAGSTER_AUTH_PROXY_TRUST_ALL=true`.
- **RBAC is now deny-by-default for unknown mutations.** New GraphQL mutations added by future Dagster releases require `ADMIN` role until explicitly audited. Configure via `DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE`.

### 🔄 Cross-Pod Session Revocation
- **DB-backed `session_version` column.** `change_password`, `change_role`, and `delete_user` now invalidate sessions across ALL pods without Redis. A new `session_version` column is automatically added to existing databases on upgrade.
- **Dual rate-limiting** (username + IP). Prevents both credential stuffing and brute-force on a single account.

### 🛡️ Attack Surface Reduction
- **CSRF protection** on the login form (double-submit signed cookie).
- **WebSocket authentication** — GraphQL subscriptions at `/graphql` are now authenticated (pure ASGI middleware).
- **XSS prevention** in login and 403 pages via HTML escaping.
- **Open redirect hardening** — protocol-relative URLs (`//evil.com`) are blocked.
- **Empty password rejection** across all backends (prevents unauthenticated LDAP binds).

### 🏗️ Core Improvements
- **`operationName` support in GraphQL RBAC.** Clients sending multiple operations in one document no longer trigger false-positive blocks.
- **Backend instance caching.** Backend connections are reused across requests instead of being recreated per call.
- **Unified role serialization.** `to_dict()` now uses `role.value` (int) for cross-backend consistency.

---

## ⚠️ Upgrading from v0.3.x

1. **Set `DAGSTER_AUTH_SECRET_KEY`** in your environment. Generate one with:
   ```bash
   python -c 'import secrets; print(secrets.token_urlsafe(32))'
   ```
2. **If using proxy mode**, set `DAGSTER_AUTH_PROXY_TRUSTED_IPS` to your proxy's IP address.
3. **Database migration** happens automatically on first boot — no manual steps needed for SQLite/Postgres/MySQL. A `session_version` column is added to the `users` table.
4. **Role serialization** changed from string (`"ADMIN"`) to int (`40`) in session cookies. Existing sessions continue to work (backward-compatible `from_dict`).

---

## 📂 Ready-to-Run Examples

We provide ready-to-use stacks for different scenarios in the `examples/` directory:

```bash
examples
├── authelia              # NEW! Authelia + Caddy + LDAP SSO (Docker)
│   ├── Makefile
│   ├── docker-compose.yml
│   ├── Caddyfile
│   └── authelia/
├── kubernetes            # NEW! Minikube deployment
│   ├── Makefile
│   └── k8s/
├── ldap                  # Active Directory integration (**Experimental**)
│   ├── Makefile
│   ├── docker-compose.yml
│   └── ldap-bootstrap.ldif
├── postgresql_redis      # Recommended production setup
│   ├── Makefile
│   └── docker-compose.yml
└── quickstart-sqlite     # Simple local testing
    ├── Makefile
    └── docker-compose.yml
```

### How to run

Pick a scenario, go into the folder, and check the `Makefile`.

**1. Authelia SSO (Docker)**
Complete SSO with Authelia, Caddy, and OpenLDAP:
```bash
cd examples/authelia
make up
# Access: https://auth.company.com (admin/password123)
# Then:   https://dagster.company.com
```

**2. Kubernetes (Minikube)**
Same stack running on Kubernetes:
```bash
cd examples/kubernetes
make build  # Build the Docker image inside Minikube
make up     # Deploy everything
# In another terminal: make connect (runs minikube tunnel)
# Add to /etc/hosts: $(minikube ip) auth.company.com dagster.company.com
```

**3. Standard Setup (Postgres + Redis)**
```bash
cd examples/postgresql_redis
make up
```

**4. Local Quickstart (SQLite)**
```bash
cd examples/quickstart-sqlite
make up
```

**5. LDAP/AD Testing** ⚠️ **EXPERIMENTAL**
```bash
cd examples/ldap
make up
```

---

## 🚀 Manual Installation (Python)

If you aren't using Docker, you can install via pip.

```bash
# For local testing (SQLite)
pip install dagster-authkit[sqlite]

# For server usage (Postgres + Redis recommended)
pip install dagster-authkit[postgresql,redis]

# For LDAP/Active Directory integration (**Experimental**)
pip install dagster-authkit[ldap]

```

**Usage:**

```bash
# Initialize the database and create the first admin
dagster-authkit init-db --with-admin

# Run Dagster (replaces the standard 'dagster-webserver' command)
dagster-authkit -f your_pipeline.py -h 0.0.0.0 -p 3000

# For proxy mode (Authelia/OAuth2 Proxy)
export DAGSTER_AUTH_BACKEND=proxy
export DAGSTER_AUTH_PROXY_LOGIN_URL=https://auth.yourcompany.com
dagster-authkit -f your_pipeline.py -h 0.0.0.0 -p 3000
```

### ☸️ Helm (Kubernetes)

Deploy on Kubernetes via the Helm chart in [`helm/dagster-authkit/`](./helm/dagster-authkit/):

```bash
helm upgrade --install dagster-authkit ./helm/dagster-authkit \
  --set authkit.secretKey="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  --set authkit.adminPassword="your-admin-password"
```

See [`values.yaml`](./helm/dagster-authkit/values.yaml) for all configuration options.

---

## 🔐 Roles (RBAC)

We provide **4 levels** of access. Permissions are enforced via GraphQL query analysis.

| Role | Description |
|------|-------------|
| **Admin** | Full access. Can manage users, settings, and all pipelines. |
| **Editor** | Can modify assets and codebase (if allowed) and manage runs. |
| **Launcher** | Can launch runs and re-execute jobs, but cannot modify code/assets. |
| **Viewer** | Read-only. Can view runs and assets. GraphQL mutations are blocked. |

**How it works:** AuthKit analyzes GraphQL queries using the official GraphQL parser to accurately identify mutations and block unauthorized actions.

---

## 📦 Backends

| Backend | Implementation | Status | Use Case |
|---------|---------------|--------|----------|
| **SQLite** | Peewee ORM | **Stable** | Local / Simple. Single instance only. |
| **PostgreSQL** | Peewee + `psycopg2` | **Stable** | Production. Recommended for Docker/K8s. |
| **MySQL/MariaDB** | Peewee + `mysql-connector` | **Stable** | Production. |
| **Redis** | Native `redis` | **Stable** | Session Storage + Distributed Rate Limiting. |
| **LDAP** | `ldap3` library | **Experimental** | Active Directory / OpenLDAP. Community maintained. |
| **Proxy** | Header-based | **Stable** | Authelia, OAuth2 Proxy, Traefik, Caddy. |
| **OpenID Connect**| Header-based | **Experimental** | AuthKit supports OIDC providers (Google, GitHub, Okta, Keycloak) via **Authelia**| 
---

## 🛠️ CLI Management

Manage users directly from the shell. Useful for CI/CD or admin tasks.

```bash
# Create a new launcher
dagster-authkit add-user bob --launcher

# Reset password
dagster-authkit change-password bob

# List everyone
dagster-authkit list-users

# View RBAC permissions matrix
dagster-authkit list-permissions
```

---

## 🔮 Roadmap

### Current (v0.4.0)

* ✅ Username/password auth (bcrypt)
* ✅ 4-level RBAC (ADMIN/EDITOR/LAUNCHER/VIEWER)
* ✅ SQLite, PostgreSQL, MySQL, Redis support
* ✅ GraphQL mutation blocking with official AST parser
* ✅ LDAP backend (experimental)
* ✅ Proxy authentication (Authelia, Caddy, Traefik)
* ✅ Kubernetes example with full SSO stack
* ✅ Redis session revocation and rate limiting
* ✅ Centralized UI templates
* ✅ CSRF protection
* ✅ Cross-pod session revocation (DB-backed `session_version`)
* ✅ WebSocket authentication (GraphQL subscriptions)
* ✅ Dual rate-limiting (username + IP)
* ✅ Proxy trusted IP allowlist

### Next

* ☸️ Helm chart for Kubernetes deployments (preview — available in `helm/`)
* 🔄 OIDC backend (beyond proxy mode)

**What we will NOT do:**

* ❌ Inject React code into Dagster UI (too brittle)
* ❌ Complex enterprise features (that's what Dagster+ is for)

---

## 🤝 Contributing

Found a bug? Want to add a feature?
Open a PR. If it works and keeps things simple, we'll merge it.

**Especially needed:**

- People with Active Directory experience to validate the LDAP backend
- Testing on different Dagster versions
- Helm chart contributions

---

## 📄 License

Apache 2.0 - see [LICENSE](LICENSE)

---

## 🙏 Credits

Built by [Demetrius Albuquerque](https://github.com/demetrius-mp) because self-hosting Dagster shouldn't mean no auth.

Inspired by the community's need for a middle ground between "no auth" and "pay for Dagster+".