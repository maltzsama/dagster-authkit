# 🛡️ Dagster AuthKit

<div align="center">

**Community authentication wrapper for self-hosted Dagster OSS.**

*Authentication, RBAC, and Audit logs for Dagster without touching internal code.*

</div>

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

## ✨ What's New in v0.3.0

### 🔐 Proxy Authentication Mode
Delegate authentication to enterprise identity providers via reverse proxy:
- **Authelia** integration with complete examples
- **Caddy** reverse proxy with built-in `forward_auth` directive
- **Traefik** forward auth support
- Header-based user extraction (`Remote-User`, `Remote-Groups`)
- Smart group parser that handles JSON, LDAP DNs, CSV, and mixed formats

### 🚀 Kubernetes Deployment
Full example stack for Minikube including:
- OpenLDAP with pre-seeded users and RBAC groups
- Authelia configured with LDAP backend
- Caddy as reverse proxy with TLS termination
- Dagster-AuthKit in proxy mode
- Step-by-step Makefile with `minikube tunnel` support

### 🏗️ Core Improvements
- **GraphQL parsing:** Replaced fragile regex with official AST parser (`graphql-core`)
- **Redis hardening:** Atomic operations, proper session revocation, URL validation
- **Code organization:** All UI templates centralized in `utils/templates.py`
- **Observability:** RBAC decision tracking via metrics endpoint

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
dagster-authkit add-user bob --role launcher

# Reset password
dagster-authkit change-password bob

# List everyone
dagster-authkit list-users

# View RBAC permissions matrix
dagster-authkit list-permissions
```

---

## 🔮 Roadmap

### Current (v0.3.0)
* ✅ Username/password auth (bcrypt)
* ✅ 4-level RBAC (ADMIN/EDITOR/LAUNCHER/VIEWER)
* ✅ SQLite, PostgreSQL, MySQL, Redis support
* ✅ GraphQL mutation blocking with official AST parser
* ✅ LDAP backend (experimental)
* ✅ **Proxy authentication** (Authelia, Caddy, Traefik)
* ✅ **Kubernetes example** with full SSO stack
* ✅ Redis session revocation and rate limiting
* ✅ Centralized UI templates

### Next
* 🔄 Improved GraphQL query analysis
* 🔄 Helm chart for Kubernetes deployments
* 🔄 OpenID Connect support (via proxy mode)

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