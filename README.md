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

## 📂 Ready-to-Run Examples

Don't waste time configuring from scratch. We provide full Docker Compose stacks for different scenarios in the `examples/` directory.

```bash
examples
├── ldap                # Active Directory integration (**Experimental**)
│   ├── Makefile
│   ├── docker-compose.yml
│   └── ldap-bootstrap.ldif
├── postgresql_redis    # Recommended production setup
│   ├── Makefile
│   └── docker-compose.yml
└── quickstart-sqlite   # Simple local testing
    ├── Makefile
    └── docker-compose.yml

```

### How to run

Pick a scenario, go into the folder, and check the `Makefile`.

**1. Standard Setup (Postgres + Redis)**
The most robust configuration available right now.

```bash
cd examples/postgresql_redis
make up
# or
docker compose up --build

```

**2. Local Quickstart (SQLite)**
Zero dependencies, just Python. Good for kicking the tires.

```bash
cd examples/quickstart-sqlite
make up

```

**3. LDAP/AD Testing** ⚠️ **EXPERIMENTAL**
Spins up a local OpenLDAP server to simulate Active Directory.

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

```

---

## 🔐 Roles (RBAC)

We provide **4 levels** of access. Permissions are enforced via GraphQL query analysis.

| Role | Description |
| --- | --- |
| **Admin** | Full access. Can manage users, settings, and all pipelines. |
| **Editor** | Can modify assets and codebase (if allowed by deployment) and manage runs. |
| **Launcher** | Can **launch runs** and re-execute jobs, but **cannot** modify code/assets. |
| **Viewer** | Read-only. Can view runs and assets. GraphQL mutations are blocked. |

**How it works:** AuthKit analyzes GraphQL queries via regex to block unauthorized mutations based on user role.

---

## 📦 Backends

Choose where to store users and sessions.

| Backend | Implementation | Status | Use Case |
| --- | --- | --- | --- |
| **SQLite** | Peewee ORM | **Functional** | Local / Simple. Single instance only. |
| **PostgreSQL** | Peewee + `psycopg2` | **Functional** | Server. Recommended for Docker/K8s. |
| **Redis** | Native `redis` | **Functional** | Session Storage. Avoids logout on restart. |
| **LDAP** | `ldap3` library | **Experimental** ⚠️ | Active Directory / OpenLDAP. Needs community testing. |

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

```

---

## 🔮 Roadmap & Community

This project belongs to the community.

**Philosophy:** Keep it simple. This is RBAC for Dagster, not an enterprise auth platform.

### Current (v0.2.0)
* Username/password auth (bcrypt)
* 4-level RBAC (ADMIN/EDITOR/LAUNCHER/VIEWER)
* SQLite, PostgreSQL, MySQL, Redis support
* GraphQL mutation blocking
* LDAP (experimental, community testing needed)

**Priorities to next version:**

* **Proxy Auth Mode:** Work with `Authelia`/`Authentik`/`oauth2-proxy` for auth
1. **Stability:** Improving GraphQL query analysis for better mutation detection.

**What we will NOT do:**

* Inject React code into Dagster UI (too brittle/hard to maintain).
* Complex enterprise features that belong in Dagster+.

---

## 🤝 Contributing

Found a bug? Want to add a feature?
Open a PR. If it works and keeps things simple, we'll merge it.

**Especially needed:** People with Active Directory experience to validate the LDAP backend.

---

## 📄 License

Apache 2.0 - see [LICENSE](LICENSE)

---

## 🙏 Credits

Built by [Demetrius Albuquerque](https://github.com/demetrius-mp) because self-hosting Dagster shouldn't mean no auth.

Inspired by the community's need for a middle ground between "no auth" and "pay for Dagster+".