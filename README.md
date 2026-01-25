# 🔒 Dagster AuthKit

**Community authentication for self-hosted Dagster OSS**

Add login, RBAC, and audit logging to Dagster without touching any code.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Dagster](https://img.shields.io/badge/dagster-1.10%2B-orange.svg)](https://dagster.io)

---

## 🎯 What is this?

Dagster OSS doesn't have authentication. You're either running it locally or trusting your VPC/firewall.

AuthKit adds:
- ✅ Login/logout pages
- ✅ Role-based access (admin, editor, viewer)
- ✅ Session management
- ✅ Audit logs (JSON)
- ✅ Rate limiting
- ✅ User menu in Dagster UI

**No code changes needed** - just wrap the `dagster-webserver` command.

---

## 🚀 Quick Start
```bash
# Install
pip install dagster-authkit[sqlite]

# Create admin user
dagster-authkit init-db --with-admin

# Start Dagster with auth
dagster-authkit -f your_pipeline.py -h 0.0.0.0 -p 3000
```

Open `http://localhost:3000` → login screen appears.

---

## 📦 Backends

| Backend | Use Case | Status |
|---------|----------| ------ |
| **SQLite** | Default - file-based DB | Done |
| **LDAP** | Active Directory integration | ToDo |
| **OAuth** | Google, Azure, Okta | ToDo |
| **Dummy** | Dev only (user: admin/admin) | Done |

---

## 🔐 Roles

| Role | Can Do |
|------|--------|
| **Admin** | Everything |
| **Editor** | Create runs, materialize assets |
| **Viewer** | Read-only |

GraphQL mutations are blocked for viewers - they see everything but can't modify.

---

## 🛠️ User Management
```bash
# Add user
dagster-authkit add-user alice --editor

# Change password
dagster-authkit change-password alice

# List users
dagster-authkit list-users

# Delete user
dagster-authkit delete-user bob
```

---

## 🐳 Docker
```dockerfile
FROM python:3.11-slim

RUN pip install dagster dagster-webserver dagster-authkit[sqlite]

# Bootstrap admin user
ENV DAGSTER_AUTH_ADMIN_USER=admin
ENV DAGSTER_AUTH_ADMIN_PASSWORD=changeme123
ENV DAGSTER_AUTH_SECRET_KEY=your-secret-key-here

COPY your_pipeline.py /app/
WORKDIR /app

EXPOSE 3000
CMD ["dagster-authkit", "-f", "your_pipeline.py", "-h", "0.0.0.0", "-p", "3000"]
```

---

## ⚙️ Configuration

Environment variables:
```bash
# Session
DAGSTER_AUTH_SECRET_KEY=xxx           # Required for production
DAGSTER_AUTH_SESSION_MAX_AGE=86400    # 24 hours

# Backend
DAGSTER_AUTH_BACKEND=sqlite           # sqlite, ldap, oauth, dummy
DAGSTER_AUTH_DB=./dagster_auth.db     # SQLite path

# Rate limiting
DAGSTER_AUTH_RATE_LIMIT=true
DAGSTER_AUTH_RATE_LIMIT_ATTEMPTS=5
DAGSTER_AUTH_RATE_LIMIT_WINDOW=300    # seconds

# Audit
DAGSTER_AUTH_AUDIT_LOG=true

# Admin bootstrap (Docker/K8s)
DAGSTER_AUTH_ADMIN_USER=admin
DAGSTER_AUTH_ADMIN_PASSWORD=secret
```

---

## 📊 Audit Logs

JSON logs to stdout (pipe to Datadog, Splunk, CloudWatch, etc):
```json
{"event_type":"LOGIN_ATTEMPT","username":"alice","status":"SUCCESS","ip":"192.168.1.10","timestamp":"2026-01-25T10:30:00Z"}
{"event_type":"ACCESS_CONTROL","username":"viewer","action":"POST","resource":"/graphql","status":"DENIED","roles":["viewer"],"reason":"EDITOR_REQUIRED_FOR_MUTATIONS"}
```

---

## 🔍 Health Checks
```bash
# Full health
curl http://localhost:3000/auth/health

# Kubernetes liveness
curl http://localhost:3000/auth/health?type=live

# Kubernetes readiness
curl http://localhost:3000/auth/health?type=ready

# Metrics
curl http://localhost:3000/auth/metrics
```

---

## 🧪 Testing Locally
```bash
# Clone repo
git clone https://github.com/demetrius-mp/dagster-authkit.git
cd dagster-authkit

# Install
pip install -e ".[sqlite,dev]"

# Init DB
dagster-authkit init-db --with-admin

# Create test pipeline
cat > test.py << 'EOF'
from dagster import asset, Definitions

@asset
def my_asset():
    return "Hello!"

defs = Definitions(assets=[my_asset])
EOF

# Start
dagster-authkit -f test.py -h 0.0.0.0 -p 3000
```

Login with `admin` and the password shown during init.

---

## 🤝 Contributing

This is a community project. PRs welcome.

**Areas that need help:**
- LDAP backend (stub exists)
- OAuth backend (stub exists)
- More comprehensive tests
- Documentation improvements

---

## ⚠️ Limitations

**This is not Dagster+**. It's a community workaround with limitations:

- **Monkey-patching** - Fragile across Dagster versions
- **In-memory rate limiting** - Doesn't work across multiple instances
- **GraphQL mutation detection** - Blocks mutations for viewers, but it's regex-based (not perfect)
- **No fine-grained permissions** - Only 3 roles (admin/editor/viewer)

For serious production use with 100+ users, consider [Dagster+](https://dagster.io/plus).

---

## 📄 License

Apache 2.0 - see [LICENSE](LICENSE)

---

## 🙏 Credits

Built by [Demetrius Albuquerque](https://github.com/demetrius-mp) because self-hosting Dagster shouldn't mean no auth.

Inspired by the community's need for a middle ground between "no auth" and "pay for Dagster+".