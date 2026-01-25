# Production Dockerfile for dagster-authkit
# Multi-stage build for minimal image size

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY pyproject.toml README.md ./
COPY dagster_authkit ./dagster_authkit

# Build wheel
RUN pip install build && \
    python -m build --wheel

# Stage 2: Runtime
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r dagster && \
    useradd -r -g dagster -s /bin/bash dagster

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install dagster-authkit from wheel
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl[sqlite] && \
    rm -rf /tmp/*.whl

# Create directories
RUN mkdir -p /data /opt/dagster/home /workspace && \
    chown -R dagster:dagster /data /opt/dagster /workspace

# Switch to non-root user
USER dagster

# Set working directory
WORKDIR /workspace

# Environment variables (can be overridden in docker-compose or k8s)
ENV DAGSTER_AUTH_BACKEND=sqlite \
    DAGSTER_AUTH_DB=/data/dagster_auth.db \
    DAGSTER_HOME=/opt/dagster/home \
    PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:3000/auth/login || exit 1

# Expose port
EXPOSE 3000

# Run dagster-authkit
CMD ["dagster-authkit", "-h", "0.0.0.0", "-p", "3000"]

# Usage:
# ------
# Build:
#   docker build -t dagster-authkit:latest .
#
# Run with admin bootstrap:
#   docker run -d \
#     -p 3000:3000 \
#     -e DAGSTER_AUTH_ADMIN_USER=admin \
#     -e DAGSTER_AUTH_ADMIN_PASSWORD=SecurePass123 \
#     -e DAGSTER_AUTH_SECRET_KEY=$(openssl rand -hex 32) \
#     -v dagster-auth-data:/data \
#     dagster-authkit:latest
#
# Manage users:
#   docker exec -it <container> dagster-authkit list-users
#   docker exec -it <container> dagster-authkit add-user newuser --editor