# Stage 1: Build
FROM python:3.11-slim as builder

ARG EXTRAS=""

WORKDIR /build

# System dependencies for compiling drivers (psycopg2, bcrypt, ldap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libldap2-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install project with production extras
COPY . .
RUN pip install --upgrade pip && \
    pip install ".[${EXTRAS}]" --prefix=/install

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Runtime dependencies (only shared libraries)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libldap-common \
    $(apt-cache search libldap- | grep -o "libldap-[0-9].[0-9]-[0-9]" | head -n 1) \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from build stage
COPY --from=builder /install /usr/local

# Dagster Home configuration (required for webserver to run)
ENV DAGSTER_HOME=/opt/dagster/dagster_home
RUN mkdir -p $DAGSTER_HOME
COPY dagster.yml $DAGSTER_HOME/

# Expose default Dagster port
EXPOSE 3000

# The entrypoint is our CLI that patches and starts the server
ENTRYPOINT ["dagster-authkit"]
CMD ["-h", "0.0.0.0", "-p", "3000"]