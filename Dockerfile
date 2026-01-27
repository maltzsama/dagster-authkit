# Stage 1: Build
FROM python:3.11-slim as builder

WORKDIR /build

# Dependências de sistema para compilar drivers (psycopg2, bcrypt, ldap)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libldap2-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

# Instala o projeto com os extras de produção
COPY . .
RUN pip install --upgrade pip && \
    pip install .[postgresql,redis] --prefix=/install

# Stage 2: Runtime
FROM python:3.11-slim

WORKDIR /app

# Dependências de runtime (apenas as libs compartilhadas)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libldap-common \
    $(apt-cache search libldap- | grep -o "libldap-[0-9].[0-9]-[0-9]" | head -n 1) \
    && rm -rf /var/lib/apt/lists/*

# Copia os pacotes instalados do stage de build
COPY --from=builder /install /usr/local

# Configuração do Dagster Home (necessário para o webserver rodar)
ENV DAGSTER_HOME=/opt/dagster/dagster_home
RUN mkdir -p $DAGSTER_HOME
COPY dagster.yaml $DAGSTER_HOME/

# Expondo a porta padrão do Dagster
EXPOSE 3000

# O entrypoint é o nosso CLI que faz o patch e sobe o server
ENTRYPOINT ["dagster-authkit"]
CMD ["-h", "0.0.0.0", "-p", "3000"]