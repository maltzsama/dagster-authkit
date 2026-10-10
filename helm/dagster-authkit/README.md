# dagster-authkit

Authentication, RBAC and audit logging for self-hosted Dagster OSS. This chart
runs the Dagster webserver wrapped by [dagster-authkit](https://github.com/maltzsama/dagster-authkit).

## Install

```bash
helm upgrade --install dagster-authkit oci://ghcr.io/maltzsama/charts/dagster-authkit \
  --set authkit.secretKey="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  --set authkit.adminPassword="your-admin-password"
```

Then:

```bash
kubectl port-forward svc/dagster-authkit 3000:3000
```

Over plain HTTP (such as a port-forward) also set `authkit.cookieSecure=false`,
or the browser will drop the session cookie.

Requires Kubernetes 1.23+ and Helm 3.8+.

## What gets deployed

- A Deployment running `dagster-authkit` as uid 1000 with a read-only root
  filesystem. The image is `ghcr.io/maltzsama/dagster-authkit`, at the chart's
  `appVersion` unless `image.tag` is set.
- A Service on port 3000, and optionally an Ingress and an HPA.
- A ConfigMap and a Secret with the authkit configuration.
- A 1Gi PersistentVolumeClaim mounted at `/data`, holding the SQLite user
  database and `DAGSTER_HOME`.

With the defaults the webserver starts with an empty workspace and stores
users in SQLite: enough to try it out, not a production setup.

## Configuration

Everything is documented in [`values.yaml`](./values.yaml). The values most
installs need:

| Value | Default | Purpose |
|---|---|---|
| `authkit.secretKey` | `""` | Session signing key. Required unless `existingSecret` is set. |
| `authkit.existingSecret` | `""` | Use a pre-created Secret instead of the chart-managed one. |
| `authkit.adminPassword` | `""` | Creates the `admin` user on first start. |
| `authkit.backend` | `sql` | `sql`, `ldap` or `proxy`. |
| `authkit.databaseUrl` | SQLite in `/data` | User database DSN. |
| `authkit.redisUrl` | `""` | Shared sessions and rate limiting across replicas. |
| `dagster.workspace.content` | `""` | Inline `workspace.yaml`. |
| `dagster.instance.content` | `""` | Inline `dagster.yaml`. |
| `persistence.enabled` | `true` | PVC for `/data`. An `emptyDir` when disabled. |
| `ingress.enabled` | `false` | Expose the webserver through an Ingress. |

### Secrets

The chart-managed Secret holds `secretKey`, `adminPassword`, `databaseUrl`,
`redisUrl`, `metricsToken`, the service token and the LDAP bind password.

To manage them yourself, set `authkit.existingSecret` to a Secret with:

| Key | Required |
|---|---|
| `DAGSTER_AUTH_SECRET_KEY` | yes |
| `DAGSTER_AUTH_ADMIN_PASSWORD` | no |
| `DAGSTER_AUTH_DATABASE_URL` | no |
| `DAGSTER_AUTH_REDIS_URL` | no |
| `DAGSTER_AUTH_METRICS_TOKEN` | no |
| `DAGSTER_AUTH_SERVICE_TOKEN` | no |
| `DAGSTER_AUTH_LDAP_BIND_PASSWORD` | no |

Keys in that Secret override the chart's values. Set `authkit.databaseUrl`,
`authkit.redisUrl` and `authkit.metricsToken` to `""` so they are not also
written to the ConfigMap.

### Pointing at your Dagster code

On Kubernetes the usual setup is one or more gRPC code location servers and a
`workspace.yaml` that lists them:

```yaml
dagster:
  workspace:
    content: |
      load_from:
        - grpc_server:
            host: my-code-location
            port: 3030
            location_name: my-code-location
```

`dagster.workspace.module` and `dagster.workspace.file` load code directly in
the webserver instead; the code then has to be in the image or mounted with
`extraVolumes`.

### Dagster instance configuration

Without `dagster.instance.content`, Dagster keeps run and event history in
SQLite files under `DAGSTER_HOME`. To use other storage, provide a `dagster.yaml`:

```yaml
dagster:
  instance:
    content: |
      telemetry:
        enabled: false
```

The published image contains `dagster` and `dagster-webserver` only. Storage
and run launcher plugins such as `dagster-postgres` or `dagster-k8s` are not
included: build an image `FROM ghcr.io/maltzsama/dagster-authkit` that installs
them, and set `image.repository` to it.

### More than one replica

SQLite cannot be shared between pods, so the chart refuses to render with
`replicaCount > 1` or autoscaling while `authkit.databaseUrl` is SQLite. For
several replicas:

```yaml
replicaCount: 2
persistence:
  enabled: false
authkit:
  databaseUrl: postgresql://user:password@postgres:5432/dagster_auth
  redisUrl: redis://redis:6379/0
```

Without Redis, rate limiting and individual logout are per pod.

### Upgrades

With persistence enabled the Deployment uses the `Recreate` strategy, because a
rolling update can deadlock on a `ReadWriteOnce` volume. Upgrades therefore
restart the pod with a short downtime. Override with `strategy` if your volume
supports it.

## Testing a release

```bash
helm test dagster-authkit
```

Runs a pod that calls `/auth/health?type=ready` through the Service.
