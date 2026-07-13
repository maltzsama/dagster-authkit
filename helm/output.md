## 📄 dagster-authkit/templates/deployment.yaml
```
{{- if and (contains "sqlite" .Values.authkit.databaseUrl) (or (gt (int .Values.replicaCount) 1) .Values.autoscaling.enabled) }}
{{- if not .Values.authkit.redisUrl }}
{{- fail "SQLite cannot be used with replicaCount > 1 or HPA without Redis. Set authkit.databaseUrl to a PostgreSQL/MySQL DSN, or set replicaCount=1 and disable autoscaling." }}
{{- end }}
{{- end }}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "dagster-authkit.fullname" . }}
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
spec:
  {{- if not .Values.autoscaling.enabled }}
  replicas: {{ .Values.replicaCount }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "dagster-authkit.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      annotations:
        checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
        {{- if not .Values.authkit.existingSecret }}
        checksum/secret: {{ include (print $.Template.BasePath "/secret.yaml") . | sha256sum }}
        {{- end }}
        {{- with .Values.podAnnotations }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      labels:
        {{- include "dagster-authkit.selectorLabels" . | nindent 8 }}
    spec:
      {{- with .Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      serviceAccountName: {{ include "dagster-authkit.fullname" . }}
      securityContext:
        {{- toYaml .Values.podSecurityContext | nindent 8 }}
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          args:
            - -h
            - "0.0.0.0"
            - -p
            - "{{ .Values.service.port }}"
            {{- if .Values.dagster.workspace.module }}
            - -m
            - {{ .Values.dagster.workspace.module | quote }}
            {{- else if .Values.dagster.workspace.file }}
            - -f
            - {{ .Values.dagster.workspace.file | quote }}
            {{- else }}
            - --empty-workspace
            {{- end }}
            {{- with .Values.dagster.extraArgs }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          envFrom:
            - configMapRef:
                name: {{ include "dagster-authkit.fullname" . }}-config
            - secretRef:
                name: {{ .Values.authkit.existingSecret | default (printf "%s-secret" (include "dagster-authkit.fullname" .)) }}
          env:
            - name: DAGSTER_HOME
              value: {{ .Values.dagster.home | quote }}
          ports:
            - name: http
              containerPort: {{ .Values.service.port }}
              protocol: TCP
          livenessProbe:
            httpGet:
              path: /auth/health?type=live
              port: http
            initialDelaySeconds: 5
            periodSeconds: 15
          readinessProbe:
            httpGet:
              path: /auth/health?type=ready
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 3
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
          volumeMounts:
            {{- if .Values.persistence.enabled }}
            - name: data
              mountPath: /data
            {{- end }}
            - name: tmp
              mountPath: /tmp
      volumes:
        {{- if .Values.persistence.enabled }}
        - name: data
          persistentVolumeClaim:
            claimName: {{ include "dagster-authkit.fullname" . }}-data
        {{- end }}
        - name: tmp
          emptyDir: {}
      {{- with .Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with .Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}

```

## 📄 dagster-authkit/templates/ingress.yaml
```
{{- if .Values.ingress.enabled }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "dagster-authkit.fullname" . }}
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
  {{- with .Values.ingress.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- if .Values.ingress.className }}
  ingressClassName: {{ .Values.ingress.className }}
  {{- end }}
  {{- if .Values.ingress.tls }}
  tls:
    {{- range .Values.ingress.tls }}
    - hosts:
        {{- range .hosts }}
        - {{ . | quote }}
        {{- end }}
      secretName: {{ .secretName }}
    {{- end }}
  {{- end }}
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host | quote }}
      http:
        paths:
          {{- range .paths }}
          - path: {{ .path }}
            pathType: {{ .pathType }}
            backend:
              service:
                name: {{ include "dagster-authkit.fullname" $ }}
                port:
                  number: {{ $.Values.service.port }}
          {{- end }}
    {{- end }}
{{- end }}

```

## 📄 dagster-authkit/templates/service.yaml
```
apiVersion: v1
kind: Service
metadata:
  name: {{ include "dagster-authkit.fullname" . }}
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: http
      protocol: TCP
      name: http
  selector:
    {{- include "dagster-authkit.selectorLabels" . | nindent 4 }}

```

## 📄 dagster-authkit/templates/hpa.yaml
```
{{- if .Values.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "dagster-authkit.fullname" . }}
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "dagster-authkit.fullname" . }}
  minReplicas: {{ .Values.autoscaling.minReplicas }}
  maxReplicas: {{ .Values.autoscaling.maxReplicas }}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .Values.autoscaling.targetCPUUtilizationPercentage }}
{{- end }}

```

## 📄 dagster-authkit/templates/pvc.yaml
```
{{- if .Values.persistence.enabled }}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ include "dagster-authkit.fullname" . }}-data
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
spec:
  accessModes:
    - {{ .Values.persistence.accessMode }}
  resources:
    requests:
      storage: {{ .Values.persistence.size }}
{{- end }}

```

## 📄 dagster-authkit/templates/serviceaccount.yaml
```
{{- if .Values.serviceAccount.create }}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "dagster-authkit.fullname" . }}
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
  {{- with .Values.serviceAccount.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end }}

```

## 📄 dagster-authkit/templates/configmap.yaml
```
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "dagster-authkit.fullname" . }}-config
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
data:
  DAGSTER_AUTH_BACKEND: {{ .Values.authkit.backend | quote }}
  DAGSTER_AUTH_SESSION_MAX_AGE: {{ .Values.authkit.sessionMaxAge | quote }}
  DAGSTER_AUTH_COOKIE_SECURE: {{ .Values.authkit.cookieSecure | quote }}
  DAGSTER_AUTH_COOKIE_SAMESITE: {{ .Values.authkit.cookieSameSite | quote }}
  DAGSTER_AUTH_DATABASE_URL: {{ .Values.authkit.databaseUrl | quote }}
  DAGSTER_AUTH_LOG_LEVEL: {{ .Values.authkit.logLevel | quote }}
  DAGSTER_AUTH_AUDIT_LOG: {{ .Values.authkit.auditLog | quote }}
  DAGSTER_AUTH_RATE_LIMIT: {{ .Values.authkit.rateLimit.enabled | quote }}
  DAGSTER_AUTH_RATE_LIMIT_ATTEMPTS: {{ .Values.authkit.rateLimit.maxAttempts | quote }}
  DAGSTER_AUTH_RATE_LIMIT_WINDOW: {{ .Values.authkit.rateLimit.windowSeconds | quote }}
  DAGSTER_AUTH_UNKNOWN_MUTATION_ROLE: {{ .Values.authkit.rbac.unknownMutationRole | quote }}
  DAGSTER_AUTH_REST_WRITE_ROLE: {{ .Values.authkit.rbac.restWriteRole | quote }}
  DAGSTER_AUTH_PROXY_USER_HEADER: {{ .Values.authkit.proxy.userHeader | quote }}
  DAGSTER_AUTH_PROXY_GROUPS_HEADER: {{ .Values.authkit.proxy.groupsHeader | quote }}
  DAGSTER_AUTH_PROXY_EMAIL_HEADER: {{ .Values.authkit.proxy.emailHeader | quote }}
  DAGSTER_AUTH_PROXY_NAME_HEADER: {{ .Values.authkit.proxy.nameHeader | quote }}
  {{- if eq .Values.authkit.backend "proxy" }}
  DAGSTER_AUTH_PROXY_LOGOUT_URL: {{ required "authkit.proxy.logoutUrl is required when backend=proxy" .Values.authkit.proxy.logoutUrl | quote }}
  {{- else }}
  DAGSTER_AUTH_PROXY_LOGOUT_URL: {{ .Values.authkit.proxy.logoutUrl | quote }}
  {{- end }}
  DAGSTER_AUTH_PROXY_TRUST_ALL: {{ .Values.authkit.proxy.trustAll | quote }}
  DAGSTER_AUTH_LDAP_USE_TLS: {{ .Values.authkit.ldap.useTLS | quote }}
  DAGSTER_AUTH_LDAP_TIMEOUT: {{ .Values.authkit.ldap.timeout | quote }}
  {{- if .Values.authkit.redisUrl }}
  DAGSTER_AUTH_REDIS_URL: {{ .Values.authkit.redisUrl | quote }}
  {{- end }}
  {{- if .Values.authkit.proxy.trustedIPs }}
  DAGSTER_AUTH_PROXY_TRUSTED_IPS: {{ .Values.authkit.proxy.trustedIPs | quote }}
  {{- end }}
  {{- if .Values.authkit.proxy.groupPattern }}
  DAGSTER_AUTH_PROXY_GROUP_PATTERN: {{ .Values.authkit.proxy.groupPattern | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.server }}
  DAGSTER_AUTH_LDAP_SERVER: {{ .Values.authkit.ldap.server | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.baseDN }}
  DAGSTER_AUTH_LDAP_BASE_DN: {{ .Values.authkit.ldap.baseDN | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.bindDN }}
  DAGSTER_AUTH_LDAP_BIND_DN: {{ .Values.authkit.ldap.bindDN | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.userFilter }}
  DAGSTER_AUTH_LDAP_USER_FILTER: {{ .Values.authkit.ldap.userFilter | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.caCert }}
  DAGSTER_AUTH_LDAP_CA_CERT: {{ .Values.authkit.ldap.caCert | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.roleAttribute }}
  DAGSTER_AUTH_LDAP_ROLE_ATTRIBUTE: {{ .Values.authkit.ldap.roleAttribute | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.groupPattern }}
  DAGSTER_AUTH_LDAP_GROUP_PATTERN: {{ .Values.authkit.ldap.groupPattern | quote }}
  {{- end }}

```

## 📄 dagster-authkit/templates/secret.yaml
```
{{- if not .Values.authkit.existingSecret }}
apiVersion: v1
kind: Secret
metadata:
  name: {{ include "dagster-authkit.fullname" . }}-secret
  labels:
    {{- include "dagster-authkit.labels" . | nindent 4 }}
type: Opaque
data:
  {{- if .Values.authkit.secretKey }}
  DAGSTER_AUTH_SECRET_KEY: {{ .Values.authkit.secretKey | b64enc | quote }}
  {{- else }}
  {{- fail "authkit.secretKey is required when existingSecret is not set" }}
  {{- end }}
  {{- if .Values.authkit.adminPassword }}
  DAGSTER_AUTH_ADMIN_PASSWORD: {{ .Values.authkit.adminPassword | b64enc | quote }}
  {{- end }}
  {{- if .Values.authkit.ldap.bindPassword }}
  DAGSTER_AUTH_LDAP_BIND_PASSWORD: {{ .Values.authkit.ldap.bindPassword | b64enc | quote }}
  {{- end }}
{{- end }}

```

## 📄 dagster-authkit/values.yaml
```
# Default values for dagster-authkit.
# This is a YAML-formatted file.
# Declare variables to be passed into your templates.

replicaCount: 1

image:
  repository: dagster-authkit
  pullPolicy: IfNotPresent
  tag: "0.4.0"

imagePullSecrets: []
nameOverride: ""
fullnameOverride: ""

serviceAccount:
  create: true
  annotations: {}
  name: ""

podAnnotations: {}
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL

service:
  type: ClusterIP
  port: 3000

ingress:
  enabled: false
  className: ""
  annotations: {}
  hosts:
    - host: dagster.local
      paths:
        - path: /
          pathType: Prefix
  tls: []

resources: {}
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

nodeSelector: {}
tolerations: []
affinity: {}

# --- Dagster AuthKit Configuration ---

authkit:
  backend: sql
  existingSecret: ""  # Name of pre-created Secret (Vault, External Secrets, etc.)
  secretKey: ""  # Used only if existingSecret is empty
  adminPassword: ""

  sessionMaxAge: 86400
  cookieSecure: true
  cookieSameSite: lax

  databaseUrl: sqlite:////data/dagster_auth.db

  redisUrl: ""  # Optional — enables distributed sessions and rate limiting

  rateLimit:
    enabled: true
    maxAttempts: 5
    windowSeconds: 300

  logLevel: INFO
  auditLog: true

  # --- Proxy Mode (when backend=proxy) ---
  proxy:
    trustedIPs: ""  # REQUIRED in proxy mode — comma-separated
    trustAll: false  # Opt-in to insecure default
    userHeader: Remote-User
    groupsHeader: Remote-Groups
    emailHeader: Remote-Email
    nameHeader: Remote-Name
    groupPattern: ""
    logoutUrl: ""  # REQUIRED in proxy mode — no default, must be explicitly set

  # --- RBAC ---
  rbac:
    unknownMutationRole: ADMIN
    restWriteRole: EDITOR

  # --- LDAP (when backend=ldap) ---
  ldap:
    server: ""
    baseDN: ""
    bindDN: ""
    bindPassword: ""
    userFilter: "(uid={username})"
    useTLS: false
    caCert: ""
    roleAttribute: ""
    groupPattern: ""
    timeout: 10

# --- Dagster workspace (passed as CLI args) ---
dagster:
  workspace:
    # Use either module or file
    module: ""
    file: ""
  extraArgs: []
  home: /data/dagster_home

# --- Persistence for SQLite (when using SQLite backend) ---
persistence:
  enabled: true
  size: 1Gi
  accessMode: ReadWriteOnce

```

