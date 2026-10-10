{{- define "dagster-authkit.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "dagster-authkit.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "dagster-authkit.labels" -}}
helm.sh/chart: {{ include "dagster-authkit.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "dagster-authkit.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "dagster-authkit.selectorLabels" -}}
app.kubernetes.io/name: {{ include "dagster-authkit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "dagster-authkit.image" -}}
{{ .Values.image.repository }}:{{ required "image.tag is required — set the exact image version (e.g. --set image.tag=1.2.0). Falling back to Chart.appVersion would silently use a stale version." .Values.image.tag }}
{{- end }}

{{- define "dagster-authkit.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "dagster-authkit.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
