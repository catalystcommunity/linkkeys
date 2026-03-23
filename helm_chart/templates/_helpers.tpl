{{/*
Expand the name of the chart.
*/}}
{{- define "linkkeys.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "linkkeys.fullname" -}}
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

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "linkkeys.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "linkkeys.labels" -}}
helm.sh/chart: {{ include "linkkeys.chart" . }}
{{ include "linkkeys.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "linkkeys.selectorLabels" -}}
app.kubernetes.io/name: {{ include "linkkeys.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "linkkeys.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "linkkeys.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL labels
*/}}
{{- define "linkkeys.postgresql.labels" -}}
helm.sh/chart: {{ include "linkkeys.chart" . }}
app.kubernetes.io/name: {{ include "linkkeys.name" . }}-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "linkkeys.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "linkkeys.name" . }}-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
