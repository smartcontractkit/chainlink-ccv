{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "generic-app.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "generic-app.labels" -}}
helm.sh/chart: {{ include "generic-app.chart" . }}
{{ include "generic-app.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Values.labels}}
{{ toYaml .Values.labels }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "generic-app.selectorLabels" -}}
{{- if .Values.service.selector}}
{{- toYaml .Values.service.selector }}
{{- else }}
app.kubernetes.io/name: {{ .Release.Name }}
app.kubernetes.io/instance: {{ .Values.name }}
{{- end }}
{{- end }}
