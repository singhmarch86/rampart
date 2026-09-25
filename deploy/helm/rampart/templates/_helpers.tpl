{{- define "rampart.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "rampart.fullname" -}}
{{- .Release.Name -}}-{{- .Chart.Name -}}
{{- end -}}

{{- define "rampart.labels" -}}
app.kubernetes.io/name: {{ include "rampart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "rampart.selectorLabels" -}}
app.kubernetes.io/name: {{ include "rampart.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
