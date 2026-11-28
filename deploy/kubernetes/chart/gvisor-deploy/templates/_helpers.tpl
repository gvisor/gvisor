{{- define "gvisor-deploy.name" -}}
{{- printf "%s-installer" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "gvisor-deploy.labels" -}}
app.kubernetes.io/name: gvisor-deploy
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "gvisor-deploy.selector" -}}
app.kubernetes.io/name: gvisor-deploy
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* The image tag: image.tag, or the appVersion of the chart. */}}
{{- define "gvisor-deploy.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion -}}
{{- end -}}

{{- define "gvisor-deploy.image" -}}
{{ .Values.image.repository }}:{{ include "gvisor-deploy.imageTag" . }}
{{- end -}}

{{/* image.pullPolicy, or Always for the "latest" tag and IfNotPresent for other tags. */}}
{{- define "gvisor-deploy.imagePullPolicy" -}}
{{- if .Values.image.pullPolicy -}}
{{ .Values.image.pullPolicy }}
{{- else if eq (include "gvisor-deploy.imageTag" .) "latest" -}}
Always
{{- else -}}
IfNotPresent
{{- end -}}
{{- end -}}

{{/* Node affinity for the architectures of the published image. */}}
{{- define "gvisor-deploy.archAffinity" -}}
nodeAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    nodeSelectorTerms:
      - matchExpressions:
          - key: kubernetes.io/os
            operator: In
            values: ["linux"]
          - key: kubernetes.io/arch
            operator: In
            values: ["amd64", "arm64"]
{{- end -}}
