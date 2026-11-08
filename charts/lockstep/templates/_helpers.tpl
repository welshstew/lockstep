{{/* Names */}}
{{- define "lockstep.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lockstep.fullname" -}}
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

{{- define "lockstep.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "lockstep.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "lockstep.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lockstep.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "lockstep.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "lockstep.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "lockstep.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{- define "lockstep.sessionSecretName" -}}
{{- default (printf "%s-session" (include "lockstep.fullname" .)) .Values.session.existingSecret }}
{{- end }}

{{- define "lockstep.sessionSecretKey" -}}
{{- if .Values.session.existingSecret }}{{ .Values.session.existingSecretKey }}{{ else }}session-key{{ end }}
{{- end }}

{{/* Mount the service account token only when Kubernetes auth needs it, unless forced. */}}
{{- define "lockstep.automountToken" -}}
{{- $a := .Values.serviceAccount.automountToken }}
{{- if eq (toString $a) "auto" }}{{ .Values.kubernetesAuth.enabled }}{{ else }}{{ $a }}{{ end }}
{{- end }}

{{/* Preset Vault connections as the JSON the app expects. */}}
{{- define "lockstep.presets" -}}
{{- $out := list }}
{{- range .Values.vaults }}
{{- if not (and .name .url) }}{{ fail "each entry in vaults needs a name and a url" }}{{ end }}
{{- $v := dict "name" .name "url" .url }}
{{- with .browserUrl }}{{ $_ := set $v "browser_url" . }}{{ end }}
{{- with .namespace }}{{ $_ := set $v "namespace" . }}{{ end }}
{{- $out = append $out $v }}
{{- end }}
{{- toJson $out }}
{{- end }}

{{/* Shared comparison profiles as the JSON the app expects (camelCase values -> snake_case). */}}
{{- define "lockstep.profiles" -}}
{{- $out := list }}
{{- range .Values.profiles }}
{{- $p := dict "name" .name }}
{{- with .description }}{{ $_ := set $p "description" . }}{{ end }}
{{- with .leftMount }}{{ $_ := set $p "left_mount" . }}{{ end }}
{{- with .leftPrefix }}{{ $_ := set $p "left_prefix" . }}{{ end }}
{{- with .rightMount }}{{ $_ := set $p "right_mount" . }}{{ end }}
{{- with .rightPrefix }}{{ $_ := set $p "right_prefix" . }}{{ end }}
{{- $r := .rules | default dict }}
{{- $keys := list }}
{{- range $r.ignoreKeys }}{{ $keys = append $keys (dict "key" .key "path" (.path | default "**")) }}{{ end }}
{{- $_ := set $p "rules" (dict "mappings" ($r.mappings | default list) "ignore_keys" $keys "ignore_paths" ($r.ignorePaths | default list)) }}
{{- $out = append $out $p }}
{{- end }}
{{- toJson $out }}
{{- end }}

{{/* Sanity checks that would otherwise only show up at runtime. */}}
{{- define "lockstep.validate" -}}
{{- if and .Values.kubernetesAuth.enabled (eq (include "lockstep.automountToken" .) "false") }}
{{- fail "kubernetesAuth.enabled needs the service account token: set serviceAccount.automountToken to auto or true" }}
{{- end }}
{{- if and (not .Values.vaults) (not .Values.allowCustomConnections) }}
{{- fail "configure at least one entry in vaults, or set allowCustomConnections: true" }}
{{- end }}
{{- $names := list }}
{{- range .Values.profiles }}
{{- if has .name $names }}{{ fail (printf "profiles: the name %q is used twice" .name) }}{{ end }}
{{- $names = append $names .name }}
{{- end }}
{{- if and .Values.vaultTls.caBundle.configMap .Values.vaultTls.caBundle.secret }}
{{- fail "vaultTls.caBundle: set configMap or secret, not both" }}
{{- end }}
{{- end }}
