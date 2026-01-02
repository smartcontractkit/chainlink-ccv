{{/*
Expand the name of the chart.
*/}}

{{- define "chainlink-cluster.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{/*
  TODO: This shouldn't be the name of the release or chart, but should be the
  name of the application, which is chainlink. The app.kubernetes.io/instance
  label should be used for the release name. Unfortunately, this pattern is
  present in multiple charts and it would be too much to unwind at this time.
*/}}
{{- define "chainlink-cluster.fullname" -}}
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
{{- define "chainlink-cluster.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "chainlink-cluster.serviceAccountName" -}}
{{- default (include "chainlink-cluster.fullname" .) .Values.serviceAccount.name }}
{{- end }}

{{/*
Define the total cluster size
*/}}
{{- define "chainlink-cluster.clusterSize" -}}
{{- $nodeCount := default 0 .Values.nodeCount -}}
{{- $bootNodeCount := default 0 .Values.bootNodeCount -}}
{{- printf "%d" (add $nodeCount $bootNodeCount) -}}
{{- end }}


{{/* ------- PORTS ------ */}}

{{/*
Explicitly define the ports.
The ui port is defined for the ingress template.
*/}}
{{- define "chainlink-cluster.uiPort" -}}
6688
{{- end }}
{{- define "chainlink-cluster.gatewayUserPort" -}}
5002
{{- end }}
{{- define "chainlink-cluster.gatewayNodePort" -}}
5003
{{- end }}

{{- define "chainlink-cluster.gatewayPorts" }}
ports:
- port: {{ include "chainlink-cluster.gatewayUserPort" . }}
  targetPort: gateway-user
  name: gateway-user
  protocol: TCP
- port: {{ include "chainlink-cluster.gatewayNodePort" . }}
  targetPort: gateway-node
  name: gateway-node
  protocol: TCP
{{- end }}

{{- define "chainlink-cluster.privatePorts" -}}
ports:
- port: {{ .Values.common.ports.ui | default (include "chainlink-cluster.uiPort" .) }}
  targetPort: http
  name: http
  protocol: TCP
- port: {{ .Values.common.ports.p2pv1 | default 6690 }}
  targetPort: p2pv1
  name: p2pv1
  protocol: TCP
- port: {{ .Values.common.ports.p2pv2 | default 5001 }}
  targetPort: p2pv2
  name: p2pv2
  protocol: TCP
{{- end }}

{{- define "chainlink-cluster.publicPorts" -}}
ports:
- port: {{ .Values.common.ports.p2pv1 | default 6690 }}
  targetPort: p2pv1
  name: p2pv1
  protocol: TCP
- port: {{ .Values.common.ports.p2pv2 | default 5001 }}
  targetPort: p2pv2
  name: p2pv2
  protocol: TCP
{{- end }}

{{- define "chainlink-cluster.policyPrivatePorts" -}}
{{- $global := . -}}
{{- range (fromYaml (include "chainlink-cluster.privatePorts" $global)).ports }}
{{- if not (has . (fromYaml (include "chainlink-cluster.publicPorts" $global)).ports) }}
- port: {{ .port }}
  protocol: {{ .protocol }}
{{- end }}
{{- end }}
{{- end }}

{{- define "chainlink-cluster.policyPublicPorts" -}}
{{- $global := . -}}
{{- if .Values.common.service.public.enabled }}
{{- range (fromYaml (include "chainlink-cluster.publicPorts" $global)).ports }}
- port: {{ .port }}
  protocol: {{ .protocol }}
{{- end }}
{{- end }}
{{- end }}

{{- define "chainlink-cluster.policyGatewayPorts" -}}
{{- if .Values.gatewayMode.enabled }}
{{- range (fromYaml (include "chainlink-cluster.gatewayPorts" .)).ports }}
- port: {{ .port }}
  protocol: {{ .protocol }}
{{- end }}
{{- end }}
{{- end }}

{{/* Map service ports to containerPorts */}}
{{- define "chainlink-cluster.mapContainerPorts" -}}
{{- $uniqPorts := uniq (concat
    (fromYaml (include "chainlink-cluster.publicPorts" . )).ports
    (fromYaml (include "chainlink-cluster.privatePorts" . )).ports
  )
-}}
{{- range $uniqPorts }}
- containerPort: {{ .port }}
  name: {{ .targetPort }}
  protocol: {{ .protocol }}
{{- end }}
{{- if .Values.gatewayMode.enabled }}
{{- range (fromYaml (include "chainlink-cluster.gatewayPorts" .)).ports }}
- containerPort: {{ .port }}
  name: {{ .targetPort }}
  protocol: {{ .protocol }}
{{- end }}
{{- end }}
{{- end }}

{{/* ------- MERGE LOGIC ------ */}}

{{/* 
  Merge common values w/ overrides
  input: dict (.common .overrides .idx)
  output: yaml
*/}}
{{- define "chainlink-cluster.merged" -}}
{{- $common := .common -}}
{{- $overrides := default dict -}}
{{- $idx := .idx -}}
{{- $ele := add1 $idx -}}
{{- if ge (len .overrides) $ele }}
  {{- $overrides = index .overrides $idx -}}
{{- end }}
{{- $merged := merge $overrides $common -}}
{{- $merged | toYaml | nindent 0 }}
{{- end -}}

{{/*
  Generates node name
  input: dict (.global .merged .idx)
  output: string
*/}}
{{- define "chainlink-cluster.nodeName" -}}
{{- $global := .global -}}
{{- $merged := .merged -}}
{{- $idx := .idx -}}
{{- $nodeIdx := (sub $idx $global.Values.bootNodeCount) -}}
{{- $bootIdx := $nodeIdx -}}
{{- $nodeName := printf "%s-%s" (include "chainlink-cluster.fullname" $global) ($nodeIdx|toString) -}}
{{- if lt $nodeIdx 0 -}}
  {{- $bootIdx = add $nodeIdx $global.Values.bootNodeCount | int -}}
  {{- $nodeName = printf "%s-%s-%s" (include "chainlink-cluster.fullname" $global) $global.Values.bootNodeSuffix ($bootIdx|toString) -}}
{{- end -}}
{{- $nodeName }}
{{- end -}}

{{/*
  Generates the node sync phase
  input: dict (.global .idx)
  output: string
*/}}

{{- define "chainlink-cluster.syncPhase" -}}
{{- $global := .global -}}
{{- $merged := .merged -}}
{{- $idx := .idx -}}
{{- if $global.Values.syncPhases.enabled -}}
  {{- $phases := $global.Values.syncPhases.phases | int -}}
  {{- if lt $phases 1 -}}
    {{- $phases = 1 -}}
  {{- end -}}
  {{- $wave := mod $idx $phases | int -}}
  {{- add $wave 1 -}}
{{- else -}}
  0
{{- end -}}
{{- end -}}

{{/* ------- LABEL MACHINE ------ */}}

{{/*
  Generate chainlink specific labels
  Labels:
  - app.chain.link (5)
*/}}
{{- define "chainlink-cluster.chainlinkLabels" -}}
app.chain.link/blockchain: {{ (index .Values "common" "requiredLabels" "app.chain.link/blockchain") }}
app.chain.link/product: {{ (index .Values "common" "requiredLabels" "app.chain.link/product") }}
app.chain.link/network: {{ (index .Values "common" "requiredLabels" "app.chain.link/network") }}
app.chain.link/network_type: {{ (index .Values "common" "requiredLabels" "app.chain.link/network-type") }}
app.chain.link/team: {{ (index .Values "common" "requiredLabels" "app.chain.link/team") }}
{{- if .Values.common.optionalLabels }}
{{ toYaml .Values.common.optionalLabels }}
{{- end }}
{{- end }}

{{/*
  Generate labels for cluster resources
  input: dict (global)
  output: string
  labels:
  - app.kubernetes.io (5)
  - app.chain.link (5)
  - helm.sh (1)
  questions:
  - is component / instance / version label necessary for cluster? or just for instance?
*/}}
{{- define "chainlink-cluster.clusterLabels" -}}
app.kubernetes.io/component: {{ (index .Values "common" "requiredLabels" "app.kubernetes.io/component") }}
app.kubernetes.io/instance: {{ include "chainlink-cluster.fullname" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/name: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.common.image.tag | quote }}
{{ include "chainlink-cluster.chainlinkLabels" . }}
helm.sh/chart: {{ include "chainlink-cluster.chart" . }}
{{- end }}

{{/*
  Generate selector labels for cluster resources
  input: dict (global)
  output: string
  labels:
  - app.kubernetes.io (1)
*/}}
{{- define "chainlink-cluster.clusterSelectorLabels" -}}
app.kubernetes.io/name: {{ .Release.Name }}
{{- end }}

{{/*
  Generate labels for instance resources
  input: dict (.global .merged .nodeName)
  output: string
  labels:
  - app.kubernetes.io (5)
  - app.chain.link (5)
*/}}
{{- define "chainlink-cluster.instanceLabels" -}}
app.kubernetes.io/component: {{ (index .merged "requiredLabels" "app.kubernetes.io/component") }}
app.kubernetes.io/instance: {{ .nodeName }}
app.kubernetes.io/managed-by: {{ .global.Release.Service }}
app.kubernetes.io/name: {{ .global.Release.Name }}
app.kubernetes.io/version: {{ .merged.image.tag | quote }}
{{ include "chainlink-cluster.chainlinkLabels" .global }}
{{- end }}

{{/*
  Generate selector labels for instance resources
  input: dict (.global .nodeName)
  output: string
  labels:
  - app.kubernetes.io (2)
*/}}
{{- define "chainlink-cluster.instanceSelectorLabels" -}}
app.kubernetes.io/instance: {{ .nodeName }}
app.kubernetes.io/name: {{ .global.Release.Name }}
{{- end }}

{{/*
  WIP Generate scrapeconfig labels for instances
  input: dict (.global .merged .nodeName)
  output: string
  labels:
  - app.kubernetes.io (5)
  - app.chain.link (5)
*/}}
{{- define "chainlink-cluster.scrapeconfigLabels" -}}
app.kubernetes.io/component: {{ (index .merged "requiredLabels" "app.kubernetes.io/component") }}
app.kubernetes.io/instance: {{ .nodeName }}
app.kubernetes.io/managed-by: {{ .global.Release.Service }}
app.kubernetes.io/name: {{ .global.Release.Name }}
app.kubernetes.io/version: {{ .merged.image.tag | quote }}
{{ include "chainlink-cluster.chainlinkLabels" .global }}
{{- end }}

{{/*
  Generate labels
  input: dict (.global .merged)
  output: dict (.cluster .instance .selector)
*/}}
{{- define "chainlink-cluster.labelMachine" -}}
{{- $global := .global -}}
{{- $merged := .merged -}}
{{- $nodeName := .nodeName -}}
{{- $clusterLabels := (include "chainlink-cluster.clusterLabels" $global) }}
{{- $clusterSelectorLabels := (include "chainlink-cluster.clusterSelectorLabels" $global) }}
{{- $instanceLabels := (dict "global" $global "merged" $merged "nodeName" $nodeName | include "chainlink-cluster.instanceLabels") }}
{{- $instanceSelectorLabels := (dict "global" $global "nodeName" $nodeName | include "chainlink-cluster.instanceSelectorLabels") }}
{{- $scrapeconfigLabels := (dict "global" $global "merged" $merged "nodeName" $nodeName | include "chainlink-cluster.scrapeconfigLabels") }}
{{- $labels := (dict "cluster" $clusterLabels "clusterSelector" $clusterSelectorLabels "instance" $instanceLabels "instanceSelector" $instanceSelectorLabels "scrapeconfig" $scrapeconfigLabels) }}
{{- $labels | toYaml }}
{{- end }}
