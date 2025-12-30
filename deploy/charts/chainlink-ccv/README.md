# chainlink-cluster

![Version: 2.12.2](https://img.shields.io/badge/Version-2.12.2-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 2.14.0](https://img.shields.io/badge/AppVersion-2.14.0-informational?style=flat-square)

A Helm chart for Chainlink in Kubernetes

## Installation

#### Installation w/o provisioner locally

Installation on local cluster has been tested with [`k3d`](https://github.com/k3d-io/k3d).

If the architecture of your local machine is `amd64`, the public chainlink image can be used. If the architecture is `arm64`, the image needs to be built from source or copied from private sdlc account.

```sh
# set env vars
export AWS_ACCOUNT="<number>"
export AWS_REGION="<region>"
export CHART_VERSION="<version>"

# login to ecr registry
aws ecr get-login-password --region us-west-2 |
  docker login --username AWS --password-stdin $AWS_ACCOUNT.dkr.ecr.us-west-2.amazonaws.com

# pull image
docker pull $AWS_ACCOUNT.dkr.ecr.us-west-2.amazonaws.com/chainlink-develop:develop

# retag image
docker tag 795953128386.dkr.ecr.us-west-2.amazonaws.com/chainlink-develop:develop localhost:5001/chainlink:local

# import image into k3d
k3d image import localhost:5001/chainlink:local --cluster chainlink
```

Once the docker image has been sourced / built:

- create `chainlink` namespace

```sh
kubectl create namespace chainlink
```

- install postgres instance

```sh
helm install pg oci://registry-1.docker.io/bitnamicharts/postgresql -n chainlink -f values.pg.yaml
```

- install chainlink node(s)

```sh
helm template cln-misc-s-n . \
-n chainlink \
-f shared.v2Config-defaults.yaml \
-f shared.v2Config-rpc-ethereum-sepolia.yaml \
-f values.single-node.yaml \
-f shared.deploy-local.yaml \
> debug.single-node.local.yaml
# | kubectl apply -f -
# | kubectl delete -f -
```

#### Installation w/ provisioner on AWS EKS

- `values.single-node.yaml`: deploy single node on testnet (sepolia)

```sh
helm template cln-misc-s-n . \
-n chainlink \
-f shared.v2Config-defaults.yaml \
-f shared.v2Config-rpc-ethereum-sepolia.yaml \
-f values.single-node.yaml \
-f shared.deploy-eks.yaml \
> debug.single-node.yaml
# | kubectl apply -f -
# | kubectl delete -f -
```

- `values.single-boot.yaml`: deploy single boot node on testnet (sepolia)

```sh
helm template cln-misc-s-b . \
-n chainlink \
-f shared.v2Config-defaults.yaml \
-f shared.v2Config-rpc-ethereum-sepolia.yaml \
-f values.single-boot.yaml \
-f shared.deploy-eks.yaml \
> debug.single-boot.yaml
# | kubectl apply -f -
# | kubectl delete -f -
```

- `values.multi-node.yaml`: deploy multiple nodes on testnet (sepolia)

```sh
helm template clc-misc-m-n . \
-n chainlink \
-f shared.v2Config-defaults.yaml \
-f shared.v2Config-rpc-ethereum-sepolia.yaml \
-f values.multi-node.yaml \
-f shared.deploy-eks.yaml \
> debug.multi-node.yaml
# | kubectl apply -f -
# | kubectl delete -f -
```

- `values.multi-boot.yaml`: deploy multiple boot nodes on testnet (sepolia)

```sh
helm template clc-misc-m-b . \
-n chainlink \
-f shared.v2Config-defaults.yaml \
-f shared.v2Config-rpc-ethereum-sepolia.yaml \
-f values.multi-boot.yaml \
-f shared.deploy-eks.yaml \
> debug.multi-boot.yaml
# | kubectl apply -f -
# | kubectl delete -f -
```

- `values.multi-node-single-boot.yaml`: deploy multiple nodes and single boot node on testnet (sepolia)

```sh
helm template clc-misc-m-n-s-b . \
-n chainlink \
-f shared.deploy-eks.yaml \
-f shared.v2Config-defaults.yaml \
-f shared.v2Config-rpc-ethereum-sepolia.yaml \
-f values.multi-node-single-boot.yaml \
> debug.multi-node-single-boot.yaml
# | kubectl apply -f -
# | kubectl delete -f -
```

- `values.multi-node-multi-boot.yaml`: deploy multiple nodes and multiple boot nodes on testnet (sepolia)

```sh
helm template clc-misc-m-n-s-b . \
-n chainlink \
-f shared.v2Config-defaults.yaml \
-f shared.v2Config-rpc-ethereum-sepolia.yaml \
-f values.multi-node-multi-boot.yaml \
-f shared.deploy-eks.yaml \
> debug.multi-node-multi-boot.yaml
# | kubectl apply -f -
# | kubectl delete -f -
```

## Development

### Testing

Unit testing is done using the [helm unittest](https://github.com/helm-unittest/helm-unittest) plugin. To install the plugin run:

```sh
helm plugin install https://github.com/helm-unittest/helm-unittest.git
```

Currently, we have only implemented snapshot testing for each of the different types of configs. To run the test suite, run:

```sh
helm unittest .
```

When developing, we should add a new test case for all new functionality. There should be a test to run it locally and on our AWS EKS clusters. To update the snapshots, run:

```sh
helm unittest -u .
```

Example output testing each config:

```sh
➜ helm unittest .

### Chart [ chainlink-cluster ] .

 PASS  test multi node local    tests/multi_node_local_test.yaml
 PASS  test multi node multi boot local tests/multi_node_multi_boot_local_test.yaml
 PASS  test multi node multi boot       tests/multi_node_multi_boot_test.yaml
 PASS  test multi node single boot local        tests/multi_node_single_boot_local_test.yaml
 PASS  test multi node single boot      tests/multi_node_single_boot_test.yaml
 PASS  test multi node single boot vpn  tests/multi_node_single_boot_vpn_test.yaml
 PASS  test multi node  tests/multi_node_test.yaml
 PASS  test single boot local   tests/single_boot_local_test.yaml
 PASS  test single boot tests/single_boot_test.yaml
 PASS  test single node ingress tests/single_node_ingress_test.yaml
 PASS  test single node local   tests/single_node_local_test.yaml
 PASS  test single node rollout tests/single_node_rollout_test.yaml
 PASS  test single node tests/single_node_test.yaml
 PASS  test single node vpn     tests/single_node_vpn_test.yaml

Charts:      1 passed, 1 total
Test Suites: 14 passed, 14 total
Tests:       14 passed, 14 total
Snapshot:    256 passed, 256 total
Time:        268.808375ms
```

### Packaging

Below are the steps to package the helm chart and push to an aws oci registry:

```sh
# set env vars
export AWS_ACCOUNT="<number>"
export AWS_REGION="<region>"
export CHART_VERSION="<version>"

# login to ecr registry
aws ecr get-login-password --region "$AWS_REGION" |
  helm registry login --username AWS --password-stdin $AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/infra-charts

# package charts into tgz
helm package -u -d packages .

# push package to ecr registry
helm push "packages/chainlink-cluster-$CHART_VERSION.tgz" oci://$AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/infra-charts
```

## Resources

The following resources are created through this helm chart:

- service account: `name=<instance>`
- role: `name=<instance>-role`
- role binding: `name=<instance>-rolebinding`
- network policies (optional): `name=<instance>-netpol`
- per node:
  - deployment / rollout: `name=<instance>-<idx>`
  - service: `name=<instance>-<idx>`
  - configmap v2: `name=<instance>-<idx>-cm-v2`
  - configmap env: `name=<instance>-<idx>-cm-env`
  - chainlinknode: `name=<instance>-<idx>`
    - secret db: `name=<instance>-<idx>-db`
    - secret creds: `name=<instance>-<idx>-creds`
    - secret v2: `name=<instance>-<idx>-v2`
  - analysis template (optional): `name=<instance>-<idx>-hc`
  - service preview (optional): `name=<instance>-<idx>-preview`
  - servicemonitor (optional): `name=<instance>-<idx>`
  - ingress (optional): `name=<instance>-<idx>`
  - service public (optional): `name=<instance>-<idx>-pub`
  - secrets user defined v2 (optional): `name=<instance>-<idx>-usr-v2`
  - oraclestore (optional): `name=<instance>-<idx>`

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| appLabelOverride | string | `""` |  |
| bootNodeCount | int | `0` | boot node size / count |
| bootNodeSuffix | string | `"bt"` | boot name suffix |
| common | object | `{}` | common values for each node |
| common.affinity | object | `{}` | affinity for node pods |
| common.chainlink | object | `{}` | chainlink node configuration |
| common.chainlink.configEnv | object | `{}` | node env configuration |
| common.chainlink.extraConfig | object | `{}` | node extra configuration files |
| common.chainlink.v2Config | object | `{}` | node toml configuration |
| common.chainlink.v2Secret | object | `{}` | node secret toml configuration |
| common.chainlinkNode | object | `{"enabled":true,"existingSecret":false,"metadata":{"annotations":{"chainlinknode.k8s.chain.link/preserve-ssm":"true"}},"spec":{"credentials":{"config":{"api":{"key":".api","password":"","user":"admin@chain.link"},"keystore":{"key":".keystore","password":""},"vrf":{"key":".vrf","password":""}},"secretName":"","storageType":"aws:ssm"},"database":{"config":{"database":"","host":"","password":"","port":"5432","user":""},"secretName":"","storageType":"aws:ssm"}}}` | chainlinkNode custom resource configuration |
| common.gateway | object | `{"annotations":{},"enabled":false,"hosts":[],"name":"internal","namespace":"envoy-gateway-system"}` | gateway configuration (Gateway API HTTPRoute) |
| common.image | object | `{"pullPolicy":"IfNotPresent","repository":"public.ecr.aws/chainlink/chainlink","tag":null}` | node image configuration |
| common.imagePullSecrets | list | `[]` | image pull secrets if using private docker registry |
| common.ingress | object | `{"annotations":{},"enabled":false,"hosts":[{"host":"chainlink-node-%s.local","paths":[{"path":"/","pathType":"ImplementationSpecific"}],"useNodeName":false}],"ingressClassName":"alb","tls":[]}` | node ingress configuration |
| common.initContainers | object | `{"initDbCheck":{"image":{"pullPolicy":"IfNotPresent","repository":"925774240219.dkr.ecr.us-west-2.amazonaws.com/containers/debian-12/postgresql","tag":"16.10.0-debian-12-r9"},"securityContext":{}}}` | init containers |
| common.nodeSelector | object | `{}` | node labels for node pods assignment |
| common.oraclestore | object | `{"enabled":false,"metadata":{"annotations":{"k8s.chain.link/disable-pg-creation":"false"}},"spec":{"dbAlias":"debug","type":"aws:ps"}}` | oraclestore custom resource configuration |
| common.otel.LogLevel | string | `""` | log level for telemetry |
| common.otel.LogStreamingEnabled | bool | `false` | enable log streaming |
| common.otel.chipIngressURL | string | `""` | chip ingress url default |
| common.otel.configOverrides | object | `{"service":{"pipelines":{"logs":{"exporters":{"debug":false}},"metrics":{"exporters":{"debug":false}},"traces":{"exporters":{"debug":false}}},"telemetry":{"logs":{"encoding":"json","level":"INFO"}}}}` | otel config overrides |
| common.otel.configVersion | string | `"v1"` | logical configuration version tag injected as resource attribute `config_version`. Bump this (without needing a chart release) to correlate telemetry with config rollouts. Example overrides: --set common.otel.configVersion=v2 or via a values file. |
| common.otel.deployedBy | string | `"chainlink-labs"` | value of enforced resource attribute to differentiate internal vs external NOPs |
| common.otel.enabled | bool | `false` | otel sidecar enable container |
| common.otel.env | list | `[{"name":"POD_IP","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"status.podIP"}}},{"name":"POD_NAME","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.name"}}},{"name":"OTEL_RESOURCE_ATTRIBUTES_POD_NAME","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.name"}}},{"name":"OTEL_RESOURCE_ATTRIBUTES_POD_UID","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.uid"}}},{"name":"OTEL_RESOURCE_ATTRIBUTES_NODE_NAME","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"spec.nodeName"}}}]` | otel sidecar env vars |
| common.otel.gatewayURL | string | `"https://staging.telemetry.chain.link:443"` | otel sidecar OTLP exporter endpoint |
| common.otel.image | object | `{"pullPolicy":"IfNotPresent","repository":"otel/opentelemetry-collector-contrib","tag":"0.126.0"}` | otel sidecar image |
| common.otel.ports | object | `{"grpc":4317,"http":4318,"metrics":8888}` | otel sidecar ports numbers |
| common.otel.receivers | object | `{"grpc":{"max_recv_msg_size_mib":16}}` | otel receiver max message size configuration |
| common.otel.receivers.grpc.max_recv_msg_size_mib | int | `16` | maximum receive message size in MiB for gRPC receiver (default: 4 MiB) |
| common.otel.resourceAttributes | object | `{}` | otel resource attributes |
| common.otel.resourceAttributesOverrides | object | `{}` | otel resource attributes overrides |
| common.otel.resources | object | `{"limits":{"cpu":"250m","memory":"256Mi"},"requests":{"cpu":"125m","memory":"128Mi"}}` | otel sidecar resource request and limits |
| common.otel.securityContext | object | `{}` | otel sidecar container security context |
| common.otel.telemetry | object | `{"traceSampleRatio":0.01}` | node otel traceSampleRatio config |
| common.persistence | object | `{"enabled":false,"mountPath":"/home/chainlink/data","size":"1Gi"}` | persistence |
| common.podAnnotations | object | `{}` | node pods annotations |
| common.podSecurityContext | object | `{}` | node pods security context |
| common.ports | object | `{"p2pv1":null,"p2pv2":null,"ui":null,"vpn":null}` | node ports, defaults defined under common/_helpers.tpl |
| common.requiredLabels | object | `{"app.chain.link/blockchain":null,"app.chain.link/network":null,"app.chain.link/network-type":null,"app.chain.link/product":null,"app.chain.link/team":null,"app.kubernetes.io/component":null}` | required selector labels used by Prometheus and Loki, see templates/_helpers.tpl |
| common.resources | object | `{"limits":{"cpu":"500m","memory":"1024Mi"},"requests":{"cpu":"250m","memory":"512Mi"}}` | node resource configuration |
| common.scrapeconfig | object | `{"enabled":false}` | prometheus scrapeconfig to scrap metrics |
| common.securityContext | object | `{}` | node container security context |
| common.service.private | object | `{"type":"ClusterIP"}` | node private service |
| common.service.public | object | `{"enabled":false,"host":"chainlink-cluster-%s.public"}` | node public service |
| common.servicemonitor | object | `{"enabled":true}` | prometheus servicemonitor to scrape metrics |
| common.tolerations | list | `[]` | tolerations for node pods assignment |
| common.vpn | object | `{"awsDNS":null,"config":{},"enabled":false,"image":{"pullPolicy":"IfNotPresent","repository":"804282218731.dkr.ecr.us-west-2.amazonaws.com/wireguard-client","tag":"sha-f3e053c"},"rdsCidr":null,"securityContext":{"capabilities":{"add":["NET_ADMIN"]},"fsGroup":1000,"runAsGroup":1000,"runAsUser":1000},"vpnCidr":null,"vpnEndpoint":null}` | vpn node configuration |
| cribNetworkPolicy | object | `{"egress":{"extraEgressRules":[]},"enabled":false,"ingress":{"customCidrs":[],"extraIngressSelectors":[]}}` | custom network policy for CRIB Environments |
| enabled | bool | `true` | enable cluster |
| fullnameOverride | string | `""` |  |
| gatewayMode | object | `{"allowEgressToJobDistributor":false,"enableEgressNetworkPolicy":true,"enabled":false,"public":false,"rdsCidr":null,"serviceType":"NodePort"}` | gateway configuration |
| nameOverride | string | `""` |  |
| networkPolicy | object | `{"enabled":true,"internalCidr":"10.0.0.0/8"}` | network policy configuration |
| nodeCount | int | `1` | node size / count |
| overrides | list | `[]` | override values array |
| rollout | object | `{"analysisConsecutiveErrorLimit":24,"analysisInitialDelay":"10s","analysisInterval":"10s","enabled":false,"progressDeadlineSeconds":180}` | argo rollouts configuration |
| syncPhases | object | `{"enabled":false,"phases":1}` | incremental rollout sync phases for deployment/configmap |
