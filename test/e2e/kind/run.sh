#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Run a passmcp fleet as the shipped Kubernetes CronJob in a real kind
# cluster, three scheduled runs in a row, and verify what FLEET-01 to
# FLEET-06 promise from outside the process: what the pod was admitted as,
# what the runtime applied, what landed on the volume, what the logs
# carried, and every packet the pod sent.
#
#   make e2e-kind                                   # build the image from this tree
#   PASSMCP_IMAGE=ghcr.io/sebastienrousseau/passmcp@sha256:... make e2e-kind
#   KEEP_CLUSTER=1 make e2e-kind                    # leave the cluster up
#
# Run 1 is the baseline. Before run 2 the docs server's read-only tool
# stops claiming readOnlyHint, which must be critical and exit 2. Before
# run 3 the docs server is scaled to zero, which must be "unreachable" and
# exit 1. The verdict is build/e2e-kind/matrix.md; any failed row fails
# the script.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

here=test/e2e/kind
out=build/e2e-kind
cluster=${CLUSTER:-passmcp-e2e}
node=${cluster}-control-plane
arch=$(go env GOARCH)
version=${PASSMCP_VERSION:-$(git branch --show-current | sed -n 's|^feat/v||p')}
[ -n "${version}" ] || { echo "set PASSMCP_VERSION: the branch does not name one" >&2; exit 1; }
image=${PASSMCP_IMAGE:-passmcp:${version}-e2e}
fixture_image=passmcp-e2e-fixture:local
capture_image=passmcp-e2e-capture:local

for t in docker kind kubectl openssl jq python3 curl; do
  command -v "$t" >/dev/null || { echo "missing: $t" >&2; exit 1; }
done
k() { kubectl --context "kind-${cluster}" "$@"; }
step() { printf '\n=== %s\n' "$*"; }
# rollout NS DEPLOY: wait for it, and on failure say why before exiting.
rollout() {
  k -n "$1" rollout status "deploy/$2" --timeout=180s && return 0
  k -n "$1" get pods -o wide >&2
  k -n "$1" describe pods -l "app=$2" | tail -25 >&2
  k -n "$1" logs "deploy/$2" --all-containers --tail=40 >&2 || true
  exit 1
}

rm -rf "${out}"
mkdir -p "${out}"/{runs,tls,build/linux/"${arch}"}
out_abs=$(cd "${out}" && pwd)

cleanup() {
  docker rm -f "${cluster}-capture" >/dev/null 2>&1 || true
  if [ -n "${pf_pid:-}" ]; then kill "${pf_pid}" 2>/dev/null || true; fi
  if [ "${KEEP_CLUSTER:-0}" != 1 ]; then kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

step "images"
if [ -z "${PASSMCP_IMAGE:-}" ]; then
  # The same flags goreleaser builds with, and the repository Dockerfile
  # unchanged, laid out as dockers_v2 lays out its context.
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath \
    -ldflags "-s -w -X satellion.com/passmcp/cmd.Version=${version}" \
    -o "${out}/build/linux/${arch}/passmcp" ./cmd/passmcp
  docker buildx build -q --load --platform "linux/${arch}" -f Dockerfile \
    --label "org.opencontainers.image.version=${version}" \
    --label "org.opencontainers.image.revision=$(git rev-parse HEAD)$(git diff --quiet HEAD || echo -dirty)" \
    -t "${image}" "${out}/build" >/dev/null
else
  docker pull -q "${image}" >/dev/null
fi
(cd "${here}/fixture" && CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false -o "${out_abs}/build/fixture" .)
docker build -q -f "${here}/Dockerfile.fixture" -t "${fixture_image}" "${out}/build" >/dev/null
docker build -q -f "${here}/Dockerfile.capture" -t "${capture_image}" "${here}" >/dev/null
docker image save "${image}" | tar -xO manifest.json | jq -r '.[0].Config | "sha256:" + (split("/") | last)' > "${out}/image-config"
echo "passmcp image ${image} (config $(cut -c1-19 "${out}/image-config"))"

step "cluster"
kind delete cluster --name "${cluster}" >/dev/null 2>&1 || true
# A cold node can miss kubeadm's bootstrap deadline; one retry, not a loop.
kind create cluster --name "${cluster}" --wait 180s \
  || { kind delete cluster --name "${cluster}" >/dev/null 2>&1; kind create cluster --name "${cluster}" --wait 180s; }
k version -o json > "${out}/kubernetes-version.json"
kind load docker-image --name "${cluster}" "${image}" "${fixture_image}" oryd/hydra:v2.3.0@sha256:b94007e19a1f7f78157e7f4ea340da8a55b5f104a0f1198755c256f38ef32b4b 2>/dev/null \
  || kind load docker-image --name "${cluster}" "${image}" "${fixture_image}"

docker exec "${node}" crictl inspecti -o json "${image}" > "${out}/node-image.json"

step "private CA and secrets"
tls=${out}/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=passmcp e2e CA" -keyout "${tls}/ca.key" -out "${tls}/ca.crt" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=fleet-servers" -keyout "${tls}/tls.key" -out "${tls}/tls.csr" 2>/dev/null
sans="DNS:docs.fleet-servers.svc,DNS:billing.fleet-servers.svc,DNS:hydra.fleet-servers.svc"
openssl x509 -req -in "${tls}/tls.csr" -CA "${tls}/ca.crt" -CAkey "${tls}/ca.key" -CAcreateserial -days 2 \
  -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "${sans}") -out "${tls}/tls.crt" 2>/dev/null
# Seeded secrets: random, and searched for everywhere afterwards.
docs_token="e2e-docs-$(openssl rand -hex 20)"
billing_secret="e2e-billing-$(openssl rand -hex 20)"
printf '%s\n%s\n' "${docs_token}" "${billing_secret}" > "${out}/seeded-secrets"

sed "s|FIXTURE_IMAGE|${fixture_image}|" "${here}/servers.yaml" > "${out}/servers.yaml"
k create namespace fleet-servers -o name
k -n fleet-servers create secret generic e2e-tls --from-file="${tls}/tls.crt" --from-file="${tls}/tls.key" --from-file="${tls}/ca.crt" -o name
k -n fleet-servers create secret generic hydra-system --from-literal=secret="$(openssl rand -hex 32)" -o name
k -n fleet-servers create secret generic fixture-credentials --from-literal=docs-token="${docs_token}" -o name
k apply -f "${out}/servers.yaml" -o name
for d in hydra docs billing; do rollout fleet-servers "${d}"; done

step "OAuth client at Hydra"
k -n fleet-servers port-forward svc/hydra 14445:4445 >/dev/null 2>&1 &
pf_pid=$!
for _ in $(seq 1 50); do curl -fsS --cacert "${tls}/ca.crt" --resolve hydra.fleet-servers.svc:14445:127.0.0.1 \
  https://hydra.fleet-servers.svc:14445/health/ready >/dev/null 2>&1 && break; sleep 0.2; done
client=$(jq -n --arg s "${billing_secret}" '{client_name:"passmcp-fleet", client_secret:$s,
  grant_types:["client_credentials"], response_types:["token"], token_endpoint_auth_method:"client_secret_basic"}' |
  curl -fsS --cacert "${tls}/ca.crt" --resolve hydra.fleet-servers.svc:14445:127.0.0.1 \
    -H 'Content-Type: application/json' -d @- https://hydra.fleet-servers.svc:14445/admin/clients)
kill "${pf_pid}"; pf_pid=
client_id=$(jq -r .client_id <<<"${client}")
echo "client_id ${client_id}"
k -n fleet-servers set env deploy/billing "FIXTURE_CLIENT_ID=${client_id}"
rollout fleet-servers billing

step "the shipped CronJob"
k create namespace passmcp -o name
# Pod Security Admission at its strictest: the pod is only created if its
# spec meets the restricted profile.
k label namespace passmcp pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest
sed "s|image: ghcr.io/sebastienrousseau/passmcp:[^[:space:]]*|image: ${image}|" \
  examples/kubernetes/fleet-cronjob.yaml > "${out}/fleet-cronjob.yaml"
k -n passmcp apply -f "${out}/fleet-cronjob.yaml" -o name
k -n passmcp get cronjob passmcp-fleet -o json > "${out}/cronjob-as-shipped.json"
cat > "${out}/fleet.yaml" <<YAML
version: 1
pacing:
  rps: 2
  samples: 3
servers:
  - name: docs
    endpoint: https://docs.fleet-servers.svc/mcp
    credential:
      token_env: DOCS_MCP_TOKEN
  - name: billing
    endpoint: https://billing.fleet-servers.svc/mcp
    credential:
      mode: client-credentials
      client_id: ${client_id}
      client_secret_env: BILLING_CLIENT_SECRET
      token_url: https://hydra.fleet-servers.svc:4444/oauth2/token
  - name: local-stdio
    command: ["/opt/stdio/fixture", "--stdio"]
YAML
k -n passmcp create configmap passmcp-fleet --from-file=fleet.yaml="${out}/fleet.yaml" --dry-run=client -o yaml | k -n passmcp apply -f - -o name
k -n passmcp create secret generic passmcp-fleet-credentials \
  --from-literal=docs-mcp-token="${docs_token}" --from-literal=billing-client-secret="${billing_secret}" -o name
k -n passmcp create configmap e2e-ca --from-file=ca.crt="${tls}/ca.crt" -o name
k -n passmcp apply -o name -f - <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: passmcp-fleet-state
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 64Mi
YAML
# The test's only changes to the shipped job: trust the private CA, carry a
# stdio server in from an init container (the image ships none), and tick
# every minute instead of every six hours.
k -n passmcp patch cronjob passmcp-fleet --type=json -p "$(jq -nc --arg fx "${fixture_image}" '[
  {op:"replace", path:"/spec/schedule", value:"*/1 * * * *"},
  {op:"add", path:"/spec/suspend", value:true},
  {op:"add", path:"/spec/jobTemplate/spec/template/spec/containers/0/env/-", value:{name:"SSL_CERT_FILE", value:"/etc/passmcp-ca/ca.crt"}},
  {op:"add", path:"/spec/jobTemplate/spec/template/spec/containers/0/volumeMounts/-", value:{name:"ca", mountPath:"/etc/passmcp-ca", readOnly:true}},
  {op:"add", path:"/spec/jobTemplate/spec/template/spec/containers/0/volumeMounts/-", value:{name:"stdio", mountPath:"/opt/stdio", readOnly:true}},
  {op:"add", path:"/spec/jobTemplate/spec/template/spec/volumes/-", value:{name:"ca", configMap:{name:"e2e-ca"}}},
  {op:"add", path:"/spec/jobTemplate/spec/template/spec/volumes/-", value:{name:"stdio", emptyDir:{sizeLimit:"64Mi"}}},
  {op:"add", path:"/spec/jobTemplate/spec/template/spec/initContainers", value:[{name:"stdio-server", image:$fx,
    args:["-install","/opt/stdio/fixture"],
    securityContext:{allowPrivilegeEscalation:false, readOnlyRootFilesystem:true, capabilities:{drop:["ALL"]}},
    volumeMounts:[{name:"stdio", mountPath:"/opt/stdio"}]}]}
]')" -o name
k -n passmcp get cronjob passmcp-fleet -o json > "${out}/cronjob-effective.json"

step "the image's own version, in the cluster"
k -n passmcp run passmcp-version --image="${image}" --restart=Never --image-pull-policy=IfNotPresent \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"passmcp-version","image":"'"${image}"'","args":["version"],"securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}}}]}}' -o name
k -n passmcp wait pod/passmcp-version --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s
k -n passmcp logs passmcp-version > "${out}/passmcp-version.txt"
cat "${out}/passmcp-version.txt"

step "capture every packet from here on"
docker run -d --name "${cluster}-capture" --net "container:${node}" --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "${out_abs}:/cap" "${capture_image}" -i any -nn -U -w /cap/egress.pcap 'not host 127.0.0.1 and not port 6443 and not port 2379 and not port 2380' >/dev/null
sleep 2

snapshot() { k get pods,svc -A -o json > "${out}/runs/$1-objects.json"; }

# wait_run N: let the scheduler start the next job, wait for it to end,
# suspend the CronJob, and keep everything the run left behind.
wait_run() {
  local n=$1 dir="${out}/runs/$1" before job=
  mkdir -p "${dir}"
  before=$(k -n passmcp get jobs -o name | sort)
  k -n passmcp patch cronjob passmcp-fleet -p '{"spec":{"suspend":false}}' -o name >/dev/null
  for _ in $(seq 1 300); do
    job=$(comm -13 <(printf '%s\n' "${before}") <(k -n passmcp get jobs -o name | sort) | head -1)
    [ -n "${job}" ] && break
    sleep 2
  done
  [ -n "${job}" ] || { echo "run ${n}: the CronJob never started a job" >&2; exit 1; }
  echo "run ${n}: ${job}"
  for _ in $(seq 1 180); do
    k -n passmcp get "${job}" -o json | jq -e '[.status.conditions[]? | select(.status=="True") | .type] | any(. == "Complete" or . == "Failed")' >/dev/null && break
    sleep 5
  done
  k -n passmcp patch cronjob passmcp-fleet -p '{"spec":{"suspend":true}}' -o name >/dev/null
  k -n passmcp get "${job}" -o json > "${dir}/job.json"
  local pod
  pod=$(k -n passmcp get pods -l "job-name=${job#job.batch/}" -o name | head -1)
  k -n passmcp get "${pod}" -o json > "${dir}/pod.json"
  k -n passmcp logs "${pod}" -c passmcp > "${dir}/stdout.txt" 2>/dev/null || true
  k -n passmcp logs "${pod}" -c stdio-server > "${dir}/init.txt" 2>/dev/null || true
  local cid
  cid=$(jq -r '.status.containerStatuses[] | select(.name=="passmcp") | .containerID | sub("^containerd://"; "")' "${dir}/pod.json")
  docker exec "${node}" crictl inspect "${cid}" > "${dir}/crictl-inspect.json"
  for d in docs billing hydra; do k -n fleet-servers logs "deploy/${d}" > "${dir}/${d}.log" 2>/dev/null || true; done
  snapshot "${n}"
}

step "run 1: baseline"
wait_run 1

step "run 2: docs/lookup stops claiming readOnlyHint"
k -n fleet-servers set env deploy/docs FIXTURE_READONLY=false
rollout fleet-servers docs
wait_run 2

step "run 3: docs is unreachable"
k -n fleet-servers scale deploy/docs --replicas=0
k -n fleet-servers wait --for=delete pod -l app=docs --timeout=120s || true
wait_run 3

step "evidence"
sleep 2
docker stop "${cluster}-capture" >/dev/null
k -n passmcp get jobs -o json > "${out}/jobs.json"
k get events -A -o json > "${out}/events.json"
# Everything in the namespace but the Secret, whose value is the one place
# the credentials are supposed to be.
k -n passmcp get configmap,cronjob,job,pod -o yaml > "${out}/passmcp-namespace.yaml"
k get namespace passmcp -o json > "${out}/namespace.json"
k -n passmcp apply -o name -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: state-reader
spec:
  securityContext: {runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: reader
      image: busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
      imagePullPolicy: IfNotPresent
      command: ["sleep", "300"]
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}
      volumeMounts: [{name: state, mountPath: /data, readOnly: true}]
  volumes: [{name: state, persistentVolumeClaim: {claimName: passmcp-fleet-state, readOnly: true}}]
YAML
kind load docker-image --name "${cluster}" busybox:1.37@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e >/dev/null 2>&1 || true
k -n passmcp wait pod/state-reader --for=condition=Ready --timeout=120s
mkdir -p "${out}/state"
k -n passmcp exec state-reader -- tar -C /data -cf - . | tar -C "${out}/state" -xf -
docker run --rm -v "${out_abs}:/cap" --entrypoint tcpdump "${capture_image}" -nn -tt -r /cap/egress.pcap > "${out}/egress.txt" 2>/dev/null

step "verdict"
python3 "${here}/verify.py" "${out}"
