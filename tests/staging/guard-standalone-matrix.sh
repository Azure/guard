#!/usr/bin/env bash

# Copyright The Guard Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Drives Guard's SubjectAccessReview webhook on a standalone across the full
# matrix: {CheckAccess v1, CheckAccess v2} x {real obo, IMDS token-proxy}.
#
# It talks to Guard directly rather than through the customer kube-apiserver, so
# it still works when the CCP has not converged - which is the common case on a
# standalone. See GUARD-STANDALONE-VALIDATION.md for the reasoning behind each
# step and for the negative controls this script encodes.
#
# Usage:
#   ./guard-standalone-matrix.sh run      --kubeconfig <cx-1> --cluster-id <REAL arm cluster id> --oid <your aad oid> [--upn <upn>]
#   ./guard-standalone-matrix.sh teardown --kubeconfig <cx-1>
#
# --cluster-id MUST be a cluster that exists in real ARM. A standalone's own
# clusters do not, so CheckAccess returns 404 and Guard false-denies everything.

set -euo pipefail

KUBECONFIG_PATH=""
REAL_CLUSTER_ID=""
SUBJECT_OID=""
SUBJECT_UPN="guard-matrix@test.invalid"
PROXY_BIN="${PROXY_BIN:-}"
REGION="${REGION:-westus2}"
# Guard caches authz decisions for --azure.cache-ttl-minutes (3 by default) and
# Azure role assignments take their own time, so every assertion is polled.
RETRIES="${RETRIES:-6}"
RETRY_SLEEP="${RETRY_SLEEP:-45}"

WORKDIR="$(mktemp -d)"
PASS=0
FAIL=0

# setup_client extracts the cluster's real mTLS client key into WORKDIR, so the
# directory must not outlive the run. The trap covers the abort paths too: die()
# exits non-zero, and `set -e` can end the script from any assertion.
cleanup_workdir() {
    [[ -n "${WORKDIR:-}" && -d "$WORKDIR" ]] && rm -rf "$WORKDIR"
    return 0
}
trap cleanup_workdir EXIT INT TERM

log() { printf '  %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*" >&2; }
die() {
    printf '\nSTOP: %s\n' "$*" >&2
    exit 1
}
k() { KUBECONFIG="$KUBECONFIG_PATH" kubectl "$@"; }

# --- discovery ---------------------------------------------------------------

# find_ccp_namespace locates the CCP namespace by looking for the guard
# deployment rather than guessing from a cluster name, because the namespace is
# the CCP id and is not derivable from anything the caller knows.
find_ccp_namespace() {
    local ns
    ns=$(k get deploy --all-namespaces -o json |
        python3 -c "import json,sys;print(next((i['metadata']['namespace'] for i in json.load(sys.stdin)['items'] if i['metadata']['name']=='guard'),''))")
    [[ -n "$ns" ]] || die "no 'guard' deployment found; is this the cx underlay kubeconfig?"
    printf '%s' "$ns"
}

# read_node_identity reads the kubelet managed identity off an infra node. These
# nodes carry several user-assigned identities, so IMDS refuses to pick one and
# the value must come from the node's own azure.json. It dies rather than
# returning empty: an empty --mi-client-id makes IMDS fail at request time, which
# would surface as a confusing token error several steps later.
read_node_identity() {
    local pod=guard-matrix-idread out
    k -n tokenlab delete pod "$pod" --ignore-not-found >/dev/null 2>&1 || true
    k -n tokenlab run "$pod" --image=curlimages/curl:8.10.1 --restart=Never \
        --overrides="$(infra_overrides "$pod" '["sh","-c","cat /host/etc/kubernetes/azure.json"]' true)" \
        >/dev/null
    for _ in $(seq 1 45); do
        [[ "$(k -n tokenlab get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null)" == "Succeeded" ]] && break
        sleep 2
    done
    out=$(k -n tokenlab logs "$pod" 2>/dev/null | python3 -c "
import json,sys
try: print(json.load(sys.stdin).get('userAssignedIdentityID',''))
except Exception: print('')
")
    [[ "$out" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
        die "could not read userAssignedIdentityID from an infra node (got '${out:-<empty>}'); the IMDS rows would be vacuous"
    k -n tokenlab delete pod "$pod" --ignore-not-found >/dev/null 2>&1 || true
    printf '%s' "$out"
}

# infra_overrides builds the pod spec fragment that pins a pod to the infra
# pool, which is where obo runs and therefore where the swap has to happen.
infra_overrides() {
    local name="$1" cmd="$2" hostpath="${3:-false}"
    local mounts="" vols=""
    if [[ "$hostpath" == "true" ]]; then
        mounts=',"volumeMounts":[{"name":"h","mountPath":"/host","readOnly":true}],"securityContext":{"runAsUser":0}'
        vols=',"volumes":[{"name":"h","hostPath":{"path":"/"}}]'
    fi
    cat <<EOF
{"spec":{"tolerations":[{"key":"agentpool","operator":"Equal","value":"infra","effect":"NoSchedule"}],
"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[
{"matchExpressions":[{"key":"agentpool","operator":"In","values":["infra"]}]}]}}},
"containers":[{"name":"$name","image":"curlimages/curl:8.10.1","command":$cmd$mounts}]$vols}}
EOF
}

# --- harness setup -----------------------------------------------------------

# setup_client extracts the very cert the kube-apiserver uses. Guard rejects any
# request whose peer cert has no Organization, and only serves orgs it has a
# provider for, so a self-signed cert will not do.
setup_client() {
    local ns="$1"
    k get ns tokenlab >/dev/null 2>&1 || k create ns tokenlab >/dev/null

    k -n "$ns" get secret authwebhook-config -o json | python3 -c "
import json,sys,base64,re
d=json.load(sys.stdin)['data']
y=base64.b64decode(d['authzWebhook-apiserver-client-config.yaml']).decode()
for field,out in (('client-certificate-data','client.crt'),('client-key-data','client.key')):
    m=re.search(field+r':\s*(\S+)',y)
    if not m: raise SystemExit('missing '+field+' in authwebhook-config')
    open('$WORKDIR/'+out,'wb').write(base64.b64decode(m.group(1)))
"
    k -n "$ns" get secret guard-pki -o json | python3 -c "
import json,sys,base64
open('$WORKDIR/ca.crt','wb').write(base64.b64decode(json.load(sys.stdin)['data']['ca.crt']))
"
    local subj
    subj=$(openssl x509 -in "$WORKDIR/client.crt" -noout -subject)
    [[ "$subj" == *"O=azure"* ]] || die "client cert has no O=azure ($subj); Guard will reject it"
    log "client cert ok: $subj"

    k -n tokenlab delete secret guard-client --ignore-not-found >/dev/null 2>&1 || true
    k -n tokenlab create secret generic guard-client \
        --from-file=client.crt="$WORKDIR/client.crt" \
        --from-file=client.key="$WORKDIR/client.key" \
        --from-file=ca.crt="$WORKDIR/ca.crt" >/dev/null

    k -n tokenlab delete pod guardcli --ignore-not-found >/dev/null 2>&1 || true
    k -n tokenlab run guardcli --image=curlimages/curl:8.10.1 --restart=Never \
        --overrides="$(
            cat <<EOF
{"spec":{"tolerations":[{"key":"agentpool","operator":"Equal","value":"infra","effect":"NoSchedule"}],
"containers":[{"name":"guardcli","image":"curlimages/curl:8.10.1","command":["sleep","14400"],
"volumeMounts":[{"name":"c","mountPath":"/certs","readOnly":true}]}],
"volumes":[{"name":"c","secret":{"secretName":"guard-client"}}]}}
EOF
        )" >/dev/null
    k -n tokenlab wait --for=condition=Ready pod/guardcli --timeout=180s >/dev/null
    write_sar_bodies
}

# write_sar_bodies emits the allow case and the deny case. extra.oid is required:
# without it Guard classifies the caller as a non-AAD user and denies before it
# ever reaches Azure, which would look like a policy decision but is not one.
write_sar_bodies() {
    for res in pods secrets; do
        cat >"$WORKDIR/sar-$res.json" <<EOF
{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{
 "user":"$SUBJECT_UPN","extra":{"oid":["$SUBJECT_OID"]},
 "resourceAttributes":{"namespace":"default","verb":"list","group":"","resource":"$res"}}}
EOF
        k -n tokenlab cp "$WORKDIR/sar-$res.json" "guardcli:/tmp/sar-$res.json" >/dev/null
    done
}

# --- guard configuration -----------------------------------------------------

# configure_guard rewrites guard's args for the requested CheckAccess version and
# always repoints --azure.resource-id at a real ARM cluster.
#
# The rollout restart is NOT redundant with the patch. Consecutive rows often
# produce byte-identical args (e.g. v1+obo then v1+imds), so `kubectl patch` is a
# no-op, no new pods are created, and guard keeps serving from the authz token it
# already cached - which it fetched from the PREVIOUS row's token source, valid
# for ~24h. That makes the following row pass without ever contacting its own
# token source. Restarting unconditionally forces a fresh process and a fresh
# token fetch, which is what makes an IMDS row actually exercise IMDS.
configure_guard() {
    local ns="$1" version="$2" region="$3"
    k -n "$ns" get deploy guard -o json | python3 -c "
import json,sys
d=json.load(sys.stdin)
cs=d['spec']['template']['spec']['containers']
gi=[i for i,c in enumerate(cs) if c['name']=='guard'][0]
drop=('--azure.use-checkaccess-v2','--azure.pdp-endpoint','--azure.pdp-scope','--azure.resource-id')
args=[a for a in cs[gi]['args'] if not a.startswith(drop)]
args.append('--azure.resource-id=$REAL_CLUSTER_ID')
if '$version' == 'v2':
    args += ['--azure.use-checkaccess-v2=true',
             '--azure.pdp-endpoint=https://$region.authorization.azure.net',
             '--azure.pdp-scope=https://authorization.azure.net/.default']
print(json.dumps({'spec':{'template':{'spec':{'containers':[{'name':'guard','args':args}]}}}}))
" >"$WORKDIR/guard-patch.json"
    k -n "$ns" patch deploy guard --type=strategic --patch-file "$WORKDIR/guard-patch.json" >/dev/null
    k -n "$ns" rollout restart deploy/guard >/dev/null
    k -n "$ns" rollout status deploy/guard --timeout=240s >/dev/null
    log "guard configured for $version (restarted; token + decision caches cleared)"
}

# --- token source swap -------------------------------------------------------

start_imds_proxy() {
    local mi="$1"
    [[ -n "$PROXY_BIN" && -f "$PROXY_BIN" ]] || die "--proxy-bin is required for the IMDS rows (static linux/amd64 build of tests/mock-server/token-proxy)"
    k -n obo delete pod obo-tokenlab --ignore-not-found --wait=true >/dev/null 2>&1 || true
    k -n obo run obo-tokenlab --image=curlimages/curl:8.10.1 --restart=Never \
        --labels="app=obo,variant=tokenlab" \
        --overrides="$(infra_overrides obo-tokenlab '["sleep","14400"]')" >/dev/null
    k -n obo wait --for=condition=Ready pod/obo-tokenlab --timeout=180s >/dev/null
    k -n obo cp "$PROXY_BIN" obo-tokenlab:/tmp/token-proxy >/dev/null
    k -n obo exec obo-tokenlab -- sh -c \
        "chmod +x /tmp/token-proxy && nohup /tmp/token-proxy --mode=imds --mi-client-id=$mi --port=8080 >/tmp/proxy.log 2>&1 & sleep 3" >/dev/null
    k -n obo scale deployment/obo --replicas=0 >/dev/null
    sleep 8
    assert_single_endpoint obo-tokenlab
}

use_real_obo() {
    k -n obo delete pod obo-tokenlab --ignore-not-found --wait=true >/dev/null 2>&1 || true
    k -n obo scale deployment/obo --replicas=1 >/dev/null
    k -n obo rollout status deploy/obo --timeout=180s >/dev/null
    sleep 5
}

# assert_single_endpoint guards against the silent-vacuity failure: a reconciler
# can scale obo back up, leaving the Service round-robining between the real obo
# and the proxy, so an "IMDS" row may never touch the proxy at all.
assert_single_endpoint() {
    local want="$1" got
    got=$(k -n obo get endpoints obo -o json | python3 -c "
import json,sys
print(','.join(a.get('targetRef',{}).get('name','?') for s in json.load(sys.stdin).get('subsets',[]) for a in s.get('addresses',[])))")
    [[ "$got" == "$want" ]] || die "obo Service endpoints are '$got', expected only '$want' - result would be non-deterministic"
    log "obo endpoints: $got"
}

# --- assertions --------------------------------------------------------------

sar() {
    local ns="$1" res="$2"
    k -n tokenlab exec guardcli -- sh -c \
        "curl -sS --cacert /certs/ca.crt --cert /certs/client.crt --key /certs/client.key \
     -H 'Content-Type: application/json' -X POST -d @/tmp/sar-$res.json \
     https://guard.$ns.svc.cluster.local:443/subjectaccessreviews" 2>/dev/null
}

# expect polls because a fresh role assignment is invisible until Azure has
# propagated it AND guard's decision cache has expired; a single shot reports a
# false failure. Reported reasons are kept so a wrong-but-green answer is visible.
expect() {
    local ns="$1" res="$2" want="$3" label="$4" body allowed reason
    for attempt in $(seq 1 "$RETRIES"); do
        body=$(sar "$ns" "$res" || true)
        allowed=$(printf '%s' "$body" | python3 -c "
import sys,json
try: print(json.loads(sys.stdin.read().strip().splitlines()[0])['status'].get('allowed',False))
except Exception: print('ERR')" 2>/dev/null)
        if [[ "$allowed" == "$want" ]]; then
            reason=$(printf '%s' "$body" | python3 -c "
import sys,json
try: print(str(json.loads(sys.stdin.read().strip().splitlines()[0])['status'].get('reason','')).splitlines()[0][:80])
except Exception: print('')" 2>/dev/null)
            printf '  PASS  %-28s %s=%s  %s\n' "$label" "$res" "$allowed" "$reason"
            PASS=$((PASS + 1))
            return 0
        fi
        [[ "$attempt" -lt "$RETRIES" ]] && sleep "$RETRY_SLEEP"
    done
    reason=$(printf '%s' "$body" | python3 -c "
import sys,json
try: print(str(json.loads(sys.stdin.read().strip().splitlines()[0])['status'].get('reason',''))[:200])
except Exception: print('<unparseable>')" 2>/dev/null)
    printf '  FAIL  %-28s %s: got allowed=%s want %s\n        %s\n' "$label" "$res" "$allowed" "$want" "$reason"
    FAIL=$((FAIL + 1))
    return 0
}

# assert_imds_used proves the IMDS rows were not silently served by real obo, or
# by a guard process still holding a token cached from an earlier row.
# `grep -c` prints 0 AND exits 1 when there is no match, so the count is scrubbed
# to digits rather than relying on the exit status.
assert_imds_used() {
    local hits
    hits=$(k -n obo exec obo-tokenlab -- sh -c "grep -c 'grant=imds-direct' /tmp/proxy.log || true" 2>/dev/null | tr -dc '0-9')
    hits=${hits:-0}
    if [[ "$hits" -gt 0 ]]; then
        printf '  PASS  %-28s proxy served %s imds-direct authztoken(s)\n' "imds-actually-used" "$hits"
        PASS=$((PASS + 1))
    else
        printf '  FAIL  %-28s proxy log has no grant=imds-direct - row was VACUOUS\n' "imds-actually-used"
        FAIL=$((FAIL + 1))
    fi
}

# --- matrix ------------------------------------------------------------------

# assert_obo_endpoint_absent is the mirror guard for the real-obo rows: the
# tokenlab proxy must be gone, or an "obo" row could be served by the proxy.
assert_obo_endpoint_absent() {
    local got
    got=$(k -n obo get endpoints obo -o json | python3 -c "
import json,sys
print(','.join(a.get('targetRef',{}).get('name','?') for s in json.load(sys.stdin).get('subsets',[]) for a in s.get('addresses',[])))")
    [[ -n "$got" ]] || die "obo Service has no endpoints at all"
    [[ "$got" != *"obo-tokenlab"* ]] || die "obo Service still routes to the tokenlab proxy ('$got')"
    log "obo endpoints: $got"
}

run_row() {
    local ns="$1" version="$2" source="$3" region="$4" mi="$5"
    step "$version + $source"
    if [[ "$source" == "imds" ]]; then
        start_imds_proxy "$mi"
    else
        use_real_obo
        assert_obo_endpoint_absent
    fi
    configure_guard "$ns" "$version" "$region" # rollout also clears guard's caches
    expect "$ns" pods True "$version/$source allow"
    expect "$ns" secrets False "$version/$source deny"
    [[ "$source" == "imds" ]] && assert_imds_used || true
}

cmd_run() {
    [[ -n "$REAL_CLUSTER_ID" ]] || die "--cluster-id is required (a cluster that exists in REAL ARM)"
    [[ -n "$SUBJECT_OID" ]] || die "--oid is required (the AAD object id to authorize)"
    local ns mi
    ns=$(find_ccp_namespace)
    log "CCP namespace: $ns"
    setup_client "$ns"
    mi=$(read_node_identity)
    log "node kubelet MI clientId: ${mi:-<none>}"

    run_row "$ns" v1 obo "$REGION" "$mi"
    run_row "$ns" v1 imds "$REGION" "$mi"
    run_row "$ns" v2 obo "$REGION" "$mi"
    run_row "$ns" v2 imds "$REGION" "$mi"

    printf '\n== summary ==\n  PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
    [[ "$FAIL" -eq 0 ]] || exit 1
}

cmd_teardown() {
    local ns
    ns=$(find_ccp_namespace 2>/dev/null || echo "")
    k -n obo delete pod obo-tokenlab --ignore-not-found >/dev/null 2>&1 || true
    k -n obo scale deployment/obo --replicas=1 >/dev/null 2>&1 || true
    k -n tokenlab delete pod guardcli guard-matrix-idread --ignore-not-found >/dev/null 2>&1 || true
    k -n tokenlab delete secret guard-client --ignore-not-found >/dev/null 2>&1 || true
    [[ -n "$ns" ]] && k -n "$ns" rollout restart deploy/guard >/dev/null 2>&1 || true
    log "torn down; guard's flags revert on the next overlaymgr reconcile"
    log "role assignments created for the test are NOT removed - see GUARD-STANDALONE-VALIDATION.md"
}

main() {
    local command="${1:-}"
    shift || true
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --kubeconfig)
                KUBECONFIG_PATH="$2"
                shift 2
                ;;
            --cluster-id)
                REAL_CLUSTER_ID="$2"
                shift 2
                ;;
            --oid)
                SUBJECT_OID="$2"
                shift 2
                ;;
            --upn)
                SUBJECT_UPN="$2"
                shift 2
                ;;
            --proxy-bin)
                PROXY_BIN="$2"
                shift 2
                ;;
            --region)
                REGION="$2"
                shift 2
                ;;
            *) die "unknown argument: $1" ;;
        esac
    done
    [[ -n "$KUBECONFIG_PATH" ]] || die "--kubeconfig <cx-1 underlay kubeconfig> is required"
    case "$command" in
        run) cmd_run ;;
        teardown) cmd_teardown ;;
        *) die "usage: $0 {run|teardown} --kubeconfig <path> [--cluster-id <arm id>] [--oid <aad oid>] [--proxy-bin <path>] [--region <r>]" ;;
    esac
}

main "$@"
