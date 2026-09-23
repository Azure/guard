# Guard on a standalone: SubjectAccessReview validation (v1 + v2, obo + IMDS)

Validates the Guard authorization webhook end to end **on a dev standalone**, across
both CheckAccess paths and both token sources. Every command below was run and its
output verified on **2026-09-18** against standalone `akolomeebld181518212`
(build `181518212`, westus2), CCP namespace `6aac39949cdfa7000103db7c`.

Companion runbook for the Entra/PDP mechanics: `TOKENLAB-MANUAL-VALIDATION.md`.
Automated version of everything here: `guard-standalone-matrix.sh`.

---

## Result

| token source | v1 (ARM CheckAccess) | v2 (PDP CheckAccess) |
| --- | --- | --- |
| real `obo` | PASS | PASS *only after a subscription-scope caller grant* |
| `token-proxy --mode=imds` | PASS | PASS |

Automated run, 2026-09-18 - `PASS=10 FAIL=0`, the 8 decision assertions plus both
non-vacuity checks (full output: `~/dreams/guard-standalone-matrix-2026-09-18-run.txt`):

```
== v1 + obo ==    PASS pods=True | PASS secrets=False
== v1 + imds ==   PASS pods=True | PASS secrets=False | PASS proxy served 1 imds-direct authztoken(s)
== v2 + obo ==    PASS pods=True | PASS secrets=False
== v2 + imds ==   PASS pods=True | PASS secrets=False | PASS proxy served 2 imds-direct authztoken(s)
```

In every passing cell:

```
pods/list    -> allowed=True   Role Assignment 9215ea4f... of Role 7f6c6a51b... (AKS RBAC Reader)
secrets/list -> denied=True
```

Three findings came out of this that are not documented anywhere else:

1. **A standalone's clusters are not ARM resources**, so out of the box Guard
   false-denies *everything*. Not a config gap - structural. See step 3.
2. **PDP v2 requires the caller's `checkAccess` permission at SUBSCRIPTION scope**,
   while ARM v1 accepts a CLUSTER-scope grant. See step 7.
3. **IMDS can fully replace obo** for the `/authztoken` leg, with Guard unmodified.
   See step 6.

---

## Why this is not just "run the e2ev3 scenario"

`test/e2ev3/sigs/security/aad/plans/guard_sar.go:92-95` gates its entire verification
behind `plans.IsProd()`:

> "Guard / Azure RBAC CheckAccess is only real in int/staging/prod; skip the login-VM
> verification in dev to avoid exercising an unwired PDP."

`plans.IsProd()` resolves to `DeployEnv.IsIntStagingProd()`
(`test/e2ev3/handlers/env/context.go:82`). A "Dev AKS Deploy" standalone is
`DeployEnvE2E`, i.e. `IsDevTest()`. **So that scenario provisions a cluster on a
standalone and then asserts nothing.** This document is what works instead.

---

## Step 1 - get a cluster with AAD + Azure RBAC onto the standalone

Use the `call-rp-on-standalone` skill for the mTLS/ingress scaffolding, then PUT a
managed cluster. Two things that skill does not mention, both of which fail confusingly:

```bash
# (a) Without MSI headers the RP returns:
#     500 InternalOperationError: "Identity missing essential properties: IdentityURL"
#     Supply what the intv2 ingress injects; an msi-simulator runs in the SVC underlay.
-H "x-ms-identity-url: http://msi-simulator.msi-simulator.svc.cluster.local"
-H "x-ms-identity-principal-id: 8ff738a5-abcd-4864-a162-6c18f7c9cbd9"
-H "x-ms-home-tenant-id: 72f988bf-86f1-41af-91ab-2d7cd011db47"

# (b) A fake subscription GUID registers fine, then create fails
#     404 SubscriptionNotFound - the RP calls ARM to list SKUs.
#     Use the standalone's OWN subscription, from `meta` in the
#     e2e-underlay-kubeconfig build artifact.
```

Body only needs `location`, `dnsPrefix`, one System+Linux agent pool, `identity`, and:

```json
"aadProfile": { "managed": true, "enableAzureRBAC": true, "tenantID": "<tenant>" }
```

`enableRBAC` defaults to `true` server-side, so the `createvalidator.go:344`
"RBAC required for AAD" gate passes without setting it explicitly. Verify it landed -
a 201 alone does not prove AAD was kept:

```bash
... | python3 -c "import json,sys;p=json.load(sys.stdin)['properties'];print(p['enableRBAC'],p['aadProfile'])"
```

**A broken CCP does not block this test.** On this run the CCP never converged
(`kms-service` crashloop -> KMS v2 Plus plugin fatal -> `kube-apiserver` never ready,
cluster ended `Failed`). Guard itself stayed 2/2 Running with **zero restarts**
throughout, and everything below drives Guard directly.

## Step 2 - drive Guard's webhook directly

Guard registers `m.Post("/subjectaccessreviews", ...)` (`server/server.go:228`) on
`:8443`, so the customer apiserver is not needed. Two requirements:

- **A client cert whose Organization is the provider name.** `server/authzhandler.go:40-49`
  rejects a request with no peer cert, or with no `Subject.Organization`. The apiserver's
  own cert is in CCP secret `authwebhook-config`, key
  `authzWebhook-apiserver-client-config.yaml` (`subject=O=azure, CN=azure`). The CA is
  `ca.crt` in secret `guard-pki`.
- **`spec.extra.oid`.** Without it `authz/providers/azure/azure.go:162` treats the caller
  as a non-AAD user and denies.

```bash
kubectl -n "$NS" get secret authwebhook-config -o json \
  | python3 -c "import json,sys,base64,re;d=json.load(sys.stdin)['data'];y=base64.b64decode(d['authzWebhook-apiserver-client-config.yaml']).decode();open('client.crt','wb').write(base64.b64decode(re.search(r'client-certificate-data:\s*(\S+)',y).group(1)));open('client.key','wb').write(base64.b64decode(re.search(r'client-key-data:\s*(\S+)',y).group(1)))"
kubectl -n "$NS" get secret guard-pki -o json \
  | python3 -c "import json,sys,base64;open('ca.crt','wb').write(base64.b64decode(json.load(sys.stdin)['data']['ca.crt']))"
```

The two request bodies (one expected allow, one expected deny):

```json
{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{
 "user":"<upn>","extra":{"oid":["<your AAD object id>"]},
 "resourceAttributes":{"namespace":"default","verb":"list","group":"","resource":"pods"}}}
```

```json
{... same, "resource":"secrets"}
```

```bash
curl -sS --cacert ca.crt --cert client.crt --key client.key \
  -H 'Content-Type: application/json' -X POST -d @sar.json \
  "https://guard.${NS}.svc.cluster.local:443/subjectaccessreviews"
```

## Step 3 - the default state, and why it is a FALSE deny

Unmodified, every decision comes back denied. That is **not** an RBAC evaluation:

```
rbac.go:492  "Using CheckAccess v1 API"
utils.go:544 POST https://management.azure.com/subscriptions/<standalone-sub>/.../managedClusters/guardtest/.../checkaccess
rbac.go:663  "CheckAccess request succeeded"
rbac.go:676  "CheckAccess returned 404, tracked resource deleted, returning default not found decision"
azure.go:202 allowed=false
```

obo minted a valid token and the HTTP call succeeded - **ARM returned 404 because the
cluster does not exist in ARM**. `az resource show` confirms the cluster *and its
resource group* are absent even though you have ARM access to that subscription. Guard
converts that 404 into a deny.

Same-instant PDP control, same token and subject, only the resource id differing:

| `Resource.Id` | PDP |
| --- | --- |
| standalone cluster | **403** |
| real ARM cluster | **200 Allowed** |

Azure role assignments only exist against real ARM scopes, so a cluster that is not in
ARM can carry none. **Do not skip this step** - it is the difference between a test that
evaluates policy and one that always says "deny".

## Step 4 - repoint Guard at a real ARM cluster

`--azure.resource-id` is just a flag. Point it at a cluster you control assignments on:

```bash
kubectl -n "$NS" patch deploy guard --type=strategic --patch-file patch.json   # replaces --azure.resource-id=
kubectl -n "$NS" rollout status deploy/guard --timeout=200s
```

## Step 5 - grant BOTH principals (this is two different things)

- **Subject** - the identity in `extra.oid` - needs the Kubernetes-facing role, e.g.
  `Azure Kubernetes Service RBAC Reader`, which allows `pods/list` and denies `secrets`.
- **Caller** - the identity whose token Guard uses for CheckAccess - needs
  `Microsoft.Authorization/checkAccess/read` on the scope. With obo that is
  `azure-kubernetes-service-aad-server` (appId `4f970234-6330-4470-bf3f-ef9a18e24d1b`);
  with IMDS it is the **node's** kubelet MI. No narrow built-in role exposes
  `checkAccess`, so Contributor is used (it carries it via wildcard).

Missing the caller grant is unmistakable - the error names the client id:

```
403 AuthorizationFailed: The client '4f970234-...' with object id 'b5f514f6-...' does not have
authorization to perform action 'Microsoft.Authorization/checkAccess/read' over scope '...'
```

**Retry for 3-4 minutes after any grant.** Guard caches decisions for
`cache-ttl-minutes=3`; on this run a stale 403 survived three attempts and flipped on the
fourth. A single-shot assertion reports a false failure. `rollout restart deploy/guard`
clears both the cached token and the decision cache.

## Step 6 - swap obo for IMDS (no Guard change, no registry)

Guard's two obo endpoints are not interchangeable
(`tests/mock-server/token-proxy/handler.go:33-40`):

| flag | endpoint | when |
| --- | --- | --- |
| `--azure.aks-authz-token-url` | `/v1/<ccpid>/authztoken` | **every** SubjectAccessReview |
| `--azure.aks-token-url` | `/v1/<ccpid>/token` | Graph/OBO, only on an overage claim |

`--mode=imds` serves `/authztoken` from IMDS and **refuses `/token` with 501** - "a
managed identity token carries no user identity". That is fine here: the CCP chart sets
`--azure.graph-call-on-overage-claim` unconditionally, so `/token` only fires for >200
groups.

The standalone cannot pull a personal ACR, but no registry is needed:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o token-proxy-linux ./tests/mock-server/token-proxy
kubectl -n obo apply -f obo-tokenlab-pod.yaml     # label app: obo, infra pool, `sleep`
kubectl -n obo cp token-proxy-linux obo-tokenlab:/tmp/token-proxy
kubectl -n obo exec obo-tokenlab -- sh -c \
  "chmod +x /tmp/token-proxy && nohup /tmp/token-proxy --mode=imds --mi-client-id=<node MI clientId> --port=8080 >/tmp/proxy.log 2>&1 &"

kubectl -n obo scale deployment/obo --replicas=0        # else the Service load-balances 50/50
kubectl -n obo get endpoints obo                        # MUST list only obo-tokenlab
kubectl -n "$NS" rollout restart deploy/guard           # drop the cached obo token
```

The Service (`selector app: obo`, `80 -> 8080`) does the redirection, so **Guard needs no
config change at all**. Read the node's MI from the node itself
(`grep userAssignedIdentityID /etc/kubernetes/azure.json`) - these nodes carry several.

**Verify the swap was actually exercised**, or a pass is vacuous:

```
[authztoken] grant=imds-direct mode=imds resource=https://management.azure.com status=issued
[authztoken] claims aud=... idtyp=app appid=<node MI> oid=<node MI oid> delegated=false
```

`grant=imds-direct` plus a node-MI `appid` is the proof. A reconciler scaled `obo` back to
1 mid-session here, silently restoring a second endpoint - **re-check
`kubectl get endpoints obo` before trusting any IMDS result.**

## Step 7 - the v2 (PDP) path, and the scope trap

```bash
--azure.use-checkaccess-v2=true
--azure.pdp-endpoint=https://<region>.authorization.azure.net
--azure.pdp-scope=https://authorization.azure.net/.default
```

In the chart these three are gated behind `useCheckAccessV2` *and* a guard image
`>=0.16.26-0` (`guard-deployment.yaml:198-201`); the value comes from toggle
`use-guard-checkaccess-v2` (`defaultValue "false"`, no overrides). On a standalone you
own, patch the deployment rather than releasing a toggle. The bare regional host is
correct - `buildCheckAccessV2URL` composes the path
(`authz/providers/azure/rbac/checkaccessreqhelper.go:869-897`); that function exists
because a bare host returns a non-JSON 404 whose first byte produced the
`invalid character 'N'` of the WCUS Sev2.

Confirm v2 is really in use:

```
rbac.go:487           "Using CheckAccess v2 API"
checkaccess_v2.go:294 "Performing primary CheckAccess v2" resourceId=".../namespaces/default"
checkaccess_v2.go:110 "CheckAccess v2 request succeeded" decisionsCount=1
```

**The trap.** A caller grant that satisfies v1 is *not* enough for v2. With Contributor at
**cluster** scope, v1 passes and v2 fails closed:

```
Guard -> 500  CheckAccess v2 batch failed ... RESPONSE 403
PDP   -> 403  "Caller does not have RBAC permission provisioned to call CheckAccess on this scope."
```

Granting the same principal Contributor at `/subscriptions/<id>` - changing nothing else -
flips v2 to pass. **PDP v2 wants the caller authorized at subscription scope; ARM v1
accepts cluster scope.** IMDS appeared to "just work" on v2 only because that node MI
already held Contributor/Owner at subscription scope; that is luck, not a property of IMDS.

Two more v2 differences worth knowing:

- v2's deny reason is more precise: `Access denied for action:
  Microsoft.ContainerService/managedClusters/secrets/read`, versus v1's generic
  "User does not have access to the resource in Azure."
- IMDS mints a PDP token only in the **v1 resource form**:
  `https://authorization.azure.net` works, `https://authorization.azure.net/.default`
  fails `AADSTS500011 invalid_resource`. Guard already trims it (`rbac.go:229`).

---

## Automation

`guard-standalone-matrix.sh` runs all four cells and encodes the traps above:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/token-proxy-linux ./tests/mock-server/token-proxy

./guard-standalone-matrix.sh run \
  --kubeconfig <cx-1 underlay kubeconfig> \
  --cluster-id <a cluster that exists in REAL ARM> \
  --oid <your AAD object id> \
  --proxy-bin /tmp/token-proxy-linux \
  --region westus2

./guard-standalone-matrix.sh teardown --kubeconfig <cx-1 underlay kubeconfig>
```

It discovers the CCP namespace from the `guard` deployment rather than requiring a CCP
id, reads the node MI off an infra node, and **fails loudly rather than silently
degrading** in the three places where this test can go vacuous:

- the node MI cannot be parsed (an empty `--mi-client-id` fails much later, confusingly);
- the obo Service has more than one endpoint, or still routes to the proxy on an "obo" row;
- the proxy log contains no `grant=imds-direct` after an IMDS row.

Every assertion is polled (`RETRIES`, `RETRY_SLEEP`) because of the 3-minute decision cache.

### The vacuity trap this harness exists to catch

On its first full run, all eight decision assertions passed and the IMDS rows were still
**meaningless**. The proxy log held nothing but its two startup lines: Guard had never
called it.

Consecutive rows often produce byte-identical guard args - `v1+obo` then `v1+imds` differ
only in which pod backs the obo Service - so `kubectl patch` was a no-op, **no new pods
were created**, and Guard kept serving from the authz token it had cached from the
*previous* row's token source. Guard caches that token to its expiry (~24h), so it had no
reason to call `/authztoken` again. The decisions were correct and the source was wrong.

Two consequences, both encoded in the script:

- `configure_guard` issues an unconditional `rollout restart`, not just a patch.
- `assert_imds_used` greps the proxy log, because "the decision was right" does **not**
  imply "the thing under test ran". Note `grep -c` prints `0` *and* exits 1 on no match;
  a naive `|| echo 0` yields a two-line value and a `[[: syntax error`, which reads as a
  broken assertion rather than a failing one.

If you change the row order or add a row, keep both guards. Without them this suite
reports a confident green while testing nothing.

### Doing this natively in e2ev3

The existing `Scenario_Guard_SubjectAccessReview` cannot be reused as-is (it self-skips,
see above), but the building blocks for a dev-gated variant all exist:

- `plans.IsDevTest()` (`test/e2ev3/runtime/test/plans/when.go:23`) is the counterpart to
  `IsProd()` and would gate a standalone-only verification.
- **e2ev3 can reach the cx underlay.** `test/e2ev3/handlers/clustermesh/diagnostics.go:442-456`
  fetches the underlay kubeconfig via `hcpClient.GetUnderlayV1`, builds
  `k8s.Credential{KubeConfig: ...}.KClient()`, and already reads pods *and secrets* in
  `info.CCPNamespace`. That is everything needed to pull `authwebhook-config`, patch the
  `guard` deployment's `--azure.resource-id`, and POST SubjectAccessReviews.

The one thing a native scenario still cannot avoid is the ARM-resource problem: it must be
pointed at a pre-existing real ARM cluster, because the cluster e2ev3 itself creates on a
standalone does not exist in ARM (step 3).

---

## Negative controls

A green matrix means nothing unless these go red, and red *differently*:

| control | expected |
| --- | --- |
| omit `extra.oid` | denied, `NonAADUser` verdict - not an Azure call |
| omit the client cert | `400 Missing client certificate` |
| client cert with wrong `O=` | `400 guard does not provide service for <org>` |
| leave `--azure.resource-id` on the standalone cluster | ARM 404 -> false deny (step 3) |
| caller grant at cluster scope only, v2 | Guard 500 wrapping PDP 403 (step 7) |
| revoke the subject's RBAC Reader | `pods/list` flips to denied within the 3 min cache TTL |

---

## Teardown

```bash
kubectl -n obo delete pod obo-tokenlab --ignore-not-found
kubectl -n obo scale deployment/obo --replicas=1
kubectl -n tokenlab delete pod guardcli --ignore-not-found
kubectl -n tokenlab delete secret guard-client --ignore-not-found
# Guard's flags revert on the next overlaymgr reconcile or chart redeploy:
kubectl -n "$NS" rollout restart deploy/guard
# role assignments created for the test:
az role assignment delete --assignee <subject-oid> --role "Azure Kubernetes Service RBAC Reader" --scope <cluster-id>
az role assignment delete --assignee <caller-oid>  --role Contributor --scope <cluster-id>
az role assignment delete --assignee <caller-oid>  --role Contributor --scope /subscriptions/<sub-id>
```
