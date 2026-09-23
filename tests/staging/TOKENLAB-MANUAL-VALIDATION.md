# Manually validating the tokenlab result

This is a guide to **independently reproducing** the finding, using only `az`,
`kubectl` and `curl`. It deliberately does not use the Go binaries, so a pass
here is evidence about Entra and PDP rather than about my code.

**The claim being validated:** a managed identity, used as a Federated Identity
Credential, can stand in for the AKS first-party app's S2S certificate - and the
token it yields is accepted by the real Azure RBAC data plane (PDP), from a real
standalone underlay.

Every command below was run and its output verified on 2026-08-14.

**Re-validation status (2026-09-17).** The whole document was re-run from scratch,
in **both** environments, and the core claim reproduced in both: `HTTP 200` /
`accessDecision=Allowed`, and an OBO token that is genuinely delegated.

- *Plain AKS* - rebuilt cluster, brand-new managed identity, new federated
  credential: A3, A4, all of Path B, Path C.
  Evidence: `~/dreams/tokenlab-revalidation-2026-09-16-plain-aks.txt`.
- *Standalone cx underlay* - new standalone `akolomeebld181518212` (build
  181518212, westus2), probe pod on the infra pool alongside `obo`: A1, A2, A3, A4.
  Evidence: `~/dreams/tokenlab-revalidation-2026-09-17-standalone.txt`.

That run found four errors in this document, each marked **[corrected 2026-09-17]**
below - one of them a negative control that could never have gone red. The
identifiers in the table below are still the 2026-08-14 ones and are historical,
**except** the `cx-underlay-mi` subject, which re-verified unchanged (see A2).

---

## What already exists

Written by `tokenlab-setup.sh` to `~/.config/guard-tokenlab/state.env`:

| Name | Value |
| --- | --- |
| midtier app (stands in for the AKS FPA) | `8c470c29-6209-4c7a-b80d-166973546877` |
| downstream app (stands in for Graph) | `8d4b3254-83c2-42ee-80b0-b0d881fdd3ef` |
| tenant | `72f988bf-86f1-41af-91ab-2d7cd011db47` |
| plain test cluster | `guard-tokenlab` in RG `akolomeetc`, westus2 |
| standalone | `standalone-260814f721u1` (build `176604658`) |

Two federated credentials are registered on the midtier app, one per cluster,
because the subject is bound to a specific managed identity:

```bash
source ~/.config/guard-tokenlab/state.env
az ad app federated-credential list --id "$MIDTIER_APP_ID" \
  --query '[].{name:name,subject:subject,issuer:issuer,aud:audiences[0]}' -o table
```

Expect exactly two rows, `aks-kubelet-mi` and `cx-underlay-mi`, both with
issuer `https://login.microsoftonline.com/<tenant>/v2.0` and audience
`api://AzureADTokenExchange`.

### If the environment has been cleaned up since the last run **[corrected 2026-09-17]**

The Cleanup section at the bottom deletes the resource group but *not* the Entra
applications, so a later re-run finds a misleading half-state: both apps and both
federated credentials still list fine, but `aks-kubelet-mi`'s subject managed
identity was deleted along with the cluster. **A federated credential whose
subject no longer exists still appears in the table above** - it is dangling, and
the only symptom is `AADSTS700213` at exchange time. Check the subject resolves:

```bash
az ad sp show --id <subject-oid> --query displayName -o tsv   # errors if dangling
```

To rebuild, recreate the cluster under the **same resource group name, cluster
name and subscription**. The resource id is then byte-identical to the recorded
`CLUSTER_ID`, which matters because PDP rejects synthetic scopes. Then:

```bash
# `create` is NOT idempotent - against existing apps it dies at expose_scope with
# Graph's CannotDeleteOrUpdateEnabledEntitlement ("Permission cannot be deleted or
# updated unless disabled first"). That PATCH is a clean no-op; the scopes and
# pre-authorizations from the first run are still intact, so skip straight to:
az ad app federated-credential delete --id "$MIDTIER_APP_ID" \
  --federated-credential-id aks-kubelet-mi
./tests/staging/tokenlab-setup.sh add-identity -n aks-kubelet-mi \
  -o "$(az aks show -g <rg> -n <cluster> --query identityProfile.kubeletidentity.objectId -o tsv)"
```

`add-identity` does not call `save_state`, so update `MI_CLIENT_ID` and
`MI_OBJECT_ID` in `state.env` by hand afterwards.

Deleting a federated credential is **negatively cached for roughly 30-60 seconds**.
Immediately after re-creating one, the exchange can still fail with `AADSTS700213`
for a credential that is now correct. Retry before concluding anything - and never
interpret that failure as a result of whatever else you were testing.

---

## Path A - the goal: PDP from the standalone, using only curl

### A1. Get a shell on the standalone's cx underlay

The standalone's resource group lives in a pool subscription you may not have
ARM access to, so use the build artifact rather than `az aks get-credentials`:

```bash
mkdir -p /tmp/sa && cd /tmp/sa
ADO_TOKEN=$(az account get-access-token \
  --resource "499b84ac-1321-427f-aa17-267ca6975798" --query accessToken -o tsv)
URL=$(curl -s -H "Authorization: Bearer $ADO_TOKEN" \
  "https://dev.azure.com/msazure/CloudNativeCompute/_apis/build/builds/176604658/artifacts?api-version=7.0" \
  | python3 -c "import json,sys; print([a['resource']['downloadUrl'] for a in json.load(sys.stdin)['value'] if a['name']=='e2e-underlay-kubeconfig'][0])")
curl -s -L -H "Authorization: Bearer $ADO_TOKEN" "$URL" -o kc.zip && unzip -o -q kc.zip

export KUBECONFIG=/tmp/sa/e2e-underlay-kubeconfig/kubeconfig-cx-1
kubectl get nodes
```

Start a pod **on the infra pool**, which is where `obo` actually runs:

```bash
kubectl create namespace tokenlab --dry-run=client -o yaml | kubectl apply -f -

kubectl -n tokenlab run curltest --image=curlimages/curl:8.10.1 --restart=Never \
  --overrides='{"spec":{"tolerations":[{"key":"agentpool","operator":"Equal","value":"infra","effect":"NoSchedule"}],"affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"agentpool","operator":"In","values":["infra"]}]}]}}}}}' \
  --command -- sleep 3600

kubectl -n tokenlab get pod curltest    # wait for Running
```

### A2. Confirm which identity the node actually has

These nodes carry **several** user-assigned identities, so IMDS refuses to guess
(`Multiple user assigned identities exist, please specify the clientId`). Read
the kubelet one from the node itself:

```bash
kubectl -n tokenlab run idread --image=curlimages/curl:8.10.1 --restart=Never \
  --overrides='{"spec":{"tolerations":[{"key":"agentpool","operator":"Equal","value":"infra","effect":"NoSchedule"}],"containers":[{"name":"idread","image":"curlimages/curl:8.10.1","securityContext":{"runAsUser":0},"command":["sh","-c","grep -oE \"userAssignedIdentityID.: *.[^\\\"]*\" /host/etc/kubernetes/azure.json"],"volumeMounts":[{"name":"h","mountPath":"/host","readOnly":true}]}],"volumes":[{"name":"h","hostPath":{"path":"/"}}]}}'
kubectl -n tokenlab logs idread
```

Verified value on this standalone: `b2a5f3b9-197d-41bc-9abd-38e6fc25e386`
(`akse2e-devinfra-kubelet`). Its **object** id - which is what the FIC subject
must be - comes from:

```bash
az ad sp show --id b2a5f3b9-197d-41bc-9abd-38e6fc25e386 --query id -o tsv
# 0e3ccf5f-cb04-48fa-b51a-4bb7022af1c6
```

**[corrected 2026-09-17]** Re-verified on a *different* standalone
(`akolomeebld181518212`, build 181518212) and both ids came back **unchanged**.
`akse2e-devinfra-kubelet` is shared by every standalone from this devinfra pool
rather than minted per-standalone, so `cx-underlay-mi` did **not** need
re-pointing and no new federated credential was created for that run. Do not
assume this: the general rule still holds that a credential is bound to one
subject, so read the value off the node each time and only register a new
credential if it differs. The per-cluster rule *does* bite on plain AKS clusters,
whose kubelet identity is created with the cluster and dies with it.

### A3. The three calls that constitute the proof

```bash
source ~/.config/guard-tokenlab/state.env
kubectl -n tokenlab exec curltest -- sh -c '
TENANT='"$TENANT_ID"'
APP='"$MIDTIER_APP_ID"'
MI=b2a5f3b9-197d-41bc-9abd-38e6fc25e386
SUBJECT_OID=0e3ccf5f-cb04-48fa-b51a-4bb7022af1c6
RESOURCE_ID='"$CLUSTER_ID"'

# 1. IMDS mints the assertion. NOTE the audience - Entra requires exactly this.
ASSERTION=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://AzureADTokenExchange&client_id=$MI" \
  | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")

# 2. Exchange it at Entra for a PDP-audience token. This is the v1 endpoint,
#    the one production obo uses.
PDP_TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=$APP" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$ASSERTION" \
  -d "resource=https://authorization.azure.net" \
  | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")

# 3. Spend it on a real authorization decision.
curl -s -w "\nHTTP_STATUS=%{http_code}\n" -X POST \
  "https://westus2.authorization.azure.net/providers/microsoft.authorization/checkAccess?api-version=2021-06-01-preview" \
  -H "Authorization: Bearer $PDP_TOKEN" -H "Content-Type: application/json" \
  -d "{\"Subject\":{\"Attributes\":{\"ObjectId\":\"$SUBJECT_OID\"}},\"Actions\":[{\"Id\":\"Microsoft.ContainerService/managedClusters/read\",\"IsDataAction\":false}],\"Resource\":{\"Id\":\"$RESOURCE_ID\"}}"
'
```

**Verified output:**

```json
{"value":[{"accessDecision":"Allowed",
           "actionId":"Microsoft.ContainerService/managedClusters/read",
           "roleAssignment":{"principalId":"0e3ccf5fcb0448fab51a4bb7022af1c6",
                             "roleDefinitionId":"b24988ac618042a0ab8820f7382dd24c",
                             "scope":"/subscriptions/26fe00f8-..."},
           "timeToLiveInMs":60000,"decisionReason":1}],"nextLink":null}
HTTP_STATUS=200
```

**How to read it.** `HTTP_STATUS=200` with a decision is the result that matters -
it means PDP authenticated the caller and evaluated the request. The
`roleAssignment.principalId` echoes back the managed identity's object id and
`roleDefinitionId` `b24988ac-6180-42a0-ab88-20f7382dd24c` is Contributor, so PDP
is telling you exactly which grant it matched. A decision of `NotAllowed` would
also count as success for this claim; `401`/`403` would not.

### A4. The OBO leg (the undocumented part)

```bash
./tests/staging/tokenlab-setup.sh token     # refresh; tokens last ~1h
USER_TOKEN=$(cat /tmp/tokenlab-user-token)

kubectl -n tokenlab exec curltest -- sh -c '
TENANT='"$TENANT_ID"'; APP='"$MIDTIER_APP_ID"'; DOWN='"$OBO_RESOURCE"'
MI=b2a5f3b9-197d-41bc-9abd-38e6fc25e386
USER_TOKEN="'"$USER_TOKEN"'"
ASSERTION=$(curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://AzureADTokenExchange&client_id=$MI" | sed -n "s/.*\"access_token\":\"\([^\"]*\)\".*/\1/p")
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "client_id=$APP" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$ASSERTION" \
  --data-urlencode "assertion=$USER_TOKEN" \
  -d "requested_token_use=on_behalf_of" \
  -d "resource=$DOWN" | head -c 300
'
```

**Verified output** begins:

```json
{"token_type":"Bearer","scope":"access_as_user","expires_in":"4271",
 "resource":"api://8d4b3254-83c2-42ee-80b0-b0d881fdd3ef","access_token":"eyJ0..."}
```

Two things to check, because they are the whole point:

- `"scope":"access_as_user"` - a **delegated** scope. An app-only token would
  have no `scp` at all. This is the undocumented case: Microsoft's OBO article
  documents only shared-secret and certificate client authentication.
- Confirm the user identity survived the exchange. **[corrected 2026-09-17]**
  Both applications are created with `requestedAccessTokenVersion: 2` (that is
  what `az ad app create` defaults to), so the token is `ver: 2.0` and carries
  **`preferred_username`, not `upn`**, and **`azp`, not `appid`**. An earlier
  version of this document said to check `upn`; on a v2.0 token `upn` is absent
  entirely, so that check reads as a failure on a token that is in fact correct.
  Decode locally rather than pasting a live delegated token into jwt.ms:

  ```bash
  python3 -c "
  import json,base64,sys
  t=json.load(open('/tmp/a4-resp.json'))['access_token']
  p=t.split('.')[1]; p+='='*(-len(p)%4)
  c=json.loads(base64.urlsafe_b64decode(p))
  print({k:c.get(k) for k in ('ver','scp','oid','preferred_username','azp','aud')})"
  ```

  Expect `scp=access_as_user`, `oid` = **your** object id,
  `preferred_username` = your UPN, and `azp` = the midtier app id.

Also note `"expires_in":"4271"` is a **quoted string** on the v1 endpoint. v2
returns it as a number. That difference is real and is what a naive integer
parse trips over.

---

## Path B - prove the test is not vacuous

A green result only means something if it can go red. Each of these should fail,
and fail *differently*:

**B1. Wrong FIC subject.** Register a credential whose subject is the managed
identity's *client* id instead of its object id, point the exchange at it, and
expect **`AADSTS700213: No matching federated identity record found for presented
assertion subject '<object-id>'`**. **[corrected 2026-09-17]** This document
previously said `AADSTS70021`; the code actually returned is `700213`. Note you
must **delete the correct credential first**, or the exchange simply succeeds
through it and the control proves nothing.

This is the single most common misconfiguration, and its error text is the best
available proof of the object-id rule: Entra echoes back the subject it was
*presented*, and that value is the managed identity's **object** id - which is
what IMDS puts in the assertion's `sub`, and therefore what the credential must
be keyed on.

**B2. Wrong assertion audience.** In step 1 above, change
`resource=api://AzureADTokenExchange` to `https://management.azure.com`. Entra
refuses the resulting assertion - it is a perfectly valid token, just not one
this trust relationship accepts. **[corrected 2026-09-17]** The refusal is
**`AADSTS700211`**, and it names the **issuer**, not the audience: asking IMDS for
`https://management.azure.com` yields a token issued by
`https://sts.windows.net/<tenant>/` (the v1 issuer), which does not match the
`/v2.0` issuer the credential is registered with. So B1 and B2 do fail
differently, and the code tells you which of subject or issuer was rejected.

**B3. No role assignment. [corrected 2026-09-17]** This control was previously
described as "remove Contributor from the underlay identity and expect PDP to
return 403". That is wrong, and as written the control **cannot go red**:

- Removing Contributor from the **subject** - the identity named in
  `Subject.Attributes.ObjectId`, the one being *evaluated* - returns
  `HTTP 200` with `accessDecision: NotAllowed`, `roleAssignment: null`,
  `decisionReason: 10`. Per the reading rules in A3, a `NotAllowed` decision
  **counts as success** for this claim. So this variant is green, not red.
- Removing Contributor from the **caller** - the application whose credentials
  minted the PDP token, i.e. the midtier app in `fic` and `cert` modes - is what
  produces the failure. Step 2 still issues a token, and PDP then returns:

  ```json
  {"statusCode":403,"message":"Caller does not have RBAC permission provisioned to call CheckAccess on this scope."}
  ```

Do not generalize between the two: subject and caller are different principals
answering different questions, and only the caller's grant gates the call.

```bash
source ~/.config/guard-tokenlab/state.env
# the control that actually goes red - strips the CALLER
az role assignment delete --assignee "$MIDTIER_SP_OID" \
  --role Contributor --scope "/subscriptions/$SUBSCRIPTION_ID"
```

This 403 is the distinction the harness reports as `REFUSED` rather than `PASS`,
and it is why "Entra issued a token" is not the same claim as "the token works".
Re-grant afterwards - `tokenlab-setup.sh add-identity` covers the subject, and the
caller with:

```bash
az role assignment create --assignee-object-id "$MIDTIER_SP_OID" \
  --assignee-principal-type ServicePrincipal \
  --role Contributor --scope "/subscriptions/$SUBSCRIPTION_ID"
```

**B4. Bare PDP host.** Drop the path and api-version, calling
`https://westus2.authorization.azure.net` directly. Expect **404**.
**[corrected 2026-09-17]** The body is the plain text `Not Found.`, not HTML -
which is a sharper explanation of the WCUS Sev2 than "an HTML body" was: a JSON
decoder fed `Not Found.` fails on its very first byte, and that is literally the
reported `invalid character 'N'`. It is why the endpoint is built in one place in
code.

---

## Path C - re-run the automated harness

To compare against the recorded runs rather than re-derive from scratch:

```bash
cd ~/src/guard-azure
go test ./tests/mock-server/...            # unit tests, no Azure needed
```

For the in-cluster probe, see `TOKENLAB.md`. One caveat if you re-run it on the
standalone: the image lives in a personal ACR the standalone cannot pull from.
Anonymous pull was enabled temporarily and has since been reverted, so either
re-enable it (needs Standard SKU; Basic refuses) or push the image somewhere the
standalone can already reach.

Recorded evidence for comparison:

- `~/dreams/tokenlab-pdp-evidence-standalone.txt`
- `~/dreams/tokenlab-pdp-evidence-plain-aks.txt`

---

## Cleanup

```bash
export KUBECONFIG=/tmp/sa/e2e-underlay-kubeconfig/kubeconfig-cx-1
kubectl delete namespace tokenlab

cd ~/src/guard-azure && ./tests/staging/tokenlab-setup.sh destroy   # removes both apps
az group delete -n akolomeetc --yes --no-wait                       # plain cluster + ACR
```

The standalone expires on its own lease (the 2026-08-14 one was 168h and is long
gone). **[corrected 2026-09-17]** Note what this cleanup does *not* do: deleting
the resource group destroys the cluster and its kubelet managed identity, but
`destroy` is a separate step, so skipping it leaves both Entra applications alive
with a **dangling** `aks-kubelet-mi` credential pointing at an object id that no
longer resolves. Either run both, or see "If the environment has been cleaned up
since the last run" above before re-running.

---

## What a full pass does and does not establish

Established: MI-as-FIC works for **both** grants, on **both** endpoint versions
including the v1 one production uses, and the resulting token is accepted by
real PDP from a real standalone underlay.

Not established, and not testable here: whether the genuine Microsoft-owned AKS
first-party application is permitted to carry a federated identity credential.
This harness substitutes a self-created application for it precisely to separate
the mechanics from that policy question. The mechanics work; the policy question
belongs to the Entra first-party team.
