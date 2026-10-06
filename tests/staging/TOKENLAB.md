# tokenlab: can a Managed Identity replace the OBO service's private key?

## What this answers

The production `obo` service holds the AKS first-party app's S2S **certificate
private key**, signs a `client_assertion` with it, and exchanges that at Entra
for two things:

| Guard endpoint | Grant | Result | Used for |
| --- | --- | --- | --- |
| `/v1/{ccpid}/token` | on-behalf-of | delegated Graph token | group resolution |
| `/v1/{ccpid}/authztoken` | client_credentials | app-only PDP token | CheckAccess v2 |

The primary goal is **end-to-end PDP access**: prove that a token minted by one
of these credential mechanisms is actually accepted by the Azure RBAC data
plane, not merely issued by Entra. Those are different properties -

- Entra issues a token to anyone whose client authentication succeeds.
- PDP additionally requires `Microsoft.Authorization/checkAccess/action`, which
  no narrow built-in role grants.

so the probe spends every PDP-audience token on a real CheckAccess call and
reports `REFUSED` when a token is issued but rejected. **A decision of either
allowed or denied counts as success** - it proves the call was authenticated and
evaluated.

Replacing the certificate with a **Managed Identity used as a Federated
Identity Credential** would delete the private key from the system. Two further
questions block that, and neither is answerable from documentation:

| | Question | Documentation status |
| --- | --- | --- |
| **Q1** | Does Entra accept a federated `client_assertion` for `client_credentials`? | Documented as supported. Confirm it here. |
| **Q2** | Does Entra accept a federated `client_assertion` for the **on-behalf-of** grant? | **Undocumented.** The OBO article covers only shared secret and certificate. |

A third question - whether the real Microsoft-owned first-party app may have a
FIC at all - cannot be tested locally and is an Entra-team question. This harness
deliberately uses a **self-created test application** as a stand-in, which
isolates Q1/Q2 from that policy question.

## Layout

| Path | Purpose |
| --- | --- |
| `tests/mock-server/tokenlab/` | Shared library: IMDS, client assertions, both grants, claim decoding |
| `tests/mock-server/probe/` | Runs the credential matrix once and prints the answers |
| `tests/mock-server/token-proxy/` | Drop-in replacement for the `obo` service, `--mode=cert\|fic\|imds` |
| `tests/staging/tokenlab-setup.sh` | Creates the Entra objects; each step is a gate |

The probe and the proxy share `tokenlab`, so a Phase 1 result transfers directly
to Phase 2 rather than being re-implemented.

## Phase 0 - Entra objects (no code, ~20 min)

```bash
az account set --subscription 'AKS INT/Staging Test'
az group create -l eastus2 -n akolomeetc
az acr create --name akolomeetcacr -g akolomeetc --sku Basic -l eastus2
az aks create -g akolomeetc -n guard-tokenlab --enable-aad --enable-azure-rbac \
  --attach-acr akolomeetcacr --node-count 1 --node-vm-size standard_d2s_v5 -l eastus2

./tests/staging/tokenlab-setup.sh create -g akolomeetc -c guard-tokenlab
./tests/staging/tokenlab-setup.sh token
```

The script creates **two** applications so no tenant administrator is needed:

- **midtier** stands in for the AKS first-party app, carries the FIC, and
  pre-authorizes the Azure CLI so a user token needs no consent prompt.
- **downstream** stands in for Graph and pre-authorizes midtier, so the OBO
  exchange needs no consent grant.

Using Graph directly would require `GroupMember.Read.All`, which is
admin-consent-required and would stall the experiment in a corporate tenant.

Each step is a gate. If any fails, **stop** - the failure is the finding:

| Gate | Failure means |
| --- | --- |
| 0 application creation | Q1/Q2 are not locally testable; escalate to the Entra team |
| 1 kubelet identity | cluster has no user-assigned identity; FIC requires one |
| 2 federated credential | check the subject is the MI's **object** id, not its client id |
| 3 user token | `AADSTS65001` = pre-authorization did not apply; `AADSTS53003/50076` = Conditional Access, needs an admin |

## Phase 1 - run the probe (~15 min)

```bash
GOOS=linux GOARCH=amd64 go build -o tests/mock-server/probe-linux-amd64 ./tests/mock-server/probe/
GOOS=linux GOARCH=amd64 go build -o tests/mock-server/token-proxy-linux-amd64 ./tests/mock-server/token-proxy/
az acr build --registry akolomeetcacr --image tokenlab:latest \
  --file tests/mock-server/Dockerfile.tokenlab tests/mock-server/

az aks get-credentials -g akolomeetc -n guard-tokenlab --overwrite-existing
kubectl create namespace guard-tokenlab
kubectl -n guard-tokenlab create secret generic tokenlab-user-token \
  --from-file=user-token=/tmp/tokenlab-user-token

source ~/.config/guard-tokenlab/state.env
sed -e "s|PLACEHOLDER_NAMESPACE|guard-tokenlab|g" \
    -e "s|PLACEHOLDER_IMAGE|akolomeetcacr.azurecr.io/tokenlab:latest|g" \
    -e "s|PLACEHOLDER_TENANT_ID|$TENANT_ID|g" \
    -e "s|PLACEHOLDER_APP_CLIENT_ID|$MIDTIER_APP_ID|g" \
    -e "s|PLACEHOLDER_MI_CLIENT_ID|$MI_CLIENT_ID|g" \
    -e "s|PLACEHOLDER_OBO_RESOURCE|$OBO_RESOURCE|g" \
    -e "s|PLACEHOLDER_PDP_RESOURCE|https://authorization.azure.net|g" \
    -e "s|PLACEHOLDER_PDP_REGION|westus2|g" \
    -e "s|PLACEHOLDER_CHECK_SUBJECT_OID|$MI_OBJECT_ID|g" \
    -e "s|PLACEHOLDER_CHECK_RESOURCE_ID|$CLUSTER_ID|g" \
    tests/staging/tokenlab-probe-job.yaml | kubectl apply -f -

kubectl -n guard-tokenlab wait --for=condition=complete job/tokenlab-probe --timeout=180s
kubectl -n guard-tokenlab logs job/tokenlab-probe
```

`--pdp-region` builds the full CheckAccess URL including the path and
api-version. Passing the bare host returns 404 with an HTML body, which is what
produced "invalid character 'N'" and a fleet-wide Sev2 - `BuildPDPEndpoint`
exists so that cannot be got wrong by hand.

### Reading the result

Decide what each row means **before** running, so a surprising result cannot be
rationalised afterwards:

- `imds/direct` must pass. It proves IMDS is reachable and the identity is
  assigned. If it fails, every other row is uninterpretable.
- `fic/client_credentials/v2` is the **positive control** - Microsoft documents
  this as supported. If it fails, the FIC or the harness is wrong, and no OBO
  result should be believed yet.
- The `cert/*` rows are the production baseline. Both passing means the
  application, scopes, pre-authorization and user token are all correct, so any
  `fic/on-behalf-of` failure isolates cleanly to the credential type.
- The **control** section reports whether every federated row presented the same
  client assertion. If it says `WARN`, a Q1/Q2 difference cannot be attributed
  to the grant type and the run must be repeated.

Both endpoint versions are tested because production uses **v1**
(`/oauth2/token`, `resource=`) while Microsoft documents federated credentials
only against **v2** (`/oauth2/v2.0/token`, `scope=`). "Works on v2 only" is a
materially different answer: it would mean porting the OBO service to v2, not
just swapping a credential.

Common codes: `AADSTS70021` no matching FIC (or it has not propagated yet -
wait a few minutes), `AADSTS7000113` an app-only token was offered as the OBO
assertion, `AADSTS700212` audience mismatch.

## Phase 2 - end to end with Guard (~30 min)

Deploy the proxy and point Guard at it. Guard needs no code change - the proxy
speaks the same wire protocol as `obo`.

```bash
sed -e "s|PLACEHOLDER_NAMESPACE|guard-tokenlab|g" \
    -e "s|PLACEHOLDER_IMAGE|akolomeetcacr.azurecr.io/tokenlab:latest|g" \
    -e "s|PLACEHOLDER_MODE|fic|g" \
    -e "s|PLACEHOLDER_API_VERSION|v1|g" \
    -e "s|PLACEHOLDER_TENANT_ID|$TENANT_ID|g" \
    -e "s|PLACEHOLDER_APP_CLIENT_ID|$MIDTIER_APP_ID|g" \
    -e "s|PLACEHOLDER_MI_CLIENT_ID|$MI_CLIENT_ID|g" \
    -e "s|PLACEHOLDER_OBO_RESOURCE|$OBO_RESOURCE|g" \
    -e "s|PLACEHOLDER_PDP_RESOURCE|https://authorization.azure.net|g" \
    tests/staging/tokenlab-proxy.yaml | kubectl apply -f -
```

Then deploy Guard per `tests/staging/deploy-guard-v2-test.sh` with:

```
--azure.aks-token-url=http://tokenlab-proxy.guard-tokenlab.svc:8080/v1/test-ccp/token
--azure.aks-authz-token-url=http://tokenlab-proxy.guard-tokenlab.svc:8080/v1/test-ccp/authztoken
```

Two flags decide whether this test is meaningful at all:

- **`--azure.graph-call-on-overage-claim` must be absent (false).** Production
  sets it, and it makes Guard skip the Graph call entirely unless the token has
  an overage claim (>200 groups). With it on, `/token` is never called and Q2
  is silently untested.
- **`--azure.verify-clientID` must be absent.** The test user token's audience
  is the midtier app, not Guard's configured client id.

`tests/staging/guard-v2-test.yaml` sets neither, so the plain-AKS path is
already correct.

| Question | How to exercise it | Success signal |
| --- | --- | --- |
| Q1 | POST a SubjectAccessReview to `/subjectaccessreviews` | proxy logs `[authztoken] grant=client_credentials ... status=issued` |
| Q2 | POST a TokenReview to `/tokenreviews` with the user token as `spec.token` | proxy logs `[token] grant=on-behalf-of ... status=issued` and `delegated=true` |

The proxy runs with `--passthrough-errors`, so a rejection returns Entra's own
body and the AADSTS code reaches Guard's logs rather than being flattened to a
generic 500.

## Phase 3 - standalone

Guard's token URL is chart-templated with only the namespace variable, so
instead of editing `underlay-config.json` and redeploying overlaymgr, take over
the existing Service by label:

```bash
# 1. the underlay's identity differs from the plain cluster's, so it needs its
#    own federated credential and role assignment
CX_RG=<standalone resource group>
CX_CLUSTER=<underlay-id>-cx-1
CX_OID=$(az aks show -g $CX_RG -n $CX_CLUSTER \
  --query identityProfile.kubeletidentity.objectId -o tsv)
CX_CLIENT_ID=$(az aks show -g $CX_RG -n $CX_CLUSTER \
  --query identityProfile.kubeletidentity.clientId -o tsv)

./tests/staging/tokenlab-setup.sh add-identity -n cx-underlay-mi -o "$CX_OID"

# 2. run the probe on the underlay
kubectl create namespace tokenlab
# ... sed the probe Job with CX_CLIENT_ID and apply it

# 3. only if you also want Guard in the loop
kubectl -n obo scale deployment/obo --replicas=0
kubectl apply -f tokenlab-proxy-obo-swap.yaml   # pod label app: obo
```

Two things differ from Phase 2:

- The identity IMDS returns there is the **underlay's** kubelet identity, so it
  needs its own federated credential (the limit is 20 per application).
- Guard is deployed by the chart with both blocking flags set, so exercising
  `/token` through Guard still needs a `kubectl patch` to remove them. The probe
  itself does not care - it talks to Entra and PDP directly.

Swapping the obo Deployment replaces token issuance for **every** CCP on that
underlay. Use only on a standalone you own. Roll back with:

```bash
kubectl -n obo delete deployment/obo-tokenlab
kubectl -n obo scale deployment/obo --replicas=3
```

Note `AKSCapacityHeavyUsage` in a region will fail standalone provisioning
outright (both svc-0 and cx-1). If `ops standalone create` fails that way,
re-queue with `--region` somewhere else.

## Cleanup

```bash
./tests/staging/tokenlab-setup.sh destroy
az group delete -n akolomeetc --yes --no-wait
```

## Notes

- `accessTokenAcceptedVersion` is deliberately left at the v1 default. Guard
  reads the v1 discovery document, so a v2 application would issue tokens whose
  issuer Guard rejects.
- A federated credential is created successfully even when the issuer, subject
  or audience is wrong; the error appears only at exchange time.
- The user token lasts about an hour. An expired assertion reports as an Entra
  rejection, which is easy to misread as a FIC refusal - re-run
  `tokenlab-setup.sh token` if a previously passing row starts failing.
