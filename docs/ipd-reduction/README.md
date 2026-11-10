# Guard / AAD IPD Reduction: Final-Week Plan

Status: w3 Guard implementation and tests available locally for review; not deployed.

Planning date: 2026-11-09. W3 update: 2026-11-10. MMM deadline: 2026-11-13.

Tracking: [Feature 39815166: [MMM][AAD] IPD Reduction (10/05 - 11/13)](https://msazure.visualstudio.com/CloudNativeCompute/_workitems/edit/39815166).

## Decision Requested

Approve a small, diagnostics-first Guard change this week, paired with an alert and
an operator TSG. Preserve all authentication and authorization decisions. Treat
upstream first-party application testing, notifications, and deployment settings
as separate deliverables with explicit owners, not capabilities a Guard PR can
provide by itself.

The incident investigation covers four failures: first-party application changes
breaking device-code sign-in, a CSR DataAction compatibility regression, malformed
CheckAccess responses, and a client reaching the API server without a valid token.
The common cost is slow attribution. This week's success criterion is that an
operator can distinguish the failing stage and find the next evidence source
without guessing from a generic 401 or 500.

## Scope And Milestones

The supplied feature screenshot is the milestone baseline. The live work item
requires sign-in and was not independently verified. Dates and owners below are
proposed assignments, not evidence that work has been accepted or completed.

| Milestone | Final-week deliverable | Proposed owner | Boundary |
| --- | --- | --- | --- |
| w2: alert on Guard 500 bursts | An evaluated alert rule, routing, and a tested TSG link | Felix + monitoring owner | Guard metrics plus AKS monitoring configuration |
| w3: improve debug / CCP log formatting with API server and Guard (PR target 11/10) | Stable, sanitized diagnostic contract and focused tests; implementation below | Felix; API-server / CCP owner for ingestion | Guard PR plus log-pipeline verification |
| w3: analyze Guard policy errors (PR target 11/10) | Bounded taxonomy, policy / dependency fixtures, and attribution guidance below | Felix | Guard and TSG |
| w4: enable SP group resolution by default | Verify staging coverage and the existing deployment PR before rollout | Bin | AKS deployment policy, not a global Guard default flip |
| w4: notify TSG of first-party app changes | A change ledger linked from the TSG and a named notification owner | Felix + AAD-FirstPartyApps owner | Upstream release process |
| w4: distinguish customer, AKS, AAD 1P app, and ESTS issues | Evidence-based triage with an explicit unknown category | Felix | Diagnostics plus external sign-in / change evidence |
| w5: owned-tenant Conditional Access policy | A repeatable device-code / browser / SP-overage test matrix | Bin; Felix reviews evidence | Tenant and upstream application test environment |
| w5: connectivity triage guides | A short decision tree, queries, mitigations, and escalation evidence | Bin + Felix | Operator TSG and support routing |

The crossed-out w1/w2 items in the screenshot are not reopened by this plan.
The screenshot's w6 is TBD and does not add scope to this deadline.

Related tracking: [Guard messaging repair, Task 39158940](https://msazure.visualstudio.com/CloudNativeCompute/_workitems/edit/39158940)
and [SP group-resolution deployment PR 17819571](https://msazure.visualstudio.com/CloudNativeCompute/_git/aks-rp/pullrequest/17819571).
Their current completion / deployment status still needs owner confirmation.

## Baseline Before The W3 Change

These are baseline source observations used to scope the work, not proof of what
is deployed in AKS. The w3 implementation below updates the OBO / Graph paths.

| Existing behavior | Planning consequence |
| --- | --- |
| [Azure authz](../../authz/providers/azure/azure.go) already creates a request ID and contextual logger; CheckAccess adds per-batch correlation IDs | Extend the existing authz context; do not introduce a second competing request ID |
| [Server metrics](../../server/prometheus.go) already expose TokenReview and SubjectAccessReview HTTP counters with `code` and `method` labels; [router instrumentation](../../server/server.go) wraps both handlers | The 500-burst alert does not require inventing a new HTTP counter |
| [Graph](../../auth/providers/azure/graph/graph.go) has user / SP failure counters, but `getGroupIDs` increments them only on transport errors | HTTP failures and malformed bodies need explicit diagnostic coverage; current counters alone are insufficient |
| [AKS OBO acquisition](../../auth/providers/azure/graph/aks_tokenprovider.go) and Graph errors interpolate upstream response bodies into error strings | Parse safe metadata at the dependency boundary; stop forwarding unfiltered bodies through the affected logs / responses |
| [CheckAccess metrics](../../authz/providers/azure/rbac/rbac.go) include `code` and `api_version`; [v2](../../authz/providers/azure/rbac/checkaccess_v2.go) maps all SDK errors to metric code `500` | Keep current series compatible; add failure classification without claiming `500` is the upstream HTTP status |
| [Response writers](../../server/utils.go) expose error strings; TokenReview defaults errors to HTTP 401 unless explicitly wrapped | Safe response formatting must preserve the existing explicit HTTP wrapper and wire protocol |
| [SP-overage refusal](../../auth/providers/azure/azure.go) already uses HTTP 200 with `Authenticated:false` so the API server can log `Status.Error`; authz 4xx failures can become cached denials | Do not normalize these to HTTP 500 or change their caching behavior merely to make alerting easier |
| CheckAccess v2 currently treats a successful response with no decisions as a denial | Diagnose an invalid / empty response separately from a genuine policy denial without changing its verdict in this PR |

## W3 Delivery: Message Refinement And Policy Analysis

Both screenshot targets have a PR target of **2026-11-10**. A PR has not been
created by this local change; attach the reviewed PR URL to both feature entries.
The implementation here is the OBO / Graph portion of package A, not completion
of every diagnostic, alert, or upstream deliverable in this plan.

### Alert Context Verified

[Alert PR 17444741](https://dev.azure.com/msazure/CloudNativeCompute/_git/aks-rp-alerts/pullrequest/17444741?_a=files)
is completed. Its metadata and source-commit rule were read using authenticated
Azure DevOps CLI access on 11/10. The rule reads `OBOActivity`, prefers raw OBO rows
where available, and derives `server_4xx`, `customer_4xx`, `server_5xx`, and
`unclassified_4xx` using status, message availability, an AAD-code list, and
`capolids` presence. It includes `ServerSide4xx`, `Cluster5xxStorm`,
`WidespreadCABlock`, `Widespread4xx`, and `Widespread5xx` alert reasons.

Those are alerting heuristics, not definitive ownership evidence. In particular,
`AADSTS53003` or a policy ID does not prove a customer changed policy. A change to
the AKS first-party application can make an unchanged policy block issuance.
Likewise, many failing clusters can belong to one tenant; cluster spread alone
does not prove an ESTS or application rollout incident.

Do not duplicate the alert's customer-code list inside Guard or suppress every
policy block at the producer. Keep the existing widespread-CA signal. The useful
producer change is separating the failing hop, response status, policy evidence,
and correlation IDs rather than publishing a guessed customer/server verdict.

### Implemented Guard Contract

[Dependency diagnostics](../../auth/providers/azure/graph/diagnostics.go) now cover
AKS OBO acquisition, direct Entra OBO acquisition, Graph user / SP group lookup,
and group expansion:

- One normal-verbosity structured event per failed dependency invocation:
  `event=guard_azure_dependency_failure`, `stage`, `dependency`, `reason`,
  `responseClass`, `faultDomain=unknown`, and outgoing `correlationID`.
- `responseClass` describes evidence, not ownership: `client_error` means an
  upstream HTTP 4xx, `server_error` an upstream HTTP 5xx, `transport_error` means
  no response, and `invalid_response` means a success body could not be decoded.
  `unexpected_status` preserves other non-200 responses without inventing a cause.
- `upstreamStatus` is the immediate dependency's actual HTTP status, never the
  TokenReview HTTP status and not necessarily the ultimate ESTS status. An AKS OBO
  500 carrying a structured `53003` retains both facts.
- Bounded JSON parsing (64 KiB) reads structured `error_codes` / `error.code` and
  an allowlist of OAuth / Graph error codes. Free-form `error_description` and
  arbitrary message text are never used to assign a policy reason or owner.
- `upstreamRequestID` / `upstreamCorrelationID` retain valid UUID response-header
  IDs, falling back to body IDs where available. `aadTraceID` /
  `aadCorrelationID` separately retain Entra body IDs, so an OBO header cannot
  overwrite the identifier needed for sign-in-log lookup. Missing IDs stay absent.
- An authn request ID is added to the contextual logger, matching the existing
  authz pattern. Each dependency sends its own UUID in `client-request-id` and
  `x-ms-correlation-request-id`; support / echo by each upstream must still be
  checked in staging. Graph request headers are cloned, not mutated globally.
- Returned error text carries the same safe diagnostic fields. Token-refresh
  wrapping retains the typed cause; raw bodies / descriptions, request URLs with
  principal paths, assertions, credentials, and token claims are not emitted by
  these changed failure paths. Direct OBO / Graph credential-bearing curl dumps
  and authn's unverified-claims dump are removed.

The event marker appears only on the structured dependency event, not on returned
error strings. Counting propagated server error text as another dependency event
would double-count the same failure.

Example field set, abbreviated and with illustrative IDs:

```text
event="guard_azure_dependency_failure" requestID="<guard-request>" stage="obo" dependency="aks_obo" reason="OBO_POLICY_BLOCKED" responseClass="client_error" upstreamStatus=400 aadCode="AADSTS53003" faultDomain="unknown" correlationID="<outgoing-request>" aadTraceID="<entra-trace>"
```

No authorization decisions, status wrappers, cache behavior, retries, timeout
budgets, metrics, or deployment defaults are changed. This is not a blanket
redaction audit of every Azure provider / PDP / Arc code path.

### Policy Error Analysis And Operator Actions

| Observed diagnostic | What it establishes | Next evidence / action |
| --- | --- | --- |
| `OBO_POLICY_BLOCKED`, `AADSTS53003`, 4xx | A structured CA block, not customer ownership | Use Entra trace / correlation IDs and UTC time for sign-in evaluation; compare effective CA and app permission / pre-authorization changes |
| The same policy reason with an OBO 5xx | An OBO server-error response also carries policy evidence | Inspect OBO / CCP handling and sign-in evidence; do not throw away the policy reason or assume an ESTS outage |
| `OBO_FAILED`, `server_error` | The immediate OBO dependency returned 5xx | Correlate OBO request IDs, backend health, and rollout timing; use the existing storm / widespread alert paths |
| `OBO_FAILED`, `client_error`, no structured AAD code | An upstream 4xx, with insufficient policy detail | Preserve an unknown cause; obtain the structured OBO contract, not substring classification of a cryptic message |
| `GRAPH_FAILED`, permission code / 403 | Graph rejected membership resolution | Check token audience, delegated/application permissions, consent, and effective AKS app config; not proof of a customer RBAC error |
| `GRAPH_FAILED`, 429 / transport / decode evidence | Throttling, connectivity, or a malformed dependency response | Inspect the relevant dependency and captured IDs; distinguish this from a valid PDP deny |

Fixture tests cover both 400 and 500 with `53003`, malformed / oversized bodies,
invalid IDs, distinct header / Entra IDs, transport cancellation, user / SP group
paths, token-refresh wrapping, normal / verbose log redaction, and TokenReview
serialization. A negative TokenReview remains negative, defaults to HTTP 401,
and preserves an explicit HTTP-200 wrapper when the caller already supplies one.

### Remaining W3 Integration Gates

1. Open / review the Guard PR and add its URL to both 11/10 feature targets.
2. Verify normal-level Guard events reach the owning CCP log sink. Publish a
   tested query projecting cluster identity, UTC time, stage, reason, actual
   status, and request IDs. Group by status / reason and cluster spread, not just
   `AADSTS53003`; join sign-in / change evidence before assigning fault.
3. Join the outgoing / returned IDs with OBOActivity and Entra sign-in records in
   staging. If the OBO service strips structured fields or does not carry the
   header, assign that upstream contract change to its owner. Guard must retain
   `OBO_FAILED` rather than manufacture missing details.
4. Check API-server logs separately from Guard logs and kubectl output. Existing
   non-200 TokenReview handling can discard the error body; preserving that
   behavior here means improved Guard diagnostics are not a claim that the
   message reaches the client. A protocol/status change needs a separate review.
5. Replay a policy-block case and a server-failure case end to end; retain the
   widespread-CA regression scenario. Confirm safe fields survive ingestion and
   do not turn an isolated policy event into a page.

The current IcM query reads OBO service logs, not these new Guard events. This PR
does not automatically improve that alert or change its thresholds. The CCP/OBO
producer contract, ingestion mapping, correlation queries, live alert backtest,
and production log analysis remain external validation work, not completed by
passing Guard unit tests. Do not copy fabricated table / column names into a TSG.

## Guard Changes

### 1. Consistent Failure Diagnostics

Implement in the Azure provider / dependency boundaries above and the
[TokenReview](../../server/handler.go),
[SubjectAccessReview](../../server/authzhandler.go), and response-writing paths.
Keep this a small extension of the existing error helpers, not a new diagnostics
framework or a provider-interface refactor. Leave non-Azure providers unchanged.

Proposed contract, frozen in the PR before monitoring / TSG integration:

- One normal-verbosity, structured terminal failure event with `event`, `requestID`,
  `stage`, `reason`, and `outcome`. Dependency events retain the parent request ID
  and existing batch ID where applicable. Normal policy denials must not produce
  error-level log floods.
- Optional allowlisted metadata: dependency name, actual upstream status when
  known, bounded upstream error code, upstream request / correlation IDs, API
  version, and elapsed time. Validate identifier length / characters before
  logging. Missing metadata stays absent; do not infer it from arbitrary prose.
- Reuse authz's request ID; create an equivalent per-request authn ID. Carry it
  through OBO / Graph / PDP calls where supported. A logger context does not prove
  an SDK forwards the same ID upstream: verify that separately.
- Authn and authz are separate webhook calls. Do not promise that their IDs, or
  the API-server audit ID, are identical. Document a verified join when available;
  otherwise use timestamp plus the separately recorded IDs.
- Return only a short safe summary, diagnostic code, and request ID through the
  existing `TokenReview.Status.Error` / SAR reason or evaluation-error path as
  appropriate. Preserve `HttpStatusCode` wrappers, `Authenticated`, `Allowed`,
  `Denied`, and NoOpinion behavior. Do not invent a new webhook response schema.
- Do not add per-request IDs to cached results. Keep verdict / TTL semantics
  unchanged and log the current request ID separately on cache hits.

Initial bounded reasons, refined only where real typed / structured evidence is
available:

| Reason | Stage / evidence | Interpretation |
| --- | --- | --- |
| `TOKEN_INVALID` | Token verification reports a known expiry, signature, issuer, or audience validation failure | Token rejected; not proof of customer fault |
| `TOKEN_VALIDATION_DEPENDENCY_FAILED` | Identifiable OIDC metadata / key retrieval or Entra-sidecar dependency failure | Do not mislabel an unavailable verifier as a bad customer token |
| `SP_OVERAGE_DISABLED` | Existing SP-overage feature gate | Unsupported configuration path; keep the existing safe refusal |
| `OBO_POLICY_BLOCKED` | OBO response supplies a structured, recognized policy-block code such as `AADSTS53003` | Policy evaluation blocked issuance; inspect sign-in and application-change evidence |
| `OBO_FAILED` | OBO transport, HTTP, or decode failure without a more specific safe classification | OBO dependency failure, not automatically ESTS or customer fault |
| `GRAPH_FAILED` | Group lookup transport, HTTP, permission, or decode failure | Record a bounded subcategory and user / SP path, not principal or group lists |
| `PDP_FAILED` | CheckAccess transport, timeout, HTTP, or SDK failure | Preserve SDK / API-version distinction; actual upstream status may be unknown |
| `PDP_INVALID_RESPONSE` | Detectable malformed payload or successful response with no decisions | Dependency response defect; preserve current failure / denial semantics |
| `RBAC_DENIED` | Valid PDP response explicitly denies an action | Normal authorization result; not a 500 or dependency failure |
| `UNKNOWN` | Evidence is insufficient or an upstream shape is unfamiliar | Preserve failure behavior and collect correlation evidence; do not guess an owner |

Use typed errors and structured JSON error fields, not substring matching against
free-form messages. Bound reads when extracting error metadata. If the OBO service
or PDP SDK does not expose a status, request ID, or structured AAD code, retain a
generic reason and track the missing contract with that owner. Do not add SDK
replacement / upgrades to this week's critical path just to obtain metadata.

Keep high-cardinality identifiers in logs, not metric labels. Never log bearer
tokens, OBO assertions, secrets, full claims / group lists, full upstream bodies,
or unfiltered error strings. Replace unsafe logging in the affected failure paths,
including verbose claim / response dumps and downstream `printStackTrace` calls
that would otherwise re-emit the unsanitized cause. Keep the underlying cause for
classification, not for automatic serialization.

Do not equate an error code with fault ownership. A Conditional Access denial is
evidence of a policy block, not proof the customer changed anything: the trigger
incident was an upstream application change interacting with an existing policy.

Guard cannot explain a request it never receives. Token acquisition can fail in
kubelogin before TokenReview; a missing bearer token may also be rejected by the
API server before Guard. Those cases require client / API-server evidence and
Entra sign-in logs. API-server propagation of Guard diagnostic text must be tested,
not assumed from a webhook unit test.

### 2. Alert And Triage Integration

Reuse these existing series without changing their labels or meaning:

- `tokenreviews_handler_requests_total{code,method}` and
  `subjectaccessreviews_handler_requests_total{code,method}` for webhook HTTP 5xx.
- `guard_azure_authz_checkaccess_failure_total{code,api_version}` and
  `guard_azure_authz_check_access_requests_total{code,api_version}` for PDP triage.
- `guard_azure_graph_failure_total` and `guard_azure_graph_sp_failure_total` for
  their currently covered Graph transport failures.

Add at most one bounded diagnostic counter,
`guard_azure_dependency_failures_total{dependency,reason}`, if required to cover
Graph HTTP / decode, OBO, and malformed PDP failures hidden by the current series.
Count once per failed Guard-level dependency invocation after existing internal
retries, not again at the handler. Cache hits and valid policy denials do not
increment it. Freeze dependency / reason enums; never label by tenant, user, app,
cluster resource ID, URL, raw error, or request ID.

Starting alert expression for the monitoring PR, not a production-tuned threshold:

```promql
sum by (cluster) (
  increase({__name__=~"(tokenreviews|subjectaccessreviews)_handler_requests_total",code=~"5.."}[5m])
) >= 5
```

Propose `for: 2m` and a warning routed to AKS on-call, with escalation based on
confirmed availability impact. `cluster` is an example scrape label, not a label
defined by Guard: replace it with the verified stable cluster identity and scope
to the owning environment before enabling the rule. Test one-series-only and
multi-pod cases so a missing authn or authz series cannot suppress the alert.

Evaluate against a healthy baseline, injected 500 bursts, and normal RBAC denials;
agree thresholds and paging policy with the monitoring owner. Include the TSG,
cluster identity, build version, time range, and dashboard / log links. Unit-test
the rule in the owning system and prove notification delivery in staging.

This alert cannot detect pre-token device-code failures, HTTP 200 negative
TokenReviews, or every cached authz denial. Pair it with dependency-classification
queries and the owned-tenant sign-in checks below. Publish actual, tested CCP /
Kusto queries for stage / reason / request-ID joins after verifying the ingestion
schema; do not invent column names in a Guard PR. Failure events must be visible
at the normal production log level without enabling global verbose logging.

### 3. Safety Constraints

- No changes to allow / deny / NoOpinion decisions, cache semantics, HTTP status
  semantics, retries, or timeout budgets in the diagnostic PR.
- No automatic CheckAccess v2-to-v1 fallback or fail-open behavior this week.
  The report's resilience recommendation needs a separate security and semantic
  review, including the actual v1/v2 request and authorization contracts.
- No new DataActions or CSR mapping changes. Any later mapping change requires
  resource-provider operation verification and Breaking Change review.
- Do not enable SP group resolution globally as an incidental IPD fix. Roll it
  through the AKS deployment setting only after the staging / CA tests pass.

## Reviewable Work Packages

| Package | Contents / dependency | Proposed effort and reviewer |
| --- | --- | --- |
| A: Guard PR | Safe diagnostic metadata and formatting, context propagation, dependency classification, bounded telemetry gap, regression tests | Approximately two engineer-days for Felix; Guard maintainer plus identity / security reviewer; confirm estimate on Monday |
| B: Monitoring / CCP / TSG PRs | Reuse existing HTTP counters immediately; integrate A's reason fields when available; alert, validated queries, decision tree, routing | Parallel with A; Felix and named AKS monitoring / CCP owners |
| C: External validation / release evidence | Bin's owned-tenant CA matrix, deployment-flag verification, and upstream change / rollback contract | Parallel with A; requires tenant permissions and AAD-FirstPartyApps release owner |

Review A in small commits: dependency error metadata first, safe request-boundary
reporting second, telemetry / tests last. Do not make B wait for a new Guard metric
to open its existing-500-counter alert PR. Assign concrete reviewers and PR links
in Feature 39815166 by Monday; no unnamed owner is a completed dependency.

If A exceeds the timebox, prioritize safe OBO / Graph attribution and the existing
500 alert, then retain generic `PDP_FAILED` when the SDK hides detail. Mark richer
PDP classification / API-server propagation as follow-up, not implemented. Do not
drop redaction, protocol-compatibility tests, or the real-tenant rollout gate.

## Acceptance And Verification

### Guard Regression Tests

Extend the existing [Azure tests](../../auth/providers/azure/azure_test.go),
[Graph tests](../../auth/providers/azure/graph/graph_test.go),
[AKS token-provider tests](../../auth/providers/azure/graph/aks_tokenprovider_test.go),
[v1 RBAC tests](../../authz/providers/azure/rbac/rbac_test.go),
[v2 tests](../../authz/providers/azure/rbac/checkaccess_v2_test.go),
[authz provider tests](../../authz/providers/azure/azure_test.go), and
[handler tests](../../server/handler_test.go). Avoid a new test harness.

- Table-test known / unknown structured OBO errors, policy block, Graph 403 / 429 /
  5xx, network / deadline failure, malformed / oversized bodies, invalid token vs.
  verifier outage, and absent upstream IDs. Verify metadata survives wrapping.
- For v1 and v2, cover allow, explicit policy deny, transport / decode failure,
  and empty responses. Assert no failure path becomes allowed and no retry,
  timeout, batching, or fallback behavior changes.
- Assert exact existing HTTP statuses and authn / authz decision fields,
  especially HTTP-200 negative TokenReviews, authz cached 4xx denials, transient
  errors remaining uncached, and `system:` / skip-list NoOpinion paths.
- Verify one root ID per webhook call, dependency / batch joins, and no new
  per-request identifier stored in cache. Metric tests assert bounded labels and
  no increments for cache hits or normal policy denial.
- Inject sentinel tokens, assertions, secrets, claims, and body text; capture
  response and normal / verbose logs. None may contain the sentinels. An unknown
  body still yields a safe `UNKNOWN` / generic dependency diagnostic.

Run the focused touched-package tests first. Before merging implementation,
follow the repository verification gates:

```bash
go test ./server/... ./auth/providers/azure/... ./authz/providers/azure/... -count=1
go build ./...
golangci-lint run ./...
gofmt -l .
go test ./authz/providers/azure/rbac/... ./auth/providers/azure/graph/... -count=1
```

New Go files require the repository's Apache header. Do not commit implementation
with failing required checks. Local verification on 11/10:

- `go build ./...` and the full affected-package test command above passed,
  including the required Graph and RBAC unit-test scopes.
- Changed Go files are formatted; Markdown link / fence / whitespace checks and
  `git diff --check` passed.
- `golangci-lint run ./...` could not run because the executable is unavailable.
- The stated repository-wide `gofmt -l .` gate reports pre-existing vendored files;
  those dependencies were not reformatted. This is not a clean full-format gate.

Lint and the repository-wide formatting baseline remain review / merge gates;
local test success is not a substitute. No staging, production, or live CCP query
validation is claimed.

### Staging And Owned-Tenant Matrix

Use an AKS staging cluster with Azure authn / authz, actual target application IDs,
and a tenant owned by the team. Retain test inputs, build / config version,
timestamps, safe request IDs, effective app / CA configuration, outcomes, and
rollback evidence. Never attach credentials or raw tokens.

| Scenario | Required evidence |
| --- | --- |
| User: device code, interactive browser, and Azure CLI; CA baseline and a controlled device-code block | Expected allow / block for the actual client, server, and downstream Graph resources; sign-in log reason and a working approved alternative |
| SP: below-overage and a verified overage-claim token; group-resolution flag off / on | Existing refusal with flag off; correct `/servicePrincipals` membership and group-derived RBAC with flag on; no changes to user group resolution |
| OBO / Graph: structured policy / permission failure, transport error, and malformed body | Correct safe stage / reason and upstream evidence when exposed; no false owner attribution |
| PDP v1 / v2: allow, genuine deny, timeout / 5xx, truncated JSON, and empty decisions | Unchanged authorization semantics, dependency vs. policy distinction, expected metrics, and alert firing for injected 500 bursts |
| Client: absent / invalid bearer token | Show whether the API server invokes Guard; if not, follow the client / API-server TSG branch rather than expect a Guard event |
| Existing standard and Entra-principal paths | Preserve `system:` bypass behavior; use a non-`system:` Entra identity to exercise actual Azure RBAC, not just standard kubelet traffic |

Mock OBO / PDP endpoints are suitable for deterministic Guard failure injection;
they do not validate upstream application permissions or real CA evaluation. User
device-code policy tests and SP / workload-identity tests are different flows and
must not be treated as interchangeable coverage.

An owned tenant or cloned test app alone cannot certify a not-yet-released change
to a global first-party app. Ask the upstream owner for a supported test flight /
ring and proof of the effective target app configuration. If that is unavailable,
record the limitation and keep the upstream rollout blocked pending a mutually
agreed validation / monitored rollout gate. Never modify production global app
permissions just to make a test pass.

For at least the four incident classes, have an operator use the TSG to reach the
correct next evidence source / escalation in a proposed 15-minute triage exercise.
Record what appears in Guard logs, API-server logs, CCP, and the client separately.
A passing webhook test is not evidence that kubectl displays the diagnostic.

## TSG And Upstream Change Contract

The operator decision tree must start with evidence:

1. Token acquisition failed before the API call: capture safe kubelogin error,
   login method, UTC time, and sign-in correlation ID; check CA / ESTS evidence.
2. Token reached the API server but no Guard call is visible: check exec-plugin /
   bearer-token handling and the API-server authentication path before blaming
   Graph or PDP. Confirm logging coverage before using absence as evidence.
3. Guard token verification failed: distinguish validation evidence from OIDC /
   Entra-sidecar availability, then inspect OBO / group-resolution events if those
   stages were reached.
4. A valid PDP deny is present: check assignment scope, role DataActions, and
   group-resolution evidence. A valid denial alone does not prove customer error.
5. OBO / Graph / PDP failed or returned an invalid response: use dependency IDs,
   recent change ledger, and service health to select the owning escalation.

The TSG must distinguish customer configuration, AKS deployment / OBO settings,
AAD-FirstPartyApps configuration, and ESTS service / policy evaluation. Require
corroborating sign-in logs, config comparison, upstream health, or a confirmed
change before assigning ownership; otherwise explicitly keep ownership unknown.

Link a single change ledger from the TSG. Each first-party app / Guard auth change
records: PR / task, owner, changed permissions / pre-authorizations / reply URLs or
deployment flags, expected affected login flows, effective time, rollout rings,
test evidence, AKS on-call / support notification, mitigation, rollback owner, and
actual rollback granularity. Agree notification before ring 1 with the upstream
release owner; appending a TSG after an outage is not the notification contract.
Guard must not poll or attempt to mutate global first-party app configuration.

Mitigations must be scenario-specific: an approved alternative login flow for a
device-code block; operator-controlled existing v2 toggle / reconcile only after
v1 compatibility is confirmed for PDP failure; upstream-owned app rollback; or a
reviewed role / configuration correction. Do not recommend disabling CA, granting
broad wildcard roles, or treating local-admin access as universally available.
Publish support routing to Identity / Authorization rather than defaulting every
case to Connectivity. Bin's guide update and Felix's diagnostics / change ledger
must link to the same decision tree rather than diverging copies.

## Proposed Sequence

| Date | Deliverable / review gate |
| --- | --- |
| Mon 11/09 | Review this scope; confirm Guard, monitoring, CCP, tenant-test, and upstream notification owners; agree diagnostic contract |
| Tue 11/10 | Open the Guard diagnostics PR with negative-path and redaction tests; open alert / TSG changes in their owning repositories |
| Wed 11/11 | Run staging failure injections and the owned-tenant auth matrix; validate API-server / CCP visibility and alert firing |
| Thu 11/12 | Security / owner review; deploy the approved candidate to a limited canary with a known rollback artifact |
| Fri 11/13 | Record canary evidence and rollout decision; mark unverified dependencies as blocked, not complete |

Friday is not a forced broad rollout. If an external dependency or canary gate is
not ready, deliver reviewed PRs and explicit blockers rather than claim production
coverage. Track implementation, staging validation, and production rollout as
separate states.

## Rollout, Rollback, And Completion

Use the approved AKS rollout mechanism: staging, limited canary, then expansion
only with owner sign-off. Propose a 24-hour canary observation window; any shorter
window needs an explicit risk acceptance, not a deadline-driven assumption. Watch
authn / authz failure rates, existing latency histograms, log volume, and alert
noise against the same-cluster baseline. Stop on any decision / status regression,
sensitive-data exposure, material latency increase, or unusable log / alert volume.

Keep the previous Guard artifact / deployment configuration and a separate alert
disable path ready. Revert the diagnostics build or monitoring rule without
changing application permissions or RBAC policy. The SP-resolution deployment
flag and upstream application rollout have separate owners / rollback mechanisms;
Guard deployment rollback is not an upstream app rollback.

Minimum Friday review packet:

- Reviewed Guard PR and test / redaction evidence; exact candidate build and
  deployment status, including any omitted reason classification.
- Monitoring PR, evaluated rule, delivered staging notification, tested CCP
  queries, and a linked operator TSG.
- Owned-tenant matrix results and upstream test-flight limitations; verified
  status of SP-resolution PR 17819571.
- Confirmed upstream notification / rollback owner and change-ledger link, or an
  explicit blocker with owner and next action.
- Canary observations / rollback drill and rollout sign-off, or a clear statement
  that production deployment has not met its gate.

This is an attribution / detection investment, not proof that IPD has already
fallen. Track alert detection and triage-exercise time this week; compare incident
rate and time-to-attribution over the following weeks.

## Explicit Follow-Ups

The report's resilience recommendation remains important but is not satisfied by
better logs: separately review bounded malformed-response retries, total deadline
budget, circuit-breaking, and whether any v2-to-v1 fallback is security- and
semantics-equivalent. Never fail open. Give this an owner / repair item by Friday.

Also track tenant / subscription rollback capability with the upstream owner,
continuous representative auth probes, and AKS Stretch / custom-role node-join
coverage. Do not claim existing Flex or `system:`-identity tests cover Stretch's
Entra-principal CSR path. Future DataAction changes require operation-manifest
verification, compatibility assessment, customer guidance, and the Breaking Change
process even when security-driven.

The incident report recommended safety work before the SP OBO expansion. Deferring
resilience here is an explicit scope / risk decision requiring Guard / identity
owner acceptance, not permission to bypass that sequencing or the CA rollout gate.

## Sources And Assumptions

- Feature 39815166 and the milestone screenshot supplied with this request.
- The supplied local KubeGuard / AAD authn-authz investigation, covering IcMs
  51000001317865, 848899489, 823292218, and 862149827. The report is not copied into
  this repository.
- Current source links above and [repository guidance](../../CLAUDE.md).

Except for alert PR 17444741 as described in the w3 update, no live incident
system, production telemetry, deployed configuration, tenant policy, upstream PR
status, or owner availability was independently verified.
Confirm these at kickoff and record evidence in the feature, not inferred green
status in this plan.