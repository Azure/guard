# Guard Azure Dependency Logging

Structured OBO and Graph failure diagnostics make the failing dependency, policy
evidence, and correlation IDs available without exposing raw upstream responses
or guessing fault ownership.

## Observed Issues

- OBO and Graph failures previously embedded raw response bodies in error strings,
  leaving operators to interpret cryptic messages and risking sensitive-data
  exposure. Verbose curl and token-claims dumps added similar risks.
- `AADSTS53003` establishes a Conditional Access block, not who caused it. An
  upstream first-party application change can trigger an unchanged customer
  policy; HTTP 4xx alone does not establish customer fault either.
- Missing structured fields and correlation IDs make it difficult to connect
  Guard failures to CCP/OBO logs and Entra sign-in evidence.

[Alert PR 17444741](https://dev.azure.com/msazure/CloudNativeCompute/_git/aks-rp-alerts/pullrequest/17444741?_a=files)
refines the existing `OBOActivity` query using status, AAD-code/message heuristics,
per-cluster error storms, and widespread failures, including `WidespreadCABlock`.
Those heuristics reduce noise but do not replace evidence-based attribution.
The query reads OBO service logs, not Guard events; this change does not directly
alter that alert.

## Implementation Scope

[Dependency diagnostics](../../auth/providers/azure/graph/diagnostics.go) cover:

- [AKS OBO token acquisition](../../auth/providers/azure/graph/aks_tokenprovider.go).
- [Direct Entra OBO acquisition](../../auth/providers/azure/graph/obo_tokenprovider.go).
- [Graph user/SP group lookup and group expansion](../../auth/providers/azure/graph/graph.go).

Each failed dependency invocation emits one normal-verbosity structured event.
The [Azure authenticator](../../auth/providers/azure/azure.go) adds a request ID to
the logging context. Dependency calls send separate UUIDs in `client-request-id`
and `x-ms-correlation-request-id`; Graph request headers are cloned rather than
mutating shared headers.

Error metadata parsing is bounded to 64 KiB and uses structured JSON fields,
allowlisted OAuth/Graph error codes, and validated UUIDs. Raw descriptions, bodies,
principal URLs, assertions, credentials, and token claims are excluded from these
changed failure paths. Credential-bearing direct OBO/Graph curl dumps and the
authenticator's unverified-claims dump are removed. Typed causes survive wrapping.

Authentication/authorization decisions, HTTP-status wrappers, caching, retries,
timeouts, metrics, and deployment defaults are unchanged. PDP, Arc, and other
Azure dependency paths are not covered by this logging change.

## Diagnostic Fields

| Field | Meaning |
| --- | --- |
| `event` | `guard_azure_dependency_failure`; emitted only on the structured event, not propagated error strings, to avoid double-counting |
| `requestID` | Parent Guard authn request ID from the logger context; authn, authz, and API-server audit IDs are not assumed identical |
| `stage` / `dependency` | `obo` or `graph`; `aks_obo`, `entra_obo`, or `ms_graph` |
| `reason` | `OBO_POLICY_BLOCKED` for structured OBO `53003` evidence; otherwise `OBO_FAILED` or `GRAPH_FAILED` |
| `responseClass` | `client_error` (4xx), `server_error` (5xx), `transport_error` (no response), `invalid_response` (decode failure), or `unexpected_status` |
| `upstreamStatus` | Immediate dependency's actual HTTP status, when available; not the TokenReview status or necessarily the ESTS status |
| `faultDomain` | `unknown`; policy codes and HTTP status do not prove ownership |
| `correlationID` | UUID generated for the outgoing dependency request |
| `aadCode` / `upstreamCode` | Structured numeric AAD code and allowlisted OAuth/Graph code, when available |
| `upstreamRequestID` / `upstreamCorrelationID` | Valid response-header IDs, falling back to body IDs when available |
| `aadTraceID` / `aadCorrelationID` | Separate Entra body IDs retained even when OBO headers contain different IDs |

An OBO 500 containing structured `53003` retains both `server_error` and
`OBO_POLICY_BLOCKED`. Unknown, malformed, or oversized bodies retain a generic
failure reason rather than inferring a cause from free-form text.

## Follow-Up Work

| Owner | Next action |
| --- | --- |
| Guard | Review the diagnostic contract and validate policy, transport, HTTP, and decode failures in staging; confirm upstream correlation-header handling and monitor log volume/redaction |
| CCP/logging | Verify normal-level events reach the log sink; publish tested queries by cluster, UTC time, stage, reason, status, and IDs; count structured events rather than repeated error text |
| OBO service | Preserve safe structured AAD error codes and Entra IDs; carry request correlation through service logs; address missing metadata at the producer instead of requiring Guard to parse prose |
| API server | Verify what reaches API-server logs separately from Guard logs and kubectl output; review any status/protocol changes separately |
| Alerting | Correlate Guard evidence with `OBOActivity`; backtest policy blocks and server failures before changing filters; retain widespread-CA detection without paging on every isolated policy event |
| TSG/support | Document sign-in-log lookup and application/policy-change checks; require corroborating evidence before assigning customer, AKS, AAD application, or ESTS ownership |

Group analysis by status/reason and affected clusters, not only `AADSTS53003`.
Cluster spread alone is not proof of an upstream incident: multiple clusters can
belong to one tenant. For Graph 403s, check audience, permissions, consent, and app
configuration rather than assuming a customer RBAC denial.

Guard cannot diagnose token acquisition that fails before it receives a request.
Existing non-200 TokenReview handling may also discard error text at the API
server. Better Guard logs therefore do not guarantee a client-visible message.
CCP ingestion, cross-service ID joins, and alert behavior require end-to-end
validation; they are not established by unit tests.

## Validation

Existing tests cover 400/500 responses with `53003`, malformed/oversized bodies,
invalid and distinct upstream/Entra IDs, transport cancellation, user/SP lookup,
typed-error wrapping, normal/verbose log redaction, and TokenReview serialization
with unchanged negative decisions and HTTP-status wrappers.

```bash
go test ./auth/providers/azure/... ./server/... -count=1
```

For integration validation, replay a policy block and a server failure, verify
the safe fields and IDs across Guard/CCP/OBO/Entra, and check API-server visibility
independently. Follow the repository's build and lint gates before merging.