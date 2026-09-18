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

# Provisions the Entra objects the tokenlab probe needs, then verifies each
# prerequisite before the next one depends on it.
#
# Two applications are created rather than one, so no tenant admin is required:
#
#   midtier     stands in for the AKS first-party app. Carries the federated
#               identity credential. Pre-authorizes the Azure CLI, so a user
#               token for it can be fetched with NO consent prompt.
#   downstream  stands in for Microsoft Graph. Pre-authorizes midtier, so the
#               on-behalf-of exchange needs NO consent grant either.
#
# Using Graph itself as the downstream would need GroupMember.Read.All, which is
# admin-consent-required and would block the experiment in a corporate tenant.
#
# Usage:
#   ./tokenlab-setup.sh create   -g <resource-group> -c <aks-cluster>
#   ./tokenlab-setup.sh token
#   ./tokenlab-setup.sh show
#   ./tokenlab-setup.sh destroy

set -euo pipefail

MIDTIER_NAME="${MIDTIER_NAME:-guard-tokenlab-midtier}"
DOWNSTREAM_NAME="${DOWNSTREAM_NAME:-guard-tokenlab-downstream}"
# Azure CLI's well-known first-party client id. Pre-authorizing it is what makes
# `az account get-access-token --resource api://<midtier>` work without consent.
AZURE_CLI_APP_ID="04b07795-8ddb-461a-bbee-02f9e1bf7b46"
# The Microsoft corporate tenant rejects app registrations that carry no Service
# Tree id ("ServiceManagementReference field is required for Create"). This is
# the AKS DevInfra id used by .pipelines/github/dev/managedsdp; override with
# SERVICE_TREE_ID if your team has its own.
SERVICE_TREE_ID="${SERVICE_TREE_ID:-f1d1800e-d38e-41f2-b63c-72d59ecaf9c0}"
STATE_FILE="${STATE_FILE:-$HOME/.config/guard-tokenlab/state.env}"
USER_TOKEN_FILE="${USER_TOKEN_FILE:-/tmp/tokenlab-user-token}"

RESOURCE_GROUP=""
CLUSTER_NAME=""
IDENTITY_NAME=""
IDENTITY_OBJECT_ID=""

# Progress goes to stderr so that functions which return a value on stdout can
# be used in command substitution without their log lines being captured.
log() { printf '  %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*" >&2; }
die() {
    printf '\nSTOP: %s\n' "$*" >&2
    exit 1
}

require_az_login() {
    az account show >/dev/null 2>&1 || die "not logged in; run 'az login' first"
}

# --- gate 0: can this account create app registrations at all? ---------------
# Everything downstream depends on this. The tenant policy may permit it while
# a Conditional Access or delegation rule still refuses, so it is probed for
# real rather than inferred.
create_app() {
    local display_name="$1"
    local existing
    existing=$(az ad app list --display-name "$display_name" --query '[0].appId' -o tsv 2>/dev/null || true)

    if [[ -n "$existing" && "$existing" != "null" ]]; then
        log "reusing existing application $display_name ($existing)"
        printf '%s' "$existing"
        return
    fi

    local app_id create_error
    # NOTE: accessTokenAcceptedVersion is deliberately left at its default (v1).
    # Guard reads the v1 discovery document, so a v2 app would issue tokens with a
    # login.microsoftonline.com/.../v2.0 issuer that Guard rejects.
    create_error=$(az ad app create --display-name "$display_name" --sign-in-audience AzureADMyOrg \
        --service-management-reference "$SERVICE_TREE_ID" --query appId -o tsv 2>&1) || {
        printf '\nSTOP: cannot create app registration %s\n  %s\n' "$display_name" "$create_error" >&2
        exit 1
    }
    app_id="$create_error"

    log "created application $display_name ($app_id)"
    printf '%s' "$app_id"
}

# ensure_service_principal creates the SP for an application, retrying because
# Graph is eventually consistent: an app is not immediately queryable after
# creation, and the CLI surfaces that as an opaque JSON decode error rather than
# a retryable status.
ensure_service_principal() {
    local app_id="$1" attempt

    for attempt in 1 2 3 4 5 6; do
        if az ad sp show --id "$app_id" >/dev/null 2>&1; then
            return 0
        fi
        if az ad sp create --id "$app_id" >/dev/null 2>&1; then
            log "created service principal for $app_id"
            return 0
        fi
        log "waiting for $app_id to propagate (attempt $attempt)"
        sleep 10
    done

    die "service principal for $app_id could not be created after several attempts"
}

# expose_scope publishes a delegated scope and pre-authorizes one client for it,
# which is what removes the consent requirement.
#
# This must be two PATCHes: Graph validates preAuthorizedApplications against the
# scopes that already exist on the application, so a single call declaring both
# fails with "Permission Id that cannot be found in the AppPermissions sets".
expose_scope() {
    local object_id="$1" scope_name="$2" authorized_client="$3" scope_id="$4"

    az rest --method PATCH \
        --uri "https://graph.microsoft.com/v1.0/applications/${object_id}" \
        --headers Content-Type=application/json \
        --body "{
      \"api\": {
        \"oauth2PermissionScopes\": [{
          \"id\": \"${scope_id}\",
          \"value\": \"${scope_name}\",
          \"type\": \"User\",
          \"isEnabled\": true,
          \"adminConsentDisplayName\": \"Access ${scope_name}\",
          \"adminConsentDescription\": \"Access ${scope_name} as the signed-in user\",
          \"userConsentDisplayName\": \"Access ${scope_name}\",
          \"userConsentDescription\": \"Access ${scope_name} as you\"
        }]
      }
    }" >/dev/null || die "could not expose scope ${scope_name}"

    log "exposed scope ${scope_name}"

    # Give Graph a moment to make the new scope visible to the validator.
    sleep 5

    az rest --method PATCH \
        --uri "https://graph.microsoft.com/v1.0/applications/${object_id}" \
        --headers Content-Type=application/json \
        --body "{
      \"api\": {
        \"preAuthorizedApplications\": [{
          \"appId\": \"${authorized_client}\",
          \"delegatedPermissionIds\": [\"${scope_id}\"]
        }]
      }
    }" >/dev/null || die "could not pre-authorize ${authorized_client} for ${scope_name}"

    log "pre-authorized ${authorized_client} for ${scope_name}"
}

read_kubelet_identity() {
    [[ -n "$RESOURCE_GROUP" && -n "$CLUSTER_NAME" ]] || die "--resource-group and --cluster are required for 'create'"

    local identity
    identity=$(az aks show -g "$RESOURCE_GROUP" -n "$CLUSTER_NAME" --query identityProfile.kubeletidentity -o json) ||
        die "cannot read cluster $CLUSTER_NAME in $RESOURCE_GROUP"

    MI_CLIENT_ID=$(printf '%s' "$identity" | jq -r '.clientId')
    MI_OBJECT_ID=$(printf '%s' "$identity" | jq -r '.objectId')

    [[ -n "$MI_CLIENT_ID" && "$MI_CLIENT_ID" != "null" ]] ||
        die "cluster has no user-assigned kubelet identity; federated credentials require one"

    # A real resource id is required for CheckAccess - PDP rejects synthetic
    # scopes. The cluster itself is a convenient, genuinely existing target.
    CLUSTER_ID=$(az aks show -g "$RESOURCE_GROUP" -n "$CLUSTER_NAME" --query id -o tsv)

    log "kubelet identity clientId=$MI_CLIENT_ID objectId=$MI_OBJECT_ID"
    log "check resource $CLUSTER_ID"
}

# grant_checkaccess_role gives a principal the ability to call CheckAccess.
#
# Microsoft.Authorization/checkAccess/action is not exposed by any narrow
# built-in role; it is only reachable through a wildcard, which is why
# Contributor is used here. Without it the token is issued normally and PDP
# refuses it at call time - a failure mode that looks like a credential problem
# but is not.
grant_checkaccess_role() {
    local principal_id="$1" description="$2"
    local scope="/subscriptions/${SUBSCRIPTION_ID}"

    if az role assignment list --assignee "$principal_id" --scope "$scope" --role Contributor \
        --query '[0].id' -o tsv 2>/dev/null | grep -q .; then
        log "$description already has Contributor"
        return
    fi

    az role assignment create \
        --assignee-object-id "$principal_id" \
        --assignee-principal-type ServicePrincipal \
        --role Contributor \
        --scope "$scope" >/dev/null 2>&1 &&
        log "granted Contributor to $description ($principal_id)" ||
        log "WARNING: could not grant Contributor to $description; PDP calls will return 403"
}

# create_federated_credential is the trust link that lets Entra accept the
# managed identity's token as proof of the application's identity.
create_federated_credential() {
    local app_id="$1" name="$2" subject="$3"

    if az ad app federated-credential show --id "$app_id" --federated-credential-id "$name" >/dev/null 2>&1; then
        log "federated credential $name already exists"
        return
    fi

    # subject MUST be the managed identity's OBJECT (principal) id, not its client
    # id. A wrong value still creates successfully and only fails at exchange time
    # with AADSTS70021, so it is worth double-checking against the log line above.
    az ad app federated-credential create --id "$app_id" --parameters "{
    \"name\": \"${name}\",
    \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
    \"subject\": \"${subject}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" >/dev/null

    log "created federated credential $name (subject=$subject)"
}

save_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    cat >"$STATE_FILE" <<EOF
TENANT_ID=$TENANT_ID
SUBSCRIPTION_ID=$SUBSCRIPTION_ID
MIDTIER_APP_ID=$MIDTIER_APP_ID
MIDTIER_SP_OID=${MIDTIER_SP_OID:-}
DOWNSTREAM_APP_ID=$DOWNSTREAM_APP_ID
MI_CLIENT_ID=${MI_CLIENT_ID:-}
MI_OBJECT_ID=${MI_OBJECT_ID:-}
CLUSTER_ID=${CLUSTER_ID:-}
OBO_RESOURCE=api://$DOWNSTREAM_APP_ID
EOF
    log "wrote $STATE_FILE"
}

load_state() {
    [[ -f "$STATE_FILE" ]] || die "no state at $STATE_FILE; run '$0 create' first"
    # shellcheck disable=SC1090
    source "$STATE_FILE"
}

cmd_create() {
    require_az_login
    TENANT_ID=$(az account show --query tenantId -o tsv)
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)

    step "gate 0: application registration"
    DOWNSTREAM_APP_ID=$(create_app "$DOWNSTREAM_NAME")
    MIDTIER_APP_ID=$(create_app "$MIDTIER_NAME")
    ensure_service_principal "$DOWNSTREAM_APP_ID"
    ensure_service_principal "$MIDTIER_APP_ID"
    MIDTIER_SP_OID=$(az ad sp show --id "$MIDTIER_APP_ID" --query id -o tsv)

    step "identifier URIs and pre-authorized scopes"
    az ad app update --id "$DOWNSTREAM_APP_ID" --identifier-uris "api://$DOWNSTREAM_APP_ID" >/dev/null
    az ad app update --id "$MIDTIER_APP_ID" --identifier-uris "api://$MIDTIER_APP_ID" >/dev/null

    local downstream_object midtier_object
    downstream_object=$(az ad app show --id "$DOWNSTREAM_APP_ID" --query id -o tsv)
    midtier_object=$(az ad app show --id "$MIDTIER_APP_ID" --query id -o tsv)

    # downstream trusts midtier -> the OBO exchange needs no consent grant.
    expose_scope "$downstream_object" "access_as_user" "$MIDTIER_APP_ID" "$(uuidgen)"
    # midtier trusts the Azure CLI -> the user token needs no consent prompt.
    expose_scope "$midtier_object" "user_impersonation" "$AZURE_CLI_APP_ID" "$(uuidgen)"

    step "gate 1: kubelet managed identity"
    read_kubelet_identity

    step "gate 2: federated identity credential"
    create_federated_credential "$MIDTIER_APP_ID" "aks-kubelet-mi" "$MI_OBJECT_ID"

    step "gate 3: CheckAccess permission"
    # Both principals need it: the managed identity is the caller in imds mode,
    # the midtier application is the caller in fic and cert modes.
    grant_checkaccess_role "$MI_OBJECT_ID" "kubelet managed identity"
    grant_checkaccess_role "$MIDTIER_SP_OID" "midtier application"

    save_state

    step "next"
    log "run '$0 token' to fetch a user token (gate 4)"
    log "federated credentials and role assignments both take a few minutes to"
    log "propagate; AADSTS70021 or a PDP 403 right after creation usually means"
    log "'not yet', not 'misconfigured'"
}

# cmd_token is gate 3: a delegated user token whose audience is the midtier app.
# Without it the on-behalf-of rows cannot run at all.
cmd_token() {
    require_az_login
    load_state

    step "gate 3: delegated user token"
    if ! az account get-access-token --resource "api://$MIDTIER_APP_ID" --query accessToken -o tsv >"$USER_TOKEN_FILE" 2>/dev/null; then
        rm -f "$USER_TOKEN_FILE"
        die "could not obtain a user token for api://$MIDTIER_APP_ID.
  AADSTS65001 means the pre-authorization did not apply - re-run 'create'.
  AADSTS53003/50076/530003 are Conditional Access; that needs an administrator."
    fi

    chmod 600 "$USER_TOKEN_FILE"
    log "wrote $USER_TOKEN_FILE"
    log "tokens last about an hour - run the probe within that window"
}

cmd_show() {
    load_state
    cat "$STATE_FILE"
}

# cmd_add_identity registers an ADDITIONAL managed identity against the existing
# midtier application.
#
# Needed because the identity IMDS returns differs per cluster: the plain test
# cluster uses its own kubelet identity, while a standalone's underlay uses that
# underlay's. A federated credential is bound to one subject, so each cluster
# needs its own (the limit is 20 per application).
cmd_add_identity() {
    require_az_login
    load_state

    [[ -n "$IDENTITY_NAME" ]] || die "--name is required (a label for the federated credential)"
    [[ -n "$IDENTITY_OBJECT_ID" ]] || die "--object-id is required (the managed identity's OBJECT/principal id)"

    step "federated credential for $IDENTITY_NAME"
    create_federated_credential "$MIDTIER_APP_ID" "$IDENTITY_NAME" "$IDENTITY_OBJECT_ID"

    step "CheckAccess permission for $IDENTITY_NAME"
    grant_checkaccess_role "$IDENTITY_OBJECT_ID" "$IDENTITY_NAME"

    step "done"
    log "allow a few minutes for the credential and role assignment to propagate"
}

cmd_destroy() {
    require_az_login
    load_state

    step "removing applications"
    az ad app delete --id "$MIDTIER_APP_ID" 2>/dev/null && log "deleted $MIDTIER_APP_ID" || log "midtier already gone"
    az ad app delete --id "$DOWNSTREAM_APP_ID" 2>/dev/null && log "deleted $DOWNSTREAM_APP_ID" || log "downstream already gone"
    rm -f "$STATE_FILE" "$USER_TOKEN_FILE"
    log "removed local state"
}

main() {
    local command="${1:-}"
    shift || true

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -g | --resource-group)
                RESOURCE_GROUP="$2"
                shift 2
                ;;
            -c | --cluster)
                CLUSTER_NAME="$2"
                shift 2
                ;;
            -n | --name)
                IDENTITY_NAME="$2"
                shift 2
                ;;
            -o | --object-id)
                IDENTITY_OBJECT_ID="$2"
                shift 2
                ;;
            *) die "unknown argument: $1" ;;
        esac
    done

    case "$command" in
        create) cmd_create ;;
        token) cmd_token ;;
        show) cmd_show ;;
        add-identity) cmd_add_identity ;;
        destroy) cmd_destroy ;;
        *) die "usage: $0 {create|token|show|add-identity|destroy} [-g <rg>] [-c <cluster>] [-n <name>] [-o <mi-object-id>]" ;;
    esac
}

main "$@"
