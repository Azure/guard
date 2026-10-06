/*
Copyright The Guard Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tokenlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	pdp "github.com/Azure/checkaccess-v2-go-sdk/client"
)

// pdpEndpointFormat is the FULL CheckAccess v2 URL.
//
// The path and api-version are mandatory. The SDK POSTs to this URL with no path
// manipulation, so pointing at the bare host returns 404 with an HTML body -
// which is what produced "invalid character 'N'" and a fleet-wide Sev2 (WCUS,
// IcM 810395271). Building it in one place keeps that from recurring.
const pdpEndpointFormat = "https://%s.authorization.azure.net/providers/microsoft.authorization/checkAccess?api-version=2021-06-01-preview"

// BuildPDPEndpoint returns the CheckAccess v2 URL for a region.
func BuildPDPEndpoint(region string) string {
	return fmt.Sprintf(pdpEndpointFormat, region)
}

// PDPClient calls the Azure RBAC data plane with a PDP-audience bearer token.
//
// This is the step that distinguishes "Entra issued a token" from "the token is
// actually usable". Entra issues to anyone whose client authentication succeeds;
// PDP additionally requires the caller to hold
// Microsoft.Authorization/checkAccess/action.
type PDPClient struct {
	endpoint string
	http     *http.Client
}

// NewPDPClient returns a client for the given full CheckAccess URL.
func NewPDPClient(endpoint string) *PDPClient {
	return &PDPClient{
		endpoint: endpoint,
		http:     &http.Client{Timeout: httpTimeout},
	}
}

// PDPError is a failure from the CheckAccess endpoint. The status code carries
// the meaning: 401/403 mean the token was refused, 404 means the endpoint URL is
// wrong rather than the credential.
type PDPError struct {
	StatusCode int
	Body       string
}

func (e *PDPError) Error() string {
	switch e.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("PDP refused the token (HTTP %d): %s", e.StatusCode, truncate(e.Body, 300))
	case http.StatusNotFound:
		return fmt.Sprintf("PDP returned 404 - the endpoint URL is missing the checkAccess path or api-version: %s", truncate(e.Body, 200))
	default:
		return fmt.Sprintf("PDP call failed (HTTP %d): %s", e.StatusCode, truncate(e.Body, 300))
	}
}

// TokenRejected reports whether the failure was an authentication or
// authorization refusal of the credential itself, as opposed to a malformed
// request or a wrong URL.
func (e *PDPError) TokenRejected() bool {
	return e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden
}

// CheckAccess submits an authorization request using the supplied bearer token.
//
// A returned decision - whether it says allowed or denied - proves the token was
// accepted and PDP evaluated the request. "Denied" is a successful end-to-end
// result: it means the call was authenticated and answered.
func (c *PDPClient) CheckAccess(ctx context.Context, bearerToken string, request pdp.AuthorizationRequest) (*pdp.AuthorizationDecisionResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal CheckAccess request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create CheckAccess request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CheckAccess request to %s failed: %w", c.endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read CheckAccess response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &PDPError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var decision pdp.AuthorizationDecisionResponse
	if err := json.Unmarshal(body, &decision); err != nil {
		return nil, fmt.Errorf("decode CheckAccess response: %w (body: %s)", err, truncate(string(body), 200))
	}

	return &decision, nil
}

// NewAccessRequest builds a minimal, well-formed CheckAccess request.
//
// resourceID must be a REAL Azure resource id; PDP rejects synthetic scopes.
// The action is only used to elicit a decision, so a plain read is sufficient -
// the objective is to prove the call is authenticated and answered, not to
// obtain any particular verdict.
func NewAccessRequest(subjectObjectID, resourceID, action string) pdp.AuthorizationRequest {
	return pdp.AuthorizationRequest{
		Subject: pdp.SubjectInfo{
			Attributes: pdp.SubjectAttributes{ObjectId: subjectObjectID},
		},
		Actions: []pdp.ActionInfo{
			{Id: action, IsDataAction: false},
		},
		Resource: pdp.ResourceInfo{Id: resourceID},
	}
}

// SummarizeDecisions renders the decisions for the results table.
func SummarizeDecisions(response *pdp.AuthorizationDecisionResponse) string {
	if response == nil || len(response.Value) == 0 {
		return "no decisions returned"
	}

	first := response.Value[0]
	return fmt.Sprintf("decision=%s action=%s (%d returned)",
		string(first.AccessDecision), first.ActionId, len(response.Value))
}
