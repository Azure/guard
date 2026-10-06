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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	pdp "github.com/Azure/checkaccess-v2-go-sdk/client"
)

// TestBuildPDPEndpoint pins the full URL shape. Pointing the SDK at the bare
// host returns a 404 HTML page, which is what produced "invalid character 'N'"
// and a fleet-wide Sev2 - the path and api-version are not optional.
func TestBuildPDPEndpoint(t *testing.T) {
	endpoint := BuildPDPEndpoint("westus2")

	assert.Equal(t,
		"https://westus2.authorization.azure.net/providers/microsoft.authorization/checkAccess?api-version=2021-06-01-preview",
		endpoint)
	assert.Contains(t, endpoint, "/providers/microsoft.authorization/checkAccess")
	assert.Contains(t, endpoint, "api-version=")
}

func newPDPTestClient(t *testing.T, handler http.HandlerFunc) *PDPClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewPDPClient(server.URL)
}

func TestPDPClient_SendsBearerTokenAndDecodesDecision(t *testing.T) {
	var gotAuth, gotContentType string

	client := newPDPTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[{"actionId":"Microsoft.ContainerService/managedClusters/read","accessDecision":"Allowed"}]}`))
	})

	request := NewAccessRequest("subject-oid", "/subscriptions/s/resourceGroups/rg", "Microsoft.ContainerService/managedClusters/read")
	decision, err := client.CheckAccess(context.Background(), "the-pdp-token", request)

	assert.NoError(t, err)
	assert.Equal(t, "Bearer the-pdp-token", gotAuth)
	assert.Equal(t, "application/json", gotContentType)
	assert.Len(t, decision.Value, 1)
	assert.Contains(t, SummarizeDecisions(decision), "Allowed")
}

// A denied decision is still a successful end-to-end result: the call was
// authenticated and evaluated. Treating it as a failure would misreport the
// very thing this harness exists to measure.
func TestPDPClient_DeniedIsStillASuccessfulCall(t *testing.T) {
	client := newPDPTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":[{"actionId":"a","accessDecision":"NotAllowed"}]}`))
	})

	decision, err := client.CheckAccess(context.Background(), "token", NewAccessRequest("oid", "/subscriptions/s", "a"))

	assert.NoError(t, err)
	assert.Contains(t, SummarizeDecisions(decision), "NotAllowed")
}

func TestPDPClient_ClassifiesFailures(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		body          string
		tokenRejected bool
		wantMessage   string
	}{
		{
			name:          "unauthorized means the token was refused",
			status:        http.StatusUnauthorized,
			body:          `{"error":"invalid token"}`,
			tokenRejected: true,
			wantMessage:   "PDP refused the token",
		},
		{
			name:          "forbidden means the caller lacks checkAccess/action",
			status:        http.StatusForbidden,
			body:          `{"error":"AuthorizationFailed"}`,
			tokenRejected: true,
			wantMessage:   "PDP refused the token",
		},
		{
			name:          "not found means the endpoint URL is wrong, not the credential",
			status:        http.StatusNotFound,
			body:          "<html>Not Found</html>",
			tokenRejected: false,
			wantMessage:   "missing the checkAccess path or api-version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newPDPTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})

			_, err := client.CheckAccess(context.Background(), "token", NewAccessRequest("oid", "/subscriptions/s", "a"))
			assert.Error(t, err)

			var pdpErr *PDPError
			assert.True(t, errors.As(err, &pdpErr))
			assert.Equal(t, test.status, pdpErr.StatusCode)
			assert.Equal(t, test.tokenRejected, pdpErr.TokenRejected())
			assert.Contains(t, err.Error(), test.wantMessage)
		})
	}
}

// A 200 carrying something other than the expected JSON must surface the body,
// not just a decode error - the body is the diagnostic.
func TestPDPClient_SurfacesUndecodableBody(t *testing.T) {
	client := newPDPTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Not JSON at all"))
	})

	_, err := client.CheckAccess(context.Background(), "token", NewAccessRequest("oid", "/subscriptions/s", "a"))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Not JSON at all")
}

func TestNewAccessRequest(t *testing.T) {
	request := NewAccessRequest("subject-oid", "/subscriptions/s/rg/cluster", "Microsoft.ContainerService/managedClusters/read")

	assert.Equal(t, "subject-oid", request.Subject.Attributes.ObjectId)
	assert.Equal(t, "/subscriptions/s/rg/cluster", request.Resource.Id)
	assert.Len(t, request.Actions, 1)
	assert.Equal(t, "Microsoft.ContainerService/managedClusters/read", request.Actions[0].Id)
	// A management-plane action must not be flagged as a data action, or PDP
	// evaluates it against a different set of role definitions.
	assert.False(t, request.Actions[0].IsDataAction)
}

func TestSummarizeDecisions_EmptyResponse(t *testing.T) {
	assert.Equal(t, "no decisions returned", SummarizeDecisions(nil))
	assert.Equal(t, "no decisions returned", SummarizeDecisions(&pdp.AuthorizationDecisionResponse{}))
}
