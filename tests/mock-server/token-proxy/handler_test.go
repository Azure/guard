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

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.kubeguard.dev/guard/tests/mock-server/tokenlab"
)

// recordingIssuer captures which grant was invoked, which is the property the
// path dispatch must get right.
type recordingIssuer struct {
	calledGrant   string
	userAssertion string
	resource      string
	err           error
}

func (r *recordingIssuer) ClientCredentials(_ context.Context, resource string) (*tokenlab.Token, error) {
	r.calledGrant = "client_credentials"
	r.resource = resource
	return r.result()
}

func (r *recordingIssuer) OnBehalfOf(_ context.Context, userAssertion, resource string) (*tokenlab.Token, error) {
	r.calledGrant = "on-behalf-of"
	r.userAssertion = userAssertion
	r.resource = resource
	return r.result()
}

func (r *recordingIssuer) result() (*tokenlab.Token, error) {
	if r.err != nil {
		return nil, r.err
	}
	return &tokenlab.Token{
		AccessToken: "issued-token",
		TokenType:   "Bearer",
		ExpiresOn:   time.Now().Add(time.Hour),
	}, nil
}

func newTestServer(mode tokenlab.CredentialMode, issuer tokenIssuer) *Server {
	return &Server{
		mode:              mode,
		issuer:            issuer,
		oboResource:       "https://graph.microsoft.com",
		authzResource:     "https://management.azure.com",
		passthroughErrors: true,
	}
}

func post(t *testing.T, server *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	recorder := httptest.NewRecorder()
	server.Route(recorder, request)
	return recorder
}

// TestRoute_DispatchesByPathSuffix is the regression guard for the defect this
// handler replaced: a single handler served both endpoints from IMDS, so a
// delegated request silently received an app-only token.
func TestRoute_DispatchesByPathSuffix(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		body          string
		expectedGrant string
	}{
		{
			name:          "authztoken performs the app-only grant",
			path:          "/v1/ccp-id/authztoken",
			body:          `{"tenantID":"tid","resource":"https://authorization.azure.net"}`,
			expectedGrant: "client_credentials",
		},
		{
			name:          "token performs the delegated grant",
			path:          "/v1/ccp-id/token",
			body:          `{"tenantID":"tid","accessToken":"user-token"}`,
			expectedGrant: "on-behalf-of",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := &recordingIssuer{}
			server := newTestServer(tokenlab.ModeFIC, issuer)

			recorder := post(t, server, test.path, test.body)

			assert.Equal(t, http.StatusOK, recorder.Code)
			assert.Equal(t, test.expectedGrant, issuer.calledGrant)
		})
	}
}

func TestServeToken_ForwardsTheUserAssertion(t *testing.T) {
	issuer := &recordingIssuer{}
	server := newTestServer(tokenlab.ModeFIC, issuer)

	post(t, server, "/v1/ccp-id/token", `{"tenantID":"tid","accessToken":"the-user-token"}`)

	assert.Equal(t, "the-user-token", issuer.userAssertion)
	// With no resource in the body, the configured default must be used.
	assert.Equal(t, "https://graph.microsoft.com", issuer.resource)
}

// A delegated request with no user token is a misrouted request. Answering it
// would hand back an app-only token that looks valid, so it must fail loudly.
func TestServeToken_RejectsMissingUserAssertion(t *testing.T) {
	issuer := &recordingIssuer{}
	server := newTestServer(tokenlab.ModeFIC, issuer)

	recorder := post(t, server, "/v1/ccp-id/token", `{"tenantID":"tid"}`)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Empty(t, issuer.calledGrant, "no exchange should be attempted")
}

// mode=imds has no user identity available, so it must refuse the delegated
// endpoint rather than substitute an app-only token.
func TestServeToken_IMDSModeRefusesDelegatedEndpoint(t *testing.T) {
	server := newTestServer(tokenlab.ModeIMDS, &recordingIssuer{})

	recorder := post(t, server, "/v1/ccp-id/token", `{"tenantID":"tid","accessToken":"user-token"}`)

	assert.Equal(t, http.StatusNotImplemented, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "carries no user identity")
}

// TestRespond_MatchesGuardWireContract pins the response shape. Guard reads
// expires_on as Unix seconds and treats zero as already expired, so a wrong
// field name would cause constant token refresh rather than an obvious error.
func TestRespond_MatchesGuardWireContract(t *testing.T) {
	server := newTestServer(tokenlab.ModeFIC, &recordingIssuer{})

	recorder := post(t, server, "/v1/ccp-id/authztoken", `{"tenantID":"tid"}`)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var body map[string]any
	assert.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))

	assert.Equal(t, "issued-token", body["access_token"])
	assert.Equal(t, "Bearer", body["token_type"])

	expiresOn, ok := body["expires_on"].(float64)
	assert.True(t, ok, "expires_on must be numeric Unix seconds")
	assert.Greater(t, int64(expiresOn), time.Now().Unix())
}

func TestRoute_UnknownPath(t *testing.T) {
	server := newTestServer(tokenlab.ModeFIC, &recordingIssuer{})

	recorder := post(t, server, "/v1/ccp-id/something-else", `{}`)

	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestDecode_RejectsNonPost(t *testing.T) {
	server := newTestServer(tokenlab.ModeFIC, &recordingIssuer{})

	request := httptest.NewRequest(http.MethodGet, "/v1/ccp-id/authztoken", nil)
	recorder := httptest.NewRecorder()
	server.Route(recorder, request)

	assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
}
