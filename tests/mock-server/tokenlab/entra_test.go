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
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testTenantID  = "11111111-1111-1111-1111-111111111111"
	testClientID  = "22222222-2222-2222-2222-222222222222"
	testAssertion = "stub-client-assertion"
	testResource  = "https://authorization.azure.net"
)

// stubCredential returns a fixed assertion and records the audience it was asked
// for, so tests can assert the assertion is bound to the endpoint being called.
type stubCredential struct {
	mode         CredentialMode
	requestedAud string
	err          error
}

func (s *stubCredential) Mode() CredentialMode { return s.mode }

func (s *stubCredential) Assertion(_ context.Context, audience string) (string, error) {
	s.requestedAud = audience
	if s.err != nil {
		return "", s.err
	}
	return testAssertion, nil
}

// newTestClient wires a TokenClient at a stub authority and returns the form
// values the server received.
func newTestClient(t *testing.T, version APIVersion, handler http.HandlerFunc) (*TokenClient, *stubCredential) {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	credential := &stubCredential{mode: ModeFIC}
	client, err := NewTokenClient(TokenClientConfig{
		AuthorityHost: server.URL,
		TenantID:      testTenantID,
		ClientID:      testClientID,
		APIVersion:    version,
		Credential:    credential,
	})
	assert.NoError(t, err)
	return client, credential
}

func captureForm(received *url.Values, response string, status int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*received = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}
}

const successResponse = `{"access_token":"issued-token","token_type":"Bearer","expires_in":3599}`

func TestTokenClient_Endpoint(t *testing.T) {
	tests := []struct {
		version  APIVersion
		expected string
	}{
		{version: APIVersionV1, expected: "https://authority/" + testTenantID + "/oauth2/token"},
		{version: APIVersionV2, expected: "https://authority/" + testTenantID + "/oauth2/v2.0/token"},
	}

	for _, test := range tests {
		t.Run(string(test.version), func(t *testing.T) {
			client, err := NewTokenClient(TokenClientConfig{
				AuthorityHost: "https://authority/",
				TenantID:      testTenantID,
				ClientID:      testClientID,
				APIVersion:    test.version,
				Credential:    &stubCredential{mode: ModeCert},
			})
			assert.NoError(t, err)
			assert.Equal(t, test.expected, client.Endpoint())
		})
	}
}

// TestTokenClient_ClientCredentialsForm pins the exact wire contract. Getting a
// parameter name or grant value wrong would surface as a confusing AADSTS code
// rather than an obvious bug.
func TestTokenClient_ClientCredentialsForm(t *testing.T) {
	tests := []struct {
		name          string
		version       APIVersion
		audienceKey   string
		audienceValue string
	}{
		{
			name:          "v1 uses resource",
			version:       APIVersionV1,
			audienceKey:   paramResource,
			audienceValue: testResource,
		},
		{
			name:          "v2 uses default scope",
			version:       APIVersionV2,
			audienceKey:   paramScope,
			audienceValue: testResource + "/.default",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var form url.Values
			client, credential := newTestClient(t, test.version, captureForm(&form, successResponse, http.StatusOK))

			token, err := client.ClientCredentials(context.Background(), testResource)
			assert.NoError(t, err)
			assert.Equal(t, "issued-token", token.AccessToken)

			assert.Equal(t, GrantTypeClientCredentials, form.Get(paramGrantType))
			assert.Equal(t, testClientID, form.Get(paramClientID))
			assert.Equal(t, testAssertion, form.Get(paramClientAssertion))
			assert.Equal(t, ClientAssertionType, form.Get(paramClientAssertionType))
			assert.Equal(t, test.audienceValue, form.Get(test.audienceKey))

			// An app-only request must never carry a user assertion.
			assert.Empty(t, form.Get(paramAssertion))
			// The assertion must be bound to the endpoint it is sent to.
			assert.Equal(t, client.Endpoint(), credential.requestedAud)
		})
	}
}

func TestTokenClient_OnBehalfOfForm(t *testing.T) {
	var form url.Values
	client, _ := newTestClient(t, APIVersionV1, captureForm(&form, successResponse, http.StatusOK))

	_, err := client.OnBehalfOf(context.Background(), "user-token", "https://graph.microsoft.com")
	assert.NoError(t, err)

	assert.Equal(t, GrantTypeJWTBearer, form.Get(paramGrantType))
	assert.Equal(t, "user-token", form.Get(paramAssertion))
	assert.Equal(t, RequestedTokenUseOnBehalfOf, form.Get(paramRequestedTokenUse))
	// Client authentication is identical to the app-only grant: this is the
	// orthogonality the prototype exists to demonstrate.
	assert.Equal(t, testAssertion, form.Get(paramClientAssertion))
	assert.Equal(t, ClientAssertionType, form.Get(paramClientAssertionType))
}

func TestTokenClient_OnBehalfOfRequiresUserAssertion(t *testing.T) {
	client, _ := newTestClient(t, APIVersionV1, captureForm(new(url.Values), successResponse, http.StatusOK))

	_, err := client.OnBehalfOf(context.Background(), "", "https://graph.microsoft.com")
	assert.ErrorContains(t, err, "user assertion is required")
}

// TestTokenClient_SurfacesAADSTSCodes covers the failures that ARE the answers:
// a refusal must arrive as a typed error carrying the code, not as opaque text.
func TestTokenClient_SurfacesAADSTSCodes(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "no federated identity record",
			body:     `{"error":"invalid_client","error_description":"AADSTS70021: No matching federated identity record found for presented assertion."}`,
			expected: ErrCodeNoFederatedRecord,
		},
		{
			name:     "app token offered to OBO",
			body:     `{"error":"invalid_grant","error_description":"AADSTS7000113: OBO is not supported for app-only tokens."}`,
			expected: ErrCodeOBOAppToken,
		},
		{
			name:     "audience mismatch",
			body:     `{"error":"invalid_request","error_description":"AADSTS700212: audience mismatch."}`,
			expected: ErrCodeAudienceMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _ := newTestClient(t, APIVersionV1, captureForm(new(url.Values), test.body, http.StatusBadRequest))

			_, err := client.ClientCredentials(context.Background(), testResource)
			assert.Error(t, err)

			var tokenErr *TokenError
			assert.True(t, errors.As(err, &tokenErr), "error must be a *TokenError so callers can read the code")
			assert.Equal(t, test.expected, tokenErr.AADSTS)
			assert.Equal(t, http.StatusBadRequest, tokenErr.StatusCode)
			assert.Contains(t, tokenErr.Detail(), test.expected)
		})
	}
}

// A non-JSON body must not be swallowed - an unexpected body is itself the
// diagnostic, as the CheckAccess v2 "invalid character 'N'" incident showed.
func TestTokenClient_PreservesNonJSONErrorBody(t *testing.T) {
	client, _ := newTestClient(t, APIVersionV1, captureForm(new(url.Values), "Not Found", http.StatusNotFound))

	_, err := client.ClientCredentials(context.Background(), testResource)
	assert.Error(t, err)

	var tokenErr *TokenError
	assert.True(t, errors.As(err, &tokenErr))
	assert.Empty(t, tokenErr.AADSTS)
	assert.Contains(t, tokenErr.Detail(), "Not Found")
}

func TestTokenClient_RejectsIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  TokenClientConfig
	}{
		{name: "no tenant", cfg: TokenClientConfig{ClientID: testClientID, APIVersion: APIVersionV1, Credential: &stubCredential{}}},
		{name: "no client", cfg: TokenClientConfig{TenantID: testTenantID, APIVersion: APIVersionV1, Credential: &stubCredential{}}},
		{name: "no credential", cfg: TokenClientConfig{TenantID: testTenantID, ClientID: testClientID, APIVersion: APIVersionV1}},
		{name: "bad version", cfg: TokenClientConfig{TenantID: testTenantID, ClientID: testClientID, APIVersion: "v3", Credential: &stubCredential{}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewTokenClient(test.cfg)
			assert.Error(t, err)
		})
	}
}

func TestToDefaultScope(t *testing.T) {
	assert.Equal(t, "https://graph.microsoft.com/.default", toDefaultScope("https://graph.microsoft.com"))
	assert.Equal(t, "https://graph.microsoft.com/.default", toDefaultScope("https://graph.microsoft.com/"))
	// Already-scoped values must pass through unchanged rather than doubling up.
	assert.Equal(t, "https://graph.microsoft.com/.default", toDefaultScope("https://graph.microsoft.com/.default"))
}

// TestParseTokenResponse_DialectDifferences pins the type difference between the
// two endpoints. v1 quotes its numbers; v2 does not. Getting this wrong made
// every v1 row fail with a decode error that looked like a credential problem.
func TestParseTokenResponse_DialectDifferences(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "v1 quotes expires_on and expires_in",
			body: `{"access_token":"t","token_type":"Bearer","expires_in":"3599","expires_on":"1800000000"}`,
		},
		{
			name: "v2 returns expires_in as a number",
			body: `{"access_token":"t","token_type":"Bearer","expires_in":3599}`,
		},
		{
			name: "missing expiry fields",
			body: `{"access_token":"t","token_type":"Bearer"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, err := parseTokenResponse([]byte(test.body))
			assert.NoError(t, err)
			assert.Equal(t, "t", token.AccessToken)
		})
	}
}

func TestParseTokenResponse_RejectsMissingToken(t *testing.T) {
	_, err := parseTokenResponse([]byte(`{"token_type":"Bearer","expires_in":3599}`))
	assert.ErrorContains(t, err, "no access_token")
}
