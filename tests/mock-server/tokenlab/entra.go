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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// form parameter names for the Entra token endpoint.
const (
	paramGrantType           = "grant_type"
	paramClientID            = "client_id"
	paramClientAssertion     = "client_assertion"
	paramClientAssertionType = "client_assertion_type"
	paramResource            = "resource"
	paramScope               = "scope"
	paramAssertion           = "assertion"
	paramRequestedTokenUse   = "requested_token_use"
)

// TokenClient calls the Entra token endpoint using a pluggable ClientCredential.
//
// The credential answers "which app is calling"; the method called answers "what
// is being requested". Those axes are independent, which is the property this
// prototype exists to test.
type TokenClient struct {
	authorityHost string
	tenantID      string
	clientID      string
	apiVersion    APIVersion
	credential    ClientCredential
	http          *http.Client
}

// TokenClientConfig configures a TokenClient.
type TokenClientConfig struct {
	// AuthorityHost defaults to DefaultAuthorityHost when empty.
	AuthorityHost string
	TenantID      string
	// ClientID is the application being authenticated. Under ModeFIC this is the
	// application the managed identity is federating INTO, not the identity itself.
	ClientID   string
	APIVersion APIVersion
	Credential ClientCredential
}

// NewTokenClient validates cfg and returns a client.
func NewTokenClient(cfg TokenClientConfig) (*TokenClient, error) {
	if cfg.TenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if cfg.Credential == nil {
		return nil, fmt.Errorf("credential is required")
	}
	if !cfg.APIVersion.Valid() {
		return nil, fmt.Errorf("invalid API version %q (want %s or %s)", cfg.APIVersion, APIVersionV1, APIVersionV2)
	}

	authorityHost := cfg.AuthorityHost
	if authorityHost == "" {
		authorityHost = DefaultAuthorityHost
	}

	return &TokenClient{
		authorityHost: strings.TrimRight(authorityHost, "/"),
		tenantID:      cfg.TenantID,
		clientID:      cfg.ClientID,
		apiVersion:    cfg.APIVersion,
		credential:    cfg.Credential,
		http:          &http.Client{Timeout: httpTimeout},
	}, nil
}

// Endpoint returns the token URL this client posts to. It doubles as the
// audience of a certificate-signed client assertion.
func (c *TokenClient) Endpoint() string {
	if c.apiVersion == APIVersionV2 {
		return fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.authorityHost, c.tenantID)
	}
	return fmt.Sprintf("%s/%s/oauth2/token", c.authorityHost, c.tenantID)
}

// Mode reports how this client authenticates itself.
func (c *TokenClient) Mode() CredentialMode { return c.credential.Mode() }

// ClientCredentials requests an app-only token for resource.
//
// This is the grant behind the PDP/CheckAccess path. No user is involved, which
// is why it needs no input token.
func (c *TokenClient) ClientCredentials(ctx context.Context, resource string) (*Token, error) {
	form := url.Values{}
	form.Set(paramGrantType, GrantTypeClientCredentials)
	c.setResource(form, resource)
	return c.exchange(ctx, form)
}

// OnBehalfOf exchanges a delegated user token for another delegated token
// scoped to resource.
//
// userAssertion MUST be a user token whose audience is this client's
// application. An app-only token here is rejected by Entra with
// ErrCodeOBOAppToken, because the OBO grant only works for user principals.
func (c *TokenClient) OnBehalfOf(ctx context.Context, userAssertion, resource string) (*Token, error) {
	if userAssertion == "" {
		return nil, fmt.Errorf("user assertion is required for the on-behalf-of grant")
	}

	form := url.Values{}
	form.Set(paramGrantType, GrantTypeJWTBearer)
	form.Set(paramAssertion, userAssertion)
	form.Set(paramRequestedTokenUse, RequestedTokenUseOnBehalfOf)
	c.setResource(form, resource)
	return c.exchange(ctx, form)
}

// setResource writes the audience parameter in whichever dialect the selected
// endpoint speaks: v1 takes a bare resource, v2 takes a scope.
func (c *TokenClient) setResource(form url.Values, resource string) {
	if c.apiVersion == APIVersionV2 {
		form.Set(paramScope, toDefaultScope(resource))
		return
	}
	form.Set(paramResource, resource)
}

// exchange attaches client authentication and performs the POST.
func (c *TokenClient) exchange(ctx context.Context, form url.Values) (*Token, error) {
	endpoint := c.Endpoint()

	assertion, err := c.credential.Assertion(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	form.Set(paramClientID, c.clientID)
	form.Set(paramClientAssertion, assertion)
	form.Set(paramClientAssertionType, ClientAssertionType)

	return c.post(ctx, endpoint, form)
}

func (c *TokenClient) post(ctx context.Context, endpoint string, form url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request to %s failed: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseTokenError(resp.StatusCode, body)
	}

	return parseTokenResponse(body)
}

// tokenResponse covers both endpoint dialects.
//
// The two endpoints disagree about JSON types as well as field names: the v1
// endpoint returns expires_on AND expires_in as quoted strings, while v2 returns
// expires_in as a number. Both are parsed through flexInt64 so a dialect
// difference cannot masquerade as a credential failure.
type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresOn   flexInt64 `json:"expires_on"`
	ExpiresIn   flexInt64 `json:"expires_in"`
}

// flexInt64 accepts a JSON number or a quoted number.
type flexInt64 int64

// UnmarshalJSON implements json.Unmarshaler.
func (f *flexInt64) UnmarshalJSON(data []byte) error {
	text := strings.Trim(string(data), `"`)
	if text == "" || text == "null" {
		*f = 0
		return nil
	}

	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("expected an integer, got %s: %w", string(data), err)
	}

	*f = flexInt64(value)
	return nil
}

func parseTokenResponse(body []byte) (*Token, error) {
	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("token response contained no access_token")
	}

	return &Token{
		AccessToken: parsed.AccessToken,
		TokenType:   parsed.TokenType,
		ExpiresOn:   resolveExpiry(parsed),
	}, nil
}

func resolveExpiry(parsed tokenResponse) time.Time {
	if parsed.ExpiresOn > 0 {
		return time.Unix(int64(parsed.ExpiresOn), 0)
	}
	if parsed.ExpiresIn > 0 {
		return time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second)
	}
	return time.Time{}
}

// toDefaultScope converts a v1 resource identifier into the v2 scope form.
func toDefaultScope(resource string) string {
	if strings.HasSuffix(resource, "/.default") {
		return resource
	}
	return strings.TrimRight(resource, "/") + "/.default"
}
