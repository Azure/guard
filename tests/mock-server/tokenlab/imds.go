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
	"time"
)

const (
	// DefaultIMDSEndpoint is the Azure Instance Metadata Service token endpoint.
	// Reachable from any pod on an Azure VM unless egress is explicitly blocked.
	DefaultIMDSEndpoint = "http://169.254.169.254/metadata/identity/oauth2/token"

	imdsAPIVersion = "2018-02-01"
)

// IMDSClient acquires managed identity tokens from the Instance Metadata Service.
//
// A pod calling IMDS receives tokens for identities assigned to the underlying
// node VMSS. ClientID selects which of those identities to use; it must name an
// identity actually assigned to the VMSS or IMDS returns an error.
type IMDSClient struct {
	endpoint string
	clientID string
	http     *http.Client
}

// NewIMDSClient returns a client for the given managed identity. An empty
// endpoint falls back to DefaultIMDSEndpoint.
func NewIMDSClient(endpoint, clientID string) *IMDSClient {
	if endpoint == "" {
		endpoint = DefaultIMDSEndpoint
	}
	return &IMDSClient{
		endpoint: endpoint,
		clientID: clientID,
		http:     &http.Client{Timeout: httpTimeout},
	}
}

// imdsResponse is the IMDS token payload. Numeric fields are strings on the
// wire, which is why expires_on needs an explicit parse.
type imdsResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   string `json:"expires_on"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
}

// Token requests a managed identity token for the given resource (audience).
//
// The returned token is always app-only: it identifies the managed identity's
// service principal and carries no user claims, regardless of resource.
func (c *IMDSClient) Token(ctx context.Context, resource string) (*Token, error) {
	endpoint, err := c.buildURL(resource)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create IMDS request: %w", err)
	}
	// Required by IMDS as an SSRF mitigation; without it the request is rejected.
	req.Header.Set("Metadata", "true")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("IMDS request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IMDS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IMDS returned %d: %s", resp.StatusCode, string(body))
	}

	return parseIMDSResponse(body)
}

// buildURL assembles the IMDS query. resource becomes the `aud` claim of the
// issued token.
func (c *IMDSClient) buildURL(resource string) (string, error) {
	if resource == "" {
		return "", fmt.Errorf("resource must not be empty")
	}

	parsed, err := url.Parse(c.endpoint)
	if err != nil {
		return "", fmt.Errorf("parse IMDS endpoint %q: %w", c.endpoint, err)
	}

	query := parsed.Query()
	query.Set("api-version", imdsAPIVersion)
	query.Set("resource", resource)
	if c.clientID != "" {
		query.Set("client_id", c.clientID)
	}
	parsed.RawQuery = query.Encode()

	return parsed.String(), nil
}

func parseIMDSResponse(body []byte) (*Token, error) {
	var parsed imdsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode IMDS response: %w", err)
	}

	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("IMDS returned an empty access_token")
	}

	expiresOn, err := strconv.ParseInt(parsed.ExpiresOn, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse IMDS expires_on %q: %w", parsed.ExpiresOn, err)
	}

	return &Token{
		AccessToken: parsed.AccessToken,
		TokenType:   parsed.TokenType,
		ExpiresOn:   time.Unix(expiresOn, 0),
	}, nil
}
