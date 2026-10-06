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
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// fakeJWT builds an unsigned JWT carrying payload. The signature is never
// verified by DecodeClaims, so a placeholder is sufficient.
func fakeJWT(payload string) string {
	encode := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(value))
	}
	return strings.Join([]string{encode(`{"alg":"none"}`), encode(payload), "signature"}, ".")
}

func TestDecodeClaims_audienceShapes(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected string
	}{
		{
			name:     "v1 string audience",
			payload:  `{"aud":"https://graph.microsoft.com"}`,
			expected: "https://graph.microsoft.com",
		},
		{
			name:     "v2 array audience",
			payload:  `{"aud":["api://one","api://two"]}`,
			expected: "api://one,api://two",
		},
		{
			name:     "absent audience",
			payload:  `{"iss":"https://sts.windows.net/tid/"}`,
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims, err := DecodeClaims(fakeJWT(test.payload))
			assert.NoError(t, err)
			assert.Equal(t, test.expected, claims.Audience)
		})
	}
}

func TestDecodeClaims_rejectsMalformedTokens(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "not a JWT", token: "opaque-token"},
		{name: "too few segments", token: "header.payload"},
		{name: "payload not base64", token: "header.!!!not-base64!!!.sig"},
		{name: "payload not JSON", token: fakeJWT("not json")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeClaims(test.token)
			assert.Error(t, err)
		})
	}
}

// TestClaims_Delegated pins the classification that the whole experiment turns
// on: an app-only token must never be reported as delegated, and the absence of
// idtyp must not be treated as evidence either way.
func TestClaims_Delegated(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected bool
	}{
		{
			name:     "app-only token from a managed identity",
			payload:  `{"aud":"https://authorization.azure.net","idtyp":"app","oid":"mi-object-id","appid":"mi-client-id"}`,
			expected: false,
		},
		{
			name:     "app-only token without idtyp still not delegated",
			payload:  `{"aud":"https://authorization.azure.net","oid":"mi-object-id","appid":"mi-client-id"}`,
			expected: false,
		},
		{
			name:     "delegated token carries scp",
			payload:  `{"aud":"https://graph.microsoft.com","scp":"User.Read","oid":"user-object-id"}`,
			expected: true,
		},
		{
			name:     "delegated token identified by upn alone",
			payload:  `{"aud":"https://graph.microsoft.com","upn":"someone@example.com"}`,
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims, err := DecodeClaims(fakeJWT(test.payload))
			assert.NoError(t, err)
			assert.Equal(t, test.expected, claims.Delegated())
		})
	}
}

func TestClaims_SummaryReportsMissingClaimsExplicitly(t *testing.T) {
	claims, err := DecodeClaims(fakeJWT(`{"aud":"https://authorization.azure.net","idtyp":"app"}`))
	assert.NoError(t, err)

	summary := claims.Summary()
	assert.Contains(t, summary, "aud=https://authorization.azure.net")
	assert.Contains(t, summary, "idtyp=app")
	assert.Contains(t, summary, "delegated=false")
	// An absent claim must render as <none> rather than an empty string, so the
	// table cannot be misread as "not collected".
	assert.Contains(t, summary, "scp=<none>")
}
