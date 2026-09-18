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
	"encoding/json"
	"fmt"
	"regexp"
)

// aadstsPattern matches the error code Entra embeds in error_description, e.g.
// "AADSTS70021: No matching federated identity record found ...".
var aadstsPattern = regexp.MustCompile(`AADSTS\d+`)

// Well-known Entra failures for this experiment. Recognising them by name is
// what turns a red result into an answer rather than just an error.
const (
	// ErrCodeNoFederatedRecord means no Federated Identity Credential on the
	// application matched the presented assertion. Usually a wrong subject
	// (must be the managed identity's OBJECT id, not its client id), issuer, or
	// audience - or simply FIC propagation delay right after creation.
	ErrCodeNoFederatedRecord = "AADSTS70021"

	// ErrCodeOBOAppToken means an app-only token was offered as the OBO
	// `assertion`. The OBO grant only works for user principals.
	ErrCodeOBOAppToken = "AADSTS7000113"

	// ErrCodeAudienceMismatch means the assertion's audience did not match what
	// the federated identity credential expects.
	ErrCodeAudienceMismatch = "AADSTS700212"
)

// TokenError is a structured failure from the Entra token endpoint.
type TokenError struct {
	StatusCode    int    `json:"-"`
	Code          string `json:"error"`
	Description   string `json:"error_description"`
	CorrelationID string `json:"correlation_id"`
	AADSTS        string `json:"-"`
	rawBody       string
}

// Error implements error. It leads with the AADSTS code because that is the
// identifier worth searching for and quoting.
func (e *TokenError) Error() string {
	if e.AADSTS != "" {
		return fmt.Sprintf("entra rejected the request: %s (%s, HTTP %d)", e.AADSTS, e.Code, e.StatusCode)
	}
	if e.Code != "" {
		return fmt.Sprintf("entra rejected the request: %s (HTTP %d)", e.Code, e.StatusCode)
	}
	return fmt.Sprintf("entra rejected the request: HTTP %d: %s", e.StatusCode, truncate(e.rawBody, 300))
}

// Detail returns the full description, which usually names the exact
// misconfiguration and is the most useful thing to show an operator.
func (e *TokenError) Detail() string {
	if e.Description != "" {
		return e.Description
	}
	return truncate(e.rawBody, 500)
}

// parseTokenError builds a TokenError from a non-2xx token endpoint response.
// A body that is not the documented JSON shape is preserved verbatim rather
// than discarded, since an unexpected body is itself the diagnostic.
func parseTokenError(statusCode int, body []byte) *TokenError {
	tokenErr := &TokenError{StatusCode: statusCode, rawBody: string(body)}
	// Deliberately ignoring the unmarshal error: a non-JSON body is still
	// reported through rawBody by Error().
	_ = json.Unmarshal(body, tokenErr)
	tokenErr.AADSTS = aadstsPattern.FindString(tokenErr.Description)
	return tokenErr
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
