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
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Token is an issued access token and the metadata needed to reason about it.
type Token struct {
	AccessToken string
	TokenType   string
	ExpiresOn   time.Time
}

// Claims holds the subset of JWT claims that distinguish an app-only token from
// a delegated one. Every field is optional: Entra omits claims that have no
// value, and several are emitted only when the resource opts into them.
type Claims struct {
	Audience   string `json:"-"`
	Issuer     string `json:"iss,omitempty"`
	Subject    string `json:"sub,omitempty"`
	TenantID   string `json:"tid,omitempty"`
	ObjectID   string `json:"oid,omitempty"`
	AppID      string `json:"appid,omitempty"`
	AuthZParty string `json:"azp,omitempty"`
	// IDType is "app" on an app-only token. Its ABSENCE proves nothing: it is an
	// optional claim the resource must opt into, so a delegated token and an
	// unconfigured resource look identical here.
	IDType string `json:"idtyp,omitempty"`
	// Scope is present only on delegated tokens.
	Scope string `json:"scp,omitempty"`
	// Roles carries application permissions. App-only tokens may legitimately
	// have none, so an empty value does not imply a delegated token.
	Roles             []string `json:"roles,omitempty"`
	UPN               string   `json:"upn,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	ExpiresAt         int64    `json:"exp,omitempty"`
}

// rawClaims mirrors Claims but types `aud` as json.RawMessage, because Entra
// emits it as a string on v1 tokens and as an array on some v2 tokens.
type rawClaims struct {
	Claims
	Audience json.RawMessage `json:"aud,omitempty"`
}

// Delegated reports whether the token carries an end-user identity.
//
// This is a best-effort classification for diagnostics only. It deliberately
// keys on `scp`, which Microsoft documents as "only included for user tokens",
// rather than on the absence of `idtyp`.
func (c *Claims) Delegated() bool {
	return c.Scope != "" || c.UPN != "" || c.PreferredUsername != ""
}

// Summary renders the claims that matter when comparing credential modes, in a
// single line suitable for logs and the probe results table.
func (c *Claims) Summary() string {
	fields := []string{
		fmt.Sprintf("aud=%s", orNone(c.Audience)),
		fmt.Sprintf("idtyp=%s", orNone(c.IDType)),
		fmt.Sprintf("appid=%s", orNone(firstNonEmpty(c.AppID, c.AuthZParty))),
		fmt.Sprintf("oid=%s", orNone(c.ObjectID)),
		fmt.Sprintf("scp=%s", orNone(c.Scope)),
		fmt.Sprintf("roles=%s", orNone(strings.Join(c.Roles, "|"))),
		fmt.Sprintf("delegated=%t", c.Delegated()),
	}
	return strings.Join(fields, " ")
}

// DecodeClaims extracts the claims from a JWT payload WITHOUT verifying the
// signature. This is a diagnostic helper for inspecting tokens we just received
// over TLS from Entra; it must never be used to make a trust decision.
func DecodeClaims(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 segments, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var raw rawClaims
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}

	claims := raw.Claims
	claims.Audience = decodeAudience(raw.Audience)
	return &claims, nil
}

// decodeAudience normalises `aud`, which may be a bare string or an array.
func decodeAudience(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single
	}

	var multiple []string
	if err := json.Unmarshal(raw, &multiple); err == nil {
		return strings.Join(multiple, ",")
	}

	return string(raw)
}

func orNone(value string) string {
	if value == "" {
		return "<none>"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
