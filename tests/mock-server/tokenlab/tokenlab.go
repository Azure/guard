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

// Package tokenlab implements the credential mechanisms Guard's OBO service can
// use to authenticate to Microsoft Entra ID, so they can be compared empirically.
//
// The package separates the two orthogonal axes of an OAuth token request:
//
//   - Client authentication ("which app is calling?") - see ClientCredential.
//     Today production signs a JWT with the AKS first-party app's certificate
//     private key. The alternative under evaluation is a Managed Identity used
//     as a Federated Identity Credential, where IMDS mints the assertion instead.
//
//   - Grant type ("what is being asked for?") - see TokenClient. Either
//     client_credentials (app-only, used for the PDP/CheckAccess path) or
//     on-behalf-of (delegated, used for the Microsoft Graph group-resolution path).
//
// Keeping them separate is what allows the full {grant} x {credential} matrix to
// be exercised, which is the point of the probe binary.
package tokenlab

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const (
	// TokenExchangeAudience is the audience a managed identity token must carry
	// for Entra to accept it as a federated client assertion.
	TokenExchangeAudience = "api://AzureADTokenExchange"

	// ClientAssertionType is the fixed value identifying a JWT client assertion,
	// per RFC 7523. Used for both certificate-signed and federated assertions.
	ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// GrantTypeClientCredentials requests an app-only token.
	GrantTypeClientCredentials = "client_credentials"

	// GrantTypeJWTBearer is the on-behalf-of grant. It exchanges a delegated user
	// token for another delegated token with a different audience.
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// RequestedTokenUseOnBehalfOf is required alongside GrantTypeJWTBearer on the
	// v1 endpoint.
	RequestedTokenUseOnBehalfOf = "on_behalf_of"

	// DefaultAuthorityHost is the public-cloud Entra authority.
	DefaultAuthorityHost = "https://login.microsoftonline.com"

	// httpTimeout bounds every outbound call. IMDS and Entra are both expected to
	// answer in well under a second; a hung request must not wedge the server.
	httpTimeout = 15 * time.Second
)

// APIVersion selects which Entra token endpoint to call.
//
// This is a deliberate variable rather than a constant: production OBO uses the
// v1 endpoint (resource-based), while Microsoft's federated-credential
// documentation shows only v2 (scope-based). Whether a federated assertion is
// accepted may differ between them, so the probe tests both.
type APIVersion string

const (
	// APIVersionV1 is /{tenant}/oauth2/token - takes a `resource` parameter.
	// This is what the production obo service uses.
	APIVersionV1 APIVersion = "v1"

	// APIVersionV2 is /{tenant}/oauth2/v2.0/token - takes a `scope` parameter.
	// This is the endpoint Microsoft documents for federated credentials.
	APIVersionV2 APIVersion = "v2"
)

// Valid reports whether v is a recognised endpoint version.
func (v APIVersion) Valid() bool {
	return v == APIVersionV1 || v == APIVersionV2
}

// fingerprintLength is enough hex to make an accidental collision implausible
// while staying readable in a results table.
const fingerprintLength = 12

// Fingerprint returns a short, stable digest of a credential value.
//
// This exists for one specific experimental reason. The conclusion "Entra
// accepts a federated assertion for client_credentials but refuses it for
// on-behalf-of" is only sound if BOTH requests presented the same assertion.
// Logging the fingerprint of each makes that comparability checkable after the
// fact instead of assumed. It is a digest, never the assertion itself.
func Fingerprint(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:fingerprintLength]
}
