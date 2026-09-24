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
	"fmt"
	"sync"
	"time"
)

// assertionExpirySkew retires a cached assertion before Entra would reject it.
const assertionExpirySkew = 5 * time.Minute

// CredentialMode names how the application authenticates itself to Entra.
type CredentialMode string

const (
	// ModeCert signs a client assertion with the application's certificate
	// private key. This is what production does today.
	ModeCert CredentialMode = "cert"

	// ModeFIC uses a managed identity token as the client assertion, which
	// requires a Federated Identity Credential registered on the application.
	// This is the design under evaluation - it removes the private key entirely.
	ModeFIC CredentialMode = "fic"

	// ModeIMDS skips Entra altogether and returns the managed identity's own
	// token for the requested resource. Only viable where the caller identity may
	// be the managed identity rather than the application.
	ModeIMDS CredentialMode = "imds"
)

// ParseCredentialMode validates a mode string.
func ParseCredentialMode(value string) (CredentialMode, error) {
	switch CredentialMode(value) {
	case ModeCert:
		return ModeCert, nil
	case ModeFIC:
		return ModeFIC, nil
	case ModeIMDS:
		return ModeIMDS, nil
	default:
		return "", fmt.Errorf("unknown mode %q (want %s, %s or %s)", value, ModeCert, ModeFIC, ModeIMDS)
	}
}

// ClientCredential proves which application is calling Entra.
//
// Both implementations produce a value for the same `client_assertion` request
// parameter, which is precisely why they are interchangeable from Entra's point
// of view - and why the interface has a single method. They differ only in
// where the signed JWT comes from.
type ClientCredential interface {
	// Mode identifies the implementation, for logging and result tables.
	Mode() CredentialMode

	// Assertion returns a client assertion. For certificates, audience is the
	// Entra token endpoint the assertion will be sent to. For federated
	// credentials the audience is fixed by Entra, so the argument is ignored.
	Assertion(ctx context.Context, audience string) (string, error)
}

// CertificateCredential authenticates with a locally signed assertion.
type CertificateCredential struct {
	signer *CertificateSigner
}

// NewCertificateCredential adapts a CertificateSigner to ClientCredential.
func NewCertificateCredential(signer *CertificateSigner) *CertificateCredential {
	return &CertificateCredential{signer: signer}
}

// Mode implements ClientCredential.
func (c *CertificateCredential) Mode() CredentialMode { return ModeCert }

// Assertion signs a fresh assertion for the target endpoint. No network call is
// made, which is why this path has no bootstrap dependency.
func (c *CertificateCredential) Assertion(_ context.Context, audience string) (string, error) {
	return c.signer.Sign(audience)
}

// FederatedCredential authenticates with a managed identity token, relying on a
// Federated Identity Credential registered on the target application to make
// Entra accept it on that application's behalf.
//
// The token asserts the MANAGED IDENTITY, not the application. The application
// is named separately by client_id on the token request; the FIC is the trust
// link that permits the substitution. A missing or mismatched FIC surfaces as
// AADSTS70021.
//
// The assertion is cached until shortly before it expires. Beyond avoiding
// needless IMDS calls, this is what lets two different grants present the
// IDENTICAL assertion - without it, "client_credentials accepted the assertion
// but on-behalf-of refused it" would be comparing two different tokens and
// could not support that conclusion.
type FederatedCredential struct {
	imds *IMDSClient

	mu     sync.Mutex
	cached *Token
}

// NewFederatedCredential adapts an IMDS client to ClientCredential.
func NewFederatedCredential(imds *IMDSClient) *FederatedCredential {
	return &FederatedCredential{imds: imds}
}

// Mode implements ClientCredential.
func (c *FederatedCredential) Mode() CredentialMode { return ModeFIC }

// Assertion returns a managed identity token stamped with the fixed token
// exchange audience. The audience argument is ignored: Entra requires
// api://AzureADTokenExchange here regardless of which endpoint receives it.
func (c *FederatedCredential) Assertion(ctx context.Context, _ string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if assertion, ok := c.cachedAssertion(); ok {
		return assertion, nil
	}

	token, err := c.imds.Token(ctx, TokenExchangeAudience)
	if err != nil {
		return "", fmt.Errorf("acquire federated assertion from IMDS: %w", err)
	}

	c.cached = token
	return token.AccessToken, nil
}

// cachedAssertion returns the cached assertion when it is still comfortably
// valid. Callers must hold the mutex.
func (c *FederatedCredential) cachedAssertion() (string, bool) {
	if c.cached == nil {
		return "", false
	}
	if time.Now().After(c.cached.ExpiresOn.Add(-assertionExpirySkew)) {
		return "", false
	}
	return c.cached.AccessToken, true
}
