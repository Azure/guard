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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 - x5t is defined as a SHA-1 thumbprint; not used as a hash primitive
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// newTestSigner builds a signer over a throwaway self-signed certificate.
func newTestSigner(t *testing.T) *CertificateSigner {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tokenlab-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %s", err)
	}

	return NewCertificateSigner("00000000-0000-0000-0000-000000000000", cert, key)
}

// jwtHeader decodes the header segment of a signed assertion.
func jwtHeader(t *testing.T, assertion string) map[string]any {
	t.Helper()

	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d segments, want 3", len(parts))
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %s", err)
	}

	header := map[string]any{}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("unmarshal header: %s", err)
	}
	return header
}

// RFC 7515 section 4.1.7 defines x5t as base64url with no padding. A 20-byte
// SHA-1 sum encodes to exactly one trailing '=' under padded base64url, so a
// padded value is not a cosmetic difference - Entra rejects the assertion.
func TestSignX5TIsUnpaddedBase64URL(t *testing.T) {
	signer := newTestSigner(t)

	assertion, err := signer.Sign("https://login.microsoftonline.com/tenant/oauth2/token")
	if err != nil {
		t.Fatalf("sign: %s", err)
	}

	x5t, ok := jwtHeader(t, assertion)["x5t"].(string)
	if !ok {
		t.Fatal("x5t header is missing or not a string")
	}

	assert.NotContains(t, x5t, "=", "x5t must not carry base64 padding")

	sum := sha1.Sum(signer.certificate.Raw) // #nosec G401 - matches the x5t definition
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), x5t)

	// The padded form is what this previously emitted; assert it is gone rather
	// than only asserting the new value, so a revert fails loudly here.
	assert.NotEqual(t, base64.URLEncoding.EncodeToString(sum[:]), x5t)
}
