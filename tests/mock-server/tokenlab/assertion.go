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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// assertionLifetime bounds how long a signed client assertion stays replayable.
//
// Microsoft's guidance is "keep it short - 5-10 minutes after nbf at most".
// Note the production obo service currently uses 24h
// (aks-rp/obo/server/aadsigner/aadsigner.go), which is far longer than
// documented; this prototype follows the guidance instead.
const assertionLifetime = 10 * time.Minute

const (
	pemBlockPrivateKey    = "PRIVATE KEY"
	pemBlockRSAPrivateKey = "RSA PRIVATE KEY"
)

// CertificateSigner mints client assertions signed with an application's own
// certificate private key. This reproduces what the production obo service does.
//
// The assertion is SELF-ISSUED: signing requires no prior token and no network
// call, which is what makes it the bootstrap of the whole credential chain.
type CertificateSigner struct {
	clientID    string
	certificate *x509.Certificate
	key         *rsa.PrivateKey
}

// NewCertificateSigner returns a signer for the given app registration.
func NewCertificateSigner(clientID string, cert *x509.Certificate, key *rsa.PrivateKey) *CertificateSigner {
	return &CertificateSigner{clientID: clientID, certificate: cert, key: key}
}

// NewCertificateSignerFromPEM loads the certificate and private key from PEM
// files. Both may be the same file when it holds a concatenated pair.
func NewCertificateSignerFromPEM(clientID, certFile, keyFile string) (*CertificateSigner, error) {
	cert, err := loadCertificate(certFile)
	if err != nil {
		return nil, err
	}

	key, err := loadRSAPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}

	return NewCertificateSigner(clientID, cert, key), nil
}

// Sign builds and signs the client assertion JWT for the given audience, which
// must be the Entra token endpoint the assertion will be presented to.
func (s *CertificateSigner) Sign(audience string) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	now := time.Now()
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["x5t"] = s.thumbprint()
	// x5c carries the full certificate. Thumbprint-based registration only needs
	// x5t; x5c is what allows Entra to validate by subject name and issuer, which
	// is how first-party certificates rotate without re-registration.
	token.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(s.certificate.Raw)}
	token.Claims = jwt.MapClaims{
		"aud": audience,
		"iss": s.clientID,
		"sub": s.clientID,
		"jti": jti,
		"nbf": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
	}

	signed, err := token.SignedString(s.key)
	if err != nil {
		return "", fmt.Errorf("sign client assertion: %w", err)
	}
	return signed, nil
}

// thumbprint returns the base64url-encoded SHA-1 hash of the certificate, which
// is the format Entra expects in the x5t header.
func (s *CertificateSigner) thumbprint() string {
	sum := sha1.Sum(s.certificate.Raw) // #nosec G401 - required format, not a security primitive
	// RFC 7515 section 4.1.7 requires x5t to be base64url with no padding.
	// base64.URLEncoding always pads, and a 20-byte SHA-1 sum encodes to exactly
	// one trailing '=', which Entra rejects.
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newJTI generates the unique identifier that makes each assertion single-use.
func newJTI() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return base64.URLEncoding.EncodeToString(buf), nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	block, err := firstPEMBlock(path, func(blockType string) bool {
		return blockType == "CERTIFICATE"
	})
	if err != nil {
		return nil, fmt.Errorf("read certificate %s: %w", path, err)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	block, err := firstPEMBlock(path, func(blockType string) bool {
		return blockType == pemBlockPrivateKey || blockType == pemBlockRSAPrivateKey
	})
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}

	return parsePrivateKeyBlock(block, path)
}

func parsePrivateKeyBlock(block *pem.Block, path string) (*rsa.PrivateKey, error) {
	switch block.Type {
	case pemBlockRSAPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 key %s: %w", path, err)
		}
		return key, nil
	case pemBlockPrivateKey:
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 key %s: %w", path, err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key %s is %T, want RSA", path, parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block %q in %s", block.Type, path)
	}
}

// firstPEMBlock scans a PEM file for the first block matching want. Scanning
// rather than taking block 0 lets a single file hold a cert and key together,
// which is how the production S2S secret is packaged.
func firstPEMBlock(path string, want func(string) bool) (*pem.Block, error) {
	data, err := os.ReadFile(path) // #nosec G304 - operator-supplied path by design
	if err != nil {
		return nil, err
	}

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if want(block.Type) {
			return block, nil
		}
	}

	return nil, fmt.Errorf("no matching PEM block found")
}
