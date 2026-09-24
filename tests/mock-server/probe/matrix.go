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

package main

import (
	"context"
	"fmt"

	"go.kubeguard.dev/guard/tests/mock-server/tokenlab"
)

const (
	skipNoCertificate = "no --cert-file supplied"
	skipNoUserToken   = "no --user-assertion-file supplied"
)

// pdpVerifier returns a Verify function that spends the issued token on a real
// CheckAccess call, or nil when PDP verification was not configured.
//
// A decision of either allowed or denied counts as success: the objective is to
// prove PDP authenticated the caller and answered, not to obtain a particular
// verdict.
func pdpVerifier(cfg config) func(context.Context, *tokenlab.Token) (string, error) {
	if cfg.pdpEndpoint == "" || cfg.checkResourceID == "" || cfg.checkSubjectOID == "" {
		return nil
	}

	client := tokenlab.NewPDPClient(cfg.pdpEndpoint)
	request := tokenlab.NewAccessRequest(cfg.checkSubjectOID, cfg.checkResourceID, cfg.checkAction)

	return func(ctx context.Context, token *tokenlab.Token) (string, error) {
		decision, err := client.CheckAccess(ctx, token.AccessToken, request)
		if err != nil {
			return "", err
		}
		return tokenlab.SummarizeDecisions(decision), nil
	}
}

// buildExperiments assembles the full matrix.
//
// Ordering is deliberate: the controls run first so that a broken environment
// is obvious before any conclusion is drawn from the federated cells.
func buildExperiments(cfg config) ([]Experiment, error) {
	imds := tokenlab.NewIMDSClient(cfg.imdsEndpoint, cfg.miClientID)

	userAssertion, err := cfg.loadUserAssertion()
	if err != nil {
		return nil, err
	}

	certSkip, certCredential, err := buildCertificateCredential(cfg)
	if err != nil {
		return nil, err
	}

	// Both credentials are wrapped so every row can report which assertion it
	// presented. See SameAssertion for why that matters to the conclusion.
	certRecorder := newRecordingCredential(certCredential)
	ficRecorder := newRecordingCredential(tokenlab.NewFederatedCredential(imds))

	experiments := []Experiment{directIMDSExperiment(cfg, imds)}

	certCases, err := credentialExperiments(cfg, credentialCase{
		label:      "cert",
		credential: certRecorder,
		skip:       certSkip,
		question:   QuestionNone,
		purpose:    "baseline - reproduces what production does today",
		versions:   []tokenlab.APIVersion{tokenlab.APIVersionV1},
	}, userAssertion)
	if err != nil {
		return nil, err
	}

	ficCases, err := credentialExperiments(cfg, credentialCase{
		label:       "fic",
		credential:  ficRecorder,
		question:    Q1,
		oboQuestion: Q2,
		purpose:     "the design under evaluation - no private key involved",
		// Both endpoint dialects are tried: production uses v1, but Microsoft
		// documents federated credentials only against v2, and acceptance may
		// differ between them.
		versions: []tokenlab.APIVersion{tokenlab.APIVersionV1, tokenlab.APIVersionV2},
	}, userAssertion)
	if err != nil {
		return nil, err
	}

	experiments = append(experiments, certCases...)
	experiments = append(experiments, ficCases...)
	return experiments, nil
}

// credentialCase describes one credential column of the matrix.
type credentialCase struct {
	label      string
	credential *recordingCredential
	skip       string
	question   Question
	// oboQuestion allows the delegated row to answer a different question than
	// the app-only row, which is exactly the situation for federated credentials.
	oboQuestion Question
	purpose     string
	versions    []tokenlab.APIVersion
}

// recordingCredential wraps a ClientCredential and remembers a digest of the
// last assertion it produced, so each result can report which credential value
// was actually presented.
type recordingCredential struct {
	inner       tokenlab.ClientCredential
	fingerprint string
}

func newRecordingCredential(inner tokenlab.ClientCredential) *recordingCredential {
	return &recordingCredential{inner: inner}
}

func (r *recordingCredential) Mode() tokenlab.CredentialMode { return r.inner.Mode() }

func (r *recordingCredential) Assertion(ctx context.Context, audience string) (string, error) {
	assertion, err := r.inner.Assertion(ctx, audience)
	r.fingerprint = tokenlab.Fingerprint(assertion)
	return assertion, err
}

// Fingerprint reports the digest of the most recently produced assertion.
func (r *recordingCredential) Fingerprint() string { return r.fingerprint }

// credentialExperiments produces the app-only and delegated rows for one
// credential, across every endpoint version requested.
func credentialExperiments(cfg config, testCase credentialCase, userAssertion string) ([]Experiment, error) {
	experiments := make([]Experiment, 0, len(testCase.versions)*2)

	for _, version := range testCase.versions {
		client, err := newTokenClient(cfg, testCase.credential, version)
		if err != nil {
			return nil, err
		}

		experiments = append(experiments,
			clientCredentialsExperiment(cfg, testCase, version, client),
			onBehalfOfExperiment(cfg, testCase, version, client, userAssertion),
		)
	}

	return experiments, nil
}

func clientCredentialsExperiment(cfg config, testCase credentialCase, version tokenlab.APIVersion, client *tokenlab.TokenClient) Experiment {
	return Experiment{
		Name:     fmt.Sprintf("%s/client_credentials/%s", testCase.label, version),
		Question: testCase.question,
		Grant:    grantClientCredentials,
		Mode:     testCase.credential.Mode(),
		Version:  version,
		Purpose:  testCase.purpose,
		Skip:     testCase.skip,
		Acquire: func(ctx context.Context) (*tokenlab.Token, error) {
			return client.ClientCredentials(ctx, cfg.pdpResource)
		},
		// The app-only token is the one PDP consumes, so this is where the
		// end-to-end claim is actually established.
		Verify:      pdpVerifier(cfg),
		Fingerprint: testCase.credential.Fingerprint,
	}
}

func onBehalfOfExperiment(cfg config, testCase credentialCase, version tokenlab.APIVersion, client *tokenlab.TokenClient, userAssertion string) Experiment {
	question := testCase.question
	if testCase.oboQuestion != QuestionNone {
		question = testCase.oboQuestion
	}

	skip := testCase.skip
	if skip == "" && userAssertion == "" {
		skip = skipNoUserToken
	}

	return Experiment{
		Name:     fmt.Sprintf("%s/on-behalf-of/%s", testCase.label, version),
		Question: question,
		Grant:    grantOnBehalfOf,
		Mode:     testCase.credential.Mode(),
		Version:  version,
		Purpose:  testCase.purpose,
		Skip:     skip,
		Acquire: func(ctx context.Context) (*tokenlab.Token, error) {
			return client.OnBehalfOf(ctx, userAssertion, cfg.oboResource)
		},
		Fingerprint: testCase.credential.Fingerprint,
	}
}

// directIMDSExperiment is the control for the no-Entra path: IMDS mints a token
// for the PDP audience directly. A failure here means IMDS or the identity
// assignment is broken, and every other result should be distrusted.
//
// It also carries the PDP verification, which makes it the shortest complete
// path to the goal: managed identity -> PDP, with no Entra exchange at all.
func directIMDSExperiment(cfg config, imds *tokenlab.IMDSClient) Experiment {
	return Experiment{
		Name:     "imds/direct",
		Question: QuestionNone,
		Grant:    grantNone,
		Mode:     tokenlab.ModeIMDS,
		Purpose:  "control - proves IMDS reachability, the identity assignment, and PDP access",
		Acquire: func(ctx context.Context) (*tokenlab.Token, error) {
			return imds.Token(ctx, cfg.pdpResource)
		},
		Verify: pdpVerifier(cfg),
	}
}

// buildCertificateCredential loads the certificate when one was supplied. A
// missing certificate is not an error: it downgrades the baseline rows to SKIP.
func buildCertificateCredential(cfg config) (skip string, credential tokenlab.ClientCredential, err error) {
	if cfg.certFile == "" {
		// A non-nil credential is still required so the experiment rows can be
		// constructed; it is never invoked because Skip is set.
		return skipNoCertificate, unavailableCredential{}, nil
	}

	keyFile := cfg.keyFile
	if keyFile == "" {
		keyFile = cfg.certFile
	}

	signer, err := tokenlab.NewCertificateSignerFromPEM(cfg.appClientID, cfg.certFile, keyFile)
	if err != nil {
		return "", nil, err
	}
	return "", tokenlab.NewCertificateCredential(signer), nil
}

func newTokenClient(cfg config, credential tokenlab.ClientCredential, version tokenlab.APIVersion) (*tokenlab.TokenClient, error) {
	return tokenlab.NewTokenClient(tokenlab.TokenClientConfig{
		AuthorityHost: cfg.authorityHost,
		TenantID:      cfg.tenantID,
		ClientID:      cfg.appClientID,
		APIVersion:    version,
		Credential:    credential,
	})
}

// unavailableCredential stands in for a credential whose prerequisites are
// missing. Any call is a programming error, so it fails loudly rather than
// silently returning an empty assertion that would produce a confusing AADSTS.
type unavailableCredential struct{}

func (unavailableCredential) Mode() tokenlab.CredentialMode { return tokenlab.ModeCert }

func (unavailableCredential) Assertion(context.Context, string) (string, error) {
	return "", fmt.Errorf("credential unavailable: this experiment should have been skipped")
}
