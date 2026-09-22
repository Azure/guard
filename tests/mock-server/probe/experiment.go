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
	"errors"
	"fmt"
	"time"

	"go.kubeguard.dev/guard/tests/mock-server/tokenlab"
)

// Outcome is the verdict for one experiment.
type Outcome string

const (
	OutcomePass Outcome = "PASS"
	OutcomeFail Outcome = "FAIL"
	OutcomeSkip Outcome = "SKIP"
	// OutcomeRefused means Entra issued the token but the resource server
	// actively rejected it - a 401 or 403. This is deliberately distinct from
	// PASS: issuance and usability are different properties, and conflating
	// them is how a harness reports success for a credential that does not
	// actually work.
	OutcomeRefused Outcome = "REFUSED"
	// OutcomeError means the verification call did not complete: a 404, a 5xx,
	// a transport failure, or a body that could not be read or parsed. The
	// token was never judged, so reporting it as REFUSED would blame the
	// credential for an infrastructure fault.
	OutcomeError Outcome = "ERROR"
)

// Question identifies which open question an experiment answers.
type Question string

const (
	// QuestionNone marks a control - it establishes a baseline rather than
	// answering anything open.
	QuestionNone Question = ""

	// Q1: does Entra accept a federated client assertion for client_credentials?
	// Microsoft documents this as supported; we confirm it in this tenant.
	Q1 Question = "Q1"

	// Q2: does Entra accept a federated client assertion for the OBO grant?
	// UNDOCUMENTED - the OBO article covers only secret and certificate.
	Q2 Question = "Q2"
)

// Experiment is one cell of the {grant} x {credential} matrix.
type Experiment struct {
	Name     string
	Question Question
	Grant    string
	Mode     tokenlab.CredentialMode
	Version  tokenlab.APIVersion
	// Purpose explains what a pass or fail here actually tells us.
	Purpose string
	// Skip is non-empty when a prerequisite is missing, which is reported rather
	// than silently omitted - a missing cell would otherwise read as a failure.
	Skip string
	// Acquire performs the token request under test.
	Acquire func(ctx context.Context) (*tokenlab.Token, error)
	// Verify optionally exercises the issued token against the real resource
	// server. Without it an experiment only proves Entra issued something, not
	// that the token is accepted anywhere.
	Verify func(ctx context.Context, token *tokenlab.Token) (string, error)
	// Fingerprint reports a digest of the client assertion the last Acquire
	// presented. Comparing it across rows is what proves two grants were tested
	// with the same credential rather than two different ones.
	Fingerprint func() string
}

// Result records what happened when an Experiment ran.
type Result struct {
	Experiment  Experiment
	Outcome     Outcome
	AADSTS      string
	Detail      string
	Claims      *tokenlab.Claims
	AssertionFP string
	// Verified holds the resource server's answer when Verify ran.
	Verified string
}

// Run executes the experiment and classifies the outcome. A failure is a
// legitimate finding here, not an error to propagate: an AADSTS refusal IS the
// answer to the question being asked.
func (e Experiment) Run(ctx context.Context) Result {
	result := Result{Experiment: e}

	if e.Skip != "" {
		result.Outcome = OutcomeSkip
		result.Detail = e.Skip
		return result
	}

	token, err := e.Acquire(ctx)
	result.AssertionFP = e.assertionFingerprint()
	if err != nil {
		result.Outcome = OutcomeFail
		result.AADSTS, result.Detail = classifyError(err)
		return result
	}

	result.Outcome = OutcomePass
	result.Detail = fmt.Sprintf("expires %s", token.ExpiresOn.UTC().Format(time.RFC3339))

	claims, decodeErr := tokenlab.DecodeClaims(token.AccessToken)
	if decodeErr != nil {
		// A token we cannot decode still counts as issued; record why it could
		// not be inspected rather than discarding the pass.
		result.Detail = fmt.Sprintf("%s (claims undecodable: %s)", result.Detail, decodeErr)
	} else {
		result.Claims = claims
	}

	e.runVerify(ctx, token, &result)

	return result
}

// runVerify exercises the issued token against the real resource server and
// downgrades the outcome when the token is rejected.
//
// Only an authentication or authorization rejection is a refusal. A 404, a
// 5xx, a transport failure or an unparseable body all mean the token was never
// judged, and recording those as REFUSED would report a working credential as
// broken.
func (e Experiment) runVerify(ctx context.Context, token *tokenlab.Token, result *Result) {
	if e.Verify == nil {
		return
	}

	verified, err := e.Verify(ctx, token)
	if err != nil {
		var pdpErr *tokenlab.PDPError
		if errors.As(err, &pdpErr) && pdpErr.TokenRejected() {
			result.Outcome = OutcomeRefused
		} else {
			result.Outcome = OutcomeError
		}
		result.Detail = err.Error()
		return
	}

	result.Verified = verified
}

// classifyError extracts the AADSTS code and a human-readable detail. Entra
// failures carry the code that names the exact misconfiguration; transport
// failures do not, and are reported verbatim.
func classifyError(err error) (aadsts string, detail string) {
	var tokenErr *tokenlab.TokenError
	if errors.As(err, &tokenErr) {
		return tokenErr.AADSTS, tokenErr.Detail()
	}
	return "", err.Error()
}

// assertionFingerprint reads the digest of the assertion just presented, if the
// experiment was wired with a recorder.
func (e Experiment) assertionFingerprint() string {
	if e.Fingerprint == nil {
		return ""
	}
	return e.Fingerprint()
}

// SameAssertion reports whether every non-skipped result in the set presented
// the identical client assertion.
//
// This is the guard on the headline conclusion. If Q1 passes and Q2 fails but
// the two used different assertions, the difference in outcome cannot be
// attributed to the grant type, and the result must not be read as an answer.
func SameAssertion(results []Result) bool {
	var seen string
	for _, result := range results {
		if result.Outcome == OutcomeSkip || result.AssertionFP == "" {
			continue
		}
		if seen == "" {
			seen = result.AssertionFP
			continue
		}
		if seen != result.AssertionFP {
			return false
		}
	}
	return true
}

// Verdict summarises every result for one question into a single answer.
func Verdict(question Question, results []Result) string {
	var ran, passed, refused, errored int
	for _, result := range results {
		if result.Experiment.Question != question || result.Outcome == OutcomeSkip {
			continue
		}
		ran++
		switch result.Outcome {
		case OutcomePass:
			passed++
		case OutcomeRefused:
			refused++
		case OutcomeError:
			errored++
		}
	}

	switch {
	case ran == 0:
		return "UNANSWERED - every experiment for this question was skipped"
	case passed == ran:
		return fmt.Sprintf("YES - all %d experiment(s) succeeded", ran)
	case errored == ran:
		// The credential was never judged, so this says nothing about it.
		return fmt.Sprintf("UNANSWERED - all %d verification call(s) failed before a decision", ran)
	case refused == ran:
		return fmt.Sprintf("PARTIAL - all %d token(s) were issued but the resource server refused them", ran)
	case passed == 0:
		return fmt.Sprintf("NO - none of the %d experiment(s) produced a usable token", ran)
	default:
		return fmt.Sprintf("PARTIAL - %d of %d succeeded; the endpoint version matters", passed, ran)
	}
}

// PDPVerdict answers the question this harness exists for: did a real
// CheckAccess call, made with a token we minted, come back with a decision?
func PDPVerdict(results []Result) string {
	var attempted, verified int
	var evidence string

	for _, result := range results {
		if result.Experiment.Verify == nil || result.Outcome == OutcomeSkip {
			continue
		}
		attempted++
		if result.Verified != "" {
			verified++
			if evidence == "" {
				evidence = result.Verified
			}
		}
	}

	switch {
	case attempted == 0:
		return "NOT ATTEMPTED - no experiment called the PDP endpoint"
	case verified == 0:
		return fmt.Sprintf("NO - %d token(s) reached PDP and none were accepted", attempted)
	default:
		return fmt.Sprintf("YES - PDP accepted the token and returned %s (%d/%d)", evidence, verified, attempted)
	}
}
