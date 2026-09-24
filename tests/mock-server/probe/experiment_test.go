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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func fpResult(name, fingerprint string, outcome Outcome) Result {
	return Result{
		Experiment:  Experiment{Name: name},
		Outcome:     outcome,
		AssertionFP: fingerprint,
	}
}

// The control exists to say whether Q1 and Q2 are comparable. Answering "same"
// with nothing to compare would report the control as established on no
// evidence, which is worse than reporting it as unestablished.
func TestSameAssertionNeedsTwoComparableRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		results []Result
	}{
		{"no rows", nil},
		{"one row", []Result{fpResult("a", "fp-1", OutcomePass)}},
		{"one row, one skipped", []Result{
			fpResult("a", "fp-1", OutcomePass),
			fpResult("b", "", OutcomeSkip),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := SameAssertion(tc.results)
			assert.False(t, ok)
			assert.Contains(t, reason, "comparable")
		})
	}
}

// A non-skipped row with no digest is the row that cannot be shown to be
// comparable, so it must fail the control rather than be passed over.
func TestSameAssertionRejectsMissingFingerprint(t *testing.T) {
	ok, reason := SameAssertion([]Result{
		fpResult("q1", "fp-1", OutcomePass),
		fpResult("q2", "", OutcomeFail),
	})

	assert.False(t, ok)
	assert.Contains(t, reason, "q2")
}

func TestSameAssertionDetectsDifferentAssertions(t *testing.T) {
	ok, reason := SameAssertion([]Result{
		fpResult("q1", "fp-1", OutcomePass),
		fpResult("q2", "fp-2", OutcomePass),
	})

	assert.False(t, ok)
	assert.Contains(t, reason, "different")
}

func TestSameAssertionHoldsWithTwoMatchingRows(t *testing.T) {
	ok, reason := SameAssertion([]Result{
		fpResult("q1", "fp-1", OutcomePass),
		fpResult("q2", "fp-1", OutcomeRefused),
		fpResult("q3", "", OutcomeSkip),
	})

	assert.True(t, ok)
	assert.Empty(t, reason)
}

// A row whose Acquire failed never reaches runVerify. Counting it would claim a
// CheckAccess request was made when none was.
func TestPDPVerdictIgnoresRowsWhereVerifyNeverRan(t *testing.T) {
	verdict := PDPVerdict([]Result{
		{Experiment: Experiment{Name: "acquire failed"}, Outcome: OutcomeFail, VerifyAttempted: false},
	})

	assert.Contains(t, verdict, "NOT ATTEMPTED")
}

func TestPDPVerdictCountsOnlyAttemptedCalls(t *testing.T) {
	verdict := PDPVerdict([]Result{
		{Experiment: Experiment{Name: "ok"}, Outcome: OutcomePass, VerifyAttempted: true, Verified: "Allowed"},
		{Experiment: Experiment{Name: "never ran"}, Outcome: OutcomeFail, VerifyAttempted: false},
	})

	assert.Contains(t, verdict, "YES")
	// One attempt, not two: the failed-acquire row must not inflate the total.
	assert.Contains(t, verdict, "(1/1)")
}

// An infrastructure failure means the credential was never judged, so the
// question stays open rather than being answered "no usable token".
func TestVerdictTreatsAllErrorAsUnanswered(t *testing.T) {
	verdict := Verdict(Q1, []Result{
		{Experiment: Experiment{Name: "a", Question: Q1}, Outcome: OutcomeError},
		{Experiment: Experiment{Name: "b", Question: Q1}, Outcome: OutcomeError},
	})

	assert.True(t, strings.HasPrefix(verdict, "UNANSWERED"), "got %q", verdict)
}
