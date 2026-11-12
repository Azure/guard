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

package graph

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/google/uuid"
	"k8s.io/klog/v2"
)

func TestAKSTokenProvider(t *testing.T) {
	const (
		inputAccessToken    = "inputAccessToken"
		oboAccessToken      = "oboAccessToken"
		tenantID            = "tenantID"
		oboResponse         = `{"token_type":"Bearer","expires_on":1732881796,"access_token":"%s"}`
		expectedContentType = "application/json"
		expectedTokneType   = "Bearer"
	)

	t.Run("Upon Success Response", func(t *testing.T) {
		s := startTestServer(t, func(rw http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost {
				t.Errorf("expected http method %s, actual %s", http.MethodPost, req.Method)
			}
			if req.Header.Get("Content-Type") != expectedContentType {
				t.Errorf("expected content type: %s, actual: %s", expectedContentType, req.Header.Get("Content-Type"))
			}
			tokenRequest := struct {
				TenantID    string `json:"tenantID,omitempty"`
				AccessToken string `json:"accessToken,omitempty"`
			}{}

			if err := json.NewDecoder(req.Body).Decode(&tokenRequest); err != nil {
				t.Errorf("unable to decode request: %s", err)
			}
			if tokenRequest.TenantID != tenantID {
				t.Errorf("expected tenant ID: %s, actual: %s", tenantID, tokenRequest.TenantID)
			}
			if tokenRequest.AccessToken != inputAccessToken {
				t.Errorf("expected access token: %s, actual: %s", inputAccessToken, tokenRequest.AccessToken)
			}
			_, _ = rw.Write([]byte(fmt.Sprintf(oboResponse, oboAccessToken)))
		})

		defer stopTestServer(t, s)

		ctx := context.Background()
		r := NewAKSTokenProvider(s.URL, tenantID)
		resp, err := r.Acquire(ctx, inputAccessToken)
		if err != nil {
			t.Fatalf("refresh should not return error: %s", err)
		}

		if resp.Token != oboAccessToken {
			t.Errorf("returned obo token '%s' doesn't match expected '%s'", resp.Token, oboAccessToken)
		}
		if resp.TokenType != expectedTokneType {
			t.Errorf("expected token type: Bearer, actual: %s", resp.TokenType)
		}
	})

	t.Run("Upon Error Response", func(t *testing.T) {
		s := startTestServer(t, func(rw http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPost {
				t.Errorf("expected http method %s, actual %s", http.MethodPost, req.Method)
			}
			if req.Header.Get("Content-Type") != expectedContentType {
				t.Errorf("expected content type: %s, actual: %s", expectedContentType, req.Header.Get("Content-Type"))
			}

			tokenRequest := struct {
				TenantID    string `json:"tenantID,omitempty"`
				AccessToken string `json:"accessToken,omitempty"`
			}{}

			if err := json.NewDecoder(req.Body).Decode(&tokenRequest); err != nil {
				t.Errorf("unable to decode request: %s", err)
			}
			if tokenRequest.TenantID != tenantID {
				t.Errorf("expected tenant ID: %s, actual: %s", tenantID, tokenRequest.TenantID)
			}
			if tokenRequest.AccessToken != inputAccessToken {
				t.Errorf("expected access token: %s, actual: %s", inputAccessToken, tokenRequest.AccessToken)
			}
			rw.WriteHeader(http.StatusBadRequest)
			_, _ = rw.Write([]byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation.","innerError":{"request-id":"6e73da71-96a3-4415-8c6a-a940cb1ba052","date":"2019-12-17T21:57:17"}}}`))
		})

		defer stopTestServer(t, s)

		ctx := context.Background()
		r := NewAKSTokenProvider(s.URL, tenantID)
		resp, err := r.Acquire(ctx, inputAccessToken)
		if err == nil {
			t.Error("refresh should return error")
		}

		if resp.Token != "" {
			t.Errorf("returned obo token '%s' should be empty", resp.Token)
		}
		if resp.TokenType != "" {
			t.Errorf("expected token type: %s should be empty", resp.TokenType)
		}
	})
}

func TestAKSTokenProviderDiagnostics(t *testing.T) {
	const sensitive = "sensitive-upstream-description-and-token"
	testCases := []struct {
		name     string
		status   int
		body     string
		headers  http.Header
		expected []string
		absent   []string
	}{
		{
			name:   "policy block is not customer fault",
			status: http.StatusBadRequest,
			body:   `{"error":"invalid_grant","error_codes":[53003],"error_description":"` + sensitive + `","trace_id":"6e73da71-96a3-4415-8c6a-a940cb1ba052","correlation_id":"6e73da71-96a3-4415-8c6a-a940cb1ba053"}`,
			expected: []string{
				"stage=obo", "dependency=aks_obo", "reason=OBO_POLICY_BLOCKED",
				"responseClass=client_error", "upstreamStatus=400", "aadCode=AADSTS53003",
				"faultDomain=unknown", "upstreamRequestID=6e73da71-96a3-4415-8c6a-a940cb1ba052",
				"upstreamCorrelationID=6e73da71-96a3-4415-8c6a-a940cb1ba053",
			},
		},
		{
			name:   "preserve OBO headers separately from Entra identifiers",
			status: http.StatusBadRequest,
			body:   `{"error_codes":[53003],"trace_id":"6e73da71-96a3-4415-8c6a-a940cb1ba052","correlation_id":"6e73da71-96a3-4415-8c6a-a940cb1ba053"}`,
			headers: http.Header{
				"Request-Id":                  {"6e73da71-96a3-4415-8c6a-a940cb1ba054"},
				"X-Ms-Correlation-Request-Id": {"6e73da71-96a3-4415-8c6a-a940cb1ba055"},
			},
			expected: []string{
				"upstreamRequestID=6e73da71-96a3-4415-8c6a-a940cb1ba054",
				"upstreamCorrelationID=6e73da71-96a3-4415-8c6a-a940cb1ba055",
				"aadTraceID=6e73da71-96a3-4415-8c6a-a940cb1ba052",
				"aadCorrelationID=6e73da71-96a3-4415-8c6a-a940cb1ba053",
			},
		},
		{
			name:   "server response retains policy evidence without assigning ownership",
			status: http.StatusInternalServerError,
			body:   `{"error":"server_error","error_codes":[53003]}`,
			expected: []string{
				"reason=OBO_POLICY_BLOCKED", "responseClass=server_error",
				"upstreamStatus=500", "aadCode=AADSTS53003", "faultDomain=unknown",
			},
		},
		{
			name:     "server failure without aad code",
			status:   http.StatusServiceUnavailable,
			body:     `{"error":"server_error","error_description":"` + sensitive + `"}`,
			expected: []string{"reason=OBO_FAILED", "responseClass=server_error", "upstreamStatus=503"},
			absent:   []string{"aadCode="},
		},
		{
			name:     "do not classify code from free text",
			status:   http.StatusBadRequest,
			body:     `{"error_description":"AADSTS53003 ` + sensitive + `"}`,
			expected: []string{"reason=OBO_FAILED", "responseClass=client_error"},
			absent:   []string{"OBO_POLICY_BLOCKED", "aadCode="},
		},
		{
			name:     "malformed body",
			status:   http.StatusBadGateway,
			body:     sensitive + `<html>bad gateway</html>`,
			expected: []string{"reason=OBO_FAILED", "upstreamStatus=502"},
		},
		{
			name:     "oversized body",
			status:   http.StatusBadRequest,
			body:     `{"padding":"` + strings.Repeat("x", 65536) + `","error_codes":[53003]}`,
			expected: []string{"reason=OBO_FAILED", "responseClass=client_error"},
			absent:   []string{"OBO_POLICY_BLOCKED", "aadCode="},
		},
		{
			name:     "malformed successful response",
			status:   http.StatusOK,
			body:     sensitive,
			expected: []string{"reason=OBO_FAILED", "responseClass=invalid_response", "upstreamStatus=200"},
		},
		{
			name:     "unsafe upstream identifiers",
			status:   http.StatusBadRequest,
			body:     `{"trace_id":"` + sensitive + `","correlation_id":"` + sensitive + `"}`,
			expected: []string{"reason=OBO_FAILED", "faultDomain=unknown"},
			absent:   []string{"upstreamRequestID=", "upstreamCorrelationID="},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			requestIDs := make(chan string, 1)
			server := startTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
				requestIDs <- request.Header.Get("x-ms-correlation-request-id")
				for name, values := range testCase.headers {
					writer.Header()[name] = values
				}
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(testCase.body))
			})
			defer stopTestServer(t, server)
			provider := NewAKSTokenProvider(server.URL, "tenant")
			var logs strings.Builder
			logger := funcr.New(func(prefix, args string) {
				logs.WriteString(prefix)
				logs.WriteString(args)
			}, funcr.Options{Verbosity: 10}).WithValues("requestID", "guard-request")
			ctx := klog.NewContext(context.Background(), logger)
			_, err := provider.Acquire(ctx, sensitive)
			if err == nil {
				t.Fatal("expected acquisition failure")
			}
			correlationID := <-requestIDs
			if _, parseErr := uuid.Parse(correlationID); parseErr != nil {
				t.Fatalf("expected outgoing correlation UUID: %v", parseErr)
			}
			message := err.Error()
			if strings.Contains(message, "guard_azure_dependency_failure") {
				t.Error("returned errors must not duplicate the structured event marker")
			}
			if !strings.Contains(message, "correlationID="+correlationID) {
				t.Error("diagnostic did not retain the outgoing correlation ID")
			}
			if strings.Count(logs.String(), "guard_azure_dependency_failure") != 1 || !strings.Contains(logs.String(), "guard-request") {
				t.Errorf("expected one structured event with parent request ID: %s", logs.String())
			}
			for _, expected := range testCase.expected {
				if !strings.Contains(message, expected) {
					t.Errorf("expected %q in diagnostic: %.1000s", expected, message)
				}
			}
			for _, absent := range append(testCase.absent, sensitive, "faultDomain=customer", "faultDomain=server") {
				if strings.Contains(message, absent) || strings.Contains(logs.String(), absent) {
					t.Errorf("unexpected %q in diagnostic: %.1000s", absent, message)
				}
			}
		})
	}
}

func TestAKSTokenProviderTransportDiagnostics(t *testing.T) {
	const sensitive = "sensitive-request-path-and-token"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := NewAKSTokenProvider("https://example.invalid/"+sensitive, "tenant")
	_, err := provider.Acquire(ctx, sensitive)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected original cancellation to remain discoverable: %v", err)
	}
	if !strings.Contains(err.Error(), "responseClass=transport_error") || strings.Contains(err.Error(), sensitive) {
		t.Errorf("expected safe transport diagnostic: %v", err)
	}
}
