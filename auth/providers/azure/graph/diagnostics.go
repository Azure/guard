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
	stdjson "encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"k8s.io/klog/v2"
)

const diagnosticBodyLimit = 64 * 1024

type dependencyError struct {
	stage                 string
	dependency            string
	reason                string
	responseClass         string
	correlationID         string
	upstreamStatus        int
	aadCode               string
	upstreamCode          string
	upstreamRequestID     string
	upstreamCorrelationID string
	aadTraceID            string
	aadCorrelationID      string
	cause                 error
}

func (failure *dependencyError) fields() []interface{} {
	fields := []interface{}{
		"stage", failure.stage,
		"dependency", failure.dependency,
		"reason", failure.reason,
		"responseClass", failure.responseClass,
		"faultDomain", "unknown",
		"correlationID", failure.correlationID,
	}
	if failure.upstreamStatus != 0 {
		fields = append(fields, "upstreamStatus", failure.upstreamStatus)
	}
	for _, field := range []struct{ name, value string }{
		{"aadCode", failure.aadCode},
		{"upstreamCode", failure.upstreamCode},
		{"upstreamRequestID", failure.upstreamRequestID},
		{"upstreamCorrelationID", failure.upstreamCorrelationID},
		{"aadTraceID", failure.aadTraceID},
		{"aadCorrelationID", failure.aadCorrelationID},
	} {
		if field.value != "" {
			fields = append(fields, field.name, field.value)
		}
	}
	return fields
}

func (failure *dependencyError) Error() string {
	fields := failure.fields()
	parts := make([]string, 0, len(fields)/2)
	for index := 0; index < len(fields); index += 2 {
		parts = append(parts, fmt.Sprintf("%s=%v", fields[index], fields[index+1]))
	}
	return "Azure dependency request failed: " + strings.Join(parts, " ")
}

func (failure *dependencyError) Unwrap() error { return failure.cause }

func addDependencyCorrelation(request *http.Request) {
	correlationID := uuid.New().String()
	request.Header.Set("client-request-id", correlationID)
	request.Header.Set("x-ms-correlation-request-id", correlationID)
}

func dependencyFailure(ctx context.Context, stage, dependency string, request *http.Request, response *http.Response, cause error) error {
	failure := &dependencyError{
		stage:         stage,
		dependency:    dependency,
		reason:        "OBO_FAILED",
		responseClass: "transport_error",
		correlationID: request.Header.Get("client-request-id"),
		cause:         cause,
	}
	if stage == "graph" {
		failure.reason = "GRAPH_FAILED"
	}
	if response != nil {
		failure.upstreamStatus = response.StatusCode
		failure.responseClass = "unexpected_status"
		switch {
		case cause != nil:
			failure.responseClass = "invalid_response"
		case response.StatusCode >= 500:
			failure.responseClass = "server_error"
		case response.StatusCode >= 400:
			failure.responseClass = "client_error"
		}
		failure.upstreamRequestID = diagnosticID(response.Header.Get("request-id"))
		if failure.upstreamRequestID == "" {
			failure.upstreamRequestID = diagnosticID(response.Header.Get("x-ms-request-id"))
		}
		failure.upstreamCorrelationID = diagnosticID(response.Header.Get("x-ms-correlation-request-id"))
		if cause == nil {
			failure.readMetadata(response.Body)
		}
	}
	fields := append([]interface{}{"event", "guard_azure_dependency_failure"}, failure.fields()...)
	klog.FromContext(ctx).Info("Azure dependency request failed", fields...)
	return failure
}

func diagnosticID(value string) string {
	identifier, err := uuid.Parse(value)
	if err != nil {
		return ""
	}
	return identifier.String()
}

func (failure *dependencyError) readMetadata(body io.Reader) {
	data, err := io.ReadAll(io.LimitReader(body, diagnosticBodyLimit+1))
	if err != nil || len(data) > diagnosticBodyLimit {
		return
	}
	var envelope struct {
		Error         stdjson.RawMessage `json:"error"`
		ErrorCodes    []int              `json:"error_codes"`
		TraceID       string             `json:"trace_id"`
		CorrelationID string             `json:"correlation_id"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return
	}
	failure.aadTraceID = diagnosticID(envelope.TraceID)
	failure.aadCorrelationID = diagnosticID(envelope.CorrelationID)
	if failure.upstreamRequestID == "" {
		failure.upstreamRequestID = failure.aadTraceID
	}
	if failure.upstreamCorrelationID == "" {
		failure.upstreamCorrelationID = failure.aadCorrelationID
	}
	var code string
	if err := json.Unmarshal(envelope.Error, &code); err != nil {
		var nested struct {
			Code       string `json:"code"`
			ErrorCodes []int  `json:"error_codes"`
			InnerError struct {
				RequestID string `json:"request-id"`
			} `json:"innerError"`
		}
		if err := json.Unmarshal(envelope.Error, &nested); err == nil {
			code = nested.Code
			envelope.ErrorCodes = append(envelope.ErrorCodes, nested.ErrorCodes...)
			if failure.upstreamRequestID == "" {
				failure.upstreamRequestID = diagnosticID(nested.InnerError.RequestID)
			}
		}
	}
	switch code {
	case "invalid_grant", "invalid_client", "server_error", "temporarily_unavailable", "interaction_required",
		"unauthorized_client", "invalid_request", "invalid_scope", "insufficient_claims",
		"Authorization_RequestDenied", "InvalidAuthenticationToken", "TooManyRequests", "Request_ResourceNotFound",
		"ServiceUnavailable", "InternalServerError", "accessDenied":
		failure.upstreamCode = code
	}
	if strings.HasPrefix(code, "AADSTS") {
		if numeric, err := strconv.Atoi(strings.TrimPrefix(code, "AADSTS")); err == nil {
			envelope.ErrorCodes = append(envelope.ErrorCodes, numeric)
		}
	}
	for _, numeric := range envelope.ErrorCodes {
		if numeric <= 0 || numeric > 999999999 {
			continue
		}
		if failure.aadCode == "" || numeric == 53003 {
			failure.aadCode = fmt.Sprintf("AADSTS%d", numeric)
		}
		if numeric == 53003 && failure.stage == "obo" {
			failure.reason = "OBO_POLICY_BLOCKED"
		}
	}
}
