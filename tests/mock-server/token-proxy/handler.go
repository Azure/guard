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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"go.kubeguard.dev/guard/tests/mock-server/tokenlab"
)

// Guard's two OBO endpoints. They are NOT interchangeable: /token performs a
// delegated exchange of the caller's user token, while /authztoken performs an
// app-only request with no user involved. Serving one with the other's result
// produces a plausible-looking token that is wrong in a way nothing downstream
// detects, so dispatch is explicit.
const (
	pathSuffixToken      = "/token"
	pathSuffixAuthzToken = "/authztoken"
)

// oboRequest is the body Guard sends. Field names must match
// auth/providers/azure/graph/aks_tokenprovider.go exactly.
type oboRequest struct {
	TenantID    string `json:"tenantID,omitempty"`
	AccessToken string `json:"accessToken,omitempty"`
	Resource    string `json:"resource,omitempty"`
}

// oboResponse is the body Guard expects. expires_on is Unix seconds; Guard
// converts it with time.Unix and treats a zero value as already expired.
type oboResponse struct {
	TokenType string `json:"token_type"`
	Token     string `json:"access_token"`
	ExpiresOn int64  `json:"expires_on"`
}

// tokenIssuer produces tokens for one grant.
type tokenIssuer interface {
	ClientCredentials(ctx context.Context, resource string) (*tokenlab.Token, error)
	OnBehalfOf(ctx context.Context, userAssertion, resource string) (*tokenlab.Token, error)
}

// Server answers Guard's OBO protocol using whichever credential mode was
// configured, so Guard itself needs no modification to test a new mechanism.
type Server struct {
	mode          tokenlab.CredentialMode
	issuer        tokenIssuer
	imds          *tokenlab.IMDSClient
	oboResource   string
	authzResource string
	// passthroughErrors returns Entra's response body and status to Guard rather
	// than a generic 500. Guard surfaces that verbatim in its error, so the exact
	// AADSTS code reaches kubectl and the Guard logs.
	passthroughErrors bool
	dumpClaims        bool

	issued atomic.Int64
	failed atomic.Int64
}

// ServeToken handles the delegated exchange behind --azure.aks-token-url.
func (s *Server) ServeToken(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decode(w, r)
	if !ok {
		return
	}

	if req.AccessToken == "" {
		// Guard always sends the user token here. An empty one means the request
		// was misrouted, which would otherwise be masked by returning an app-only
		// token that looks superficially valid.
		s.fail(w, r, http.StatusBadRequest,
			errors.New("no accessToken in body: /token performs a delegated exchange and requires the caller's user token"))
		return
	}

	resource := firstNonEmpty(req.Resource, s.oboResource)

	if s.mode == tokenlab.ModeIMDS {
		s.fail(w, r, http.StatusNotImplemented,
			errors.New("mode=imds cannot serve /token: a managed identity token carries no user identity, so it cannot stand in for a delegated token"))
		return
	}

	token, err := s.issuer.OnBehalfOf(r.Context(), req.AccessToken, resource)
	s.respond(w, "token", "on-behalf-of", resource, token, err)
}

// ServeAuthzToken handles the app-only request behind
// --azure.aks-authz-token-url. Guard sends an empty accessToken here.
func (s *Server) ServeAuthzToken(w http.ResponseWriter, r *http.Request) {
	req, ok := s.decode(w, r)
	if !ok {
		return
	}

	resource := firstNonEmpty(req.Resource, s.authzResource)

	if s.mode == tokenlab.ModeIMDS {
		token, err := s.imds.Token(r.Context(), resource)
		s.respond(w, "authztoken", "imds-direct", resource, token, err)
		return
	}

	token, err := s.issuer.ClientCredentials(r.Context(), resource)
	s.respond(w, "authztoken", "client_credentials", resource, token, err)
}

// Route dispatches by path suffix so a single handler can be registered for the
// /v1/ prefix, which is what Guard's templated URLs produce.
func (s *Server) Route(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, pathSuffixAuthzToken):
		s.ServeAuthzToken(w, r)
	case strings.HasSuffix(r.URL.Path, pathSuffixToken):
		s.ServeToken(w, r)
	default:
		s.fail(w, r, http.StatusNotFound,
			fmt.Errorf("unknown path %q: expected a suffix of %s or %s", r.URL.Path, pathSuffixToken, pathSuffixAuthzToken))
	}
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request) (oboRequest, bool) {
	var req oboRequest

	if r.Method != http.MethodPost {
		s.fail(w, r, http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed", r.Method))
		return req, false
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.fail(w, r, http.StatusBadRequest, fmt.Errorf("decode request body: %w", err))
		return req, false
	}

	return req, true
}

// respond writes the token or the failure, logging enough to reconstruct what
// was asked for and what came back.
func (s *Server) respond(w http.ResponseWriter, endpoint, grant, resource string, token *tokenlab.Token, err error) {
	if err != nil {
		s.failExchange(w, endpoint, grant, resource, err)
		return
	}

	count := s.issued.Add(1)
	// Full timestamp, not just time-of-day: an app-only PDP token lives ~24h, so
	// a time-only format makes a valid expiry look like "now".
	log.Printf("[%s] grant=%s mode=%s resource=%s status=issued expires=%s total_issued=%d",
		endpoint, grant, s.mode, resource, token.ExpiresOn.UTC().Format(time.RFC3339), count)

	if s.dumpClaims {
		s.logClaims(endpoint, token)
	}

	body := oboResponse{
		TokenType: defaultString(token.TokenType, "Bearer"),
		Token:     token.AccessToken,
		ExpiresOn: token.ExpiresOn.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	if encodeErr := json.NewEncoder(w).Encode(body); encodeErr != nil {
		log.Printf("[%s] status=error detail=%q", endpoint, encodeErr.Error())
	}
}

// failExchange reports an Entra rejection. The AADSTS code is logged and, when
// passthrough is enabled, returned to Guard so it appears in kubectl output.
func (s *Server) failExchange(w http.ResponseWriter, endpoint, grant, resource string, err error) {
	count := s.failed.Add(1)

	var tokenErr *tokenlab.TokenError
	if errors.As(err, &tokenErr) {
		log.Printf("[%s] grant=%s mode=%s resource=%s status=rejected aadsts=%s detail=%q total_failed=%d",
			endpoint, grant, s.mode, resource, orUnknown(tokenErr.AADSTS), tokenErr.Detail(), count)

		if s.passthroughErrors {
			s.writeError(w, tokenErr.StatusCode, tokenErr.Detail())
			return
		}
		s.writeError(w, http.StatusInternalServerError, tokenErr.Error())
		return
	}

	log.Printf("[%s] grant=%s mode=%s resource=%s status=error detail=%q total_failed=%d",
		endpoint, grant, s.mode, resource, err.Error(), count)
	s.writeError(w, http.StatusInternalServerError, err.Error())
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, err error) {
	s.failed.Add(1)
	log.Printf("[request] path=%s status=%d detail=%q", r.URL.Path, status, err.Error())
	s.writeError(w, status, err.Error())
}

func (s *Server) writeError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": detail}); err != nil {
		log.Printf("[response] status=error detail=%q", err.Error())
	}
}

// logClaims records what the issued token actually contains, which is how a
// silently-wrong grant is caught: an app-only token on the delegated endpoint
// shows delegated=false.
func (s *Server) logClaims(endpoint string, token *tokenlab.Token) {
	claims, err := tokenlab.DecodeClaims(token.AccessToken)
	if err != nil {
		log.Printf("[%s] claims=undecodable detail=%q", endpoint, err.Error())
		return
	}
	log.Printf("[%s] claims %s", endpoint, claims.Summary())
}

// Stats reports issuance counters for the metrics endpoint.
func (s *Server) Stats() map[string]any {
	return map[string]any{
		"mode":          string(s.mode),
		"tokens_issued": s.issued.Load(),
		"tokens_failed": s.failed.Load(),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
