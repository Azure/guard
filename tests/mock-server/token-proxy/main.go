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

// token-proxy stands in for the AKS OBO service so Guard can be pointed at a
// different credential mechanism without modifying Guard.
//
// It speaks the same wire protocol as the production obo service, so it is a
// drop-in replacement:
//
//	Production:  Guard -> obo (certificate-signed assertion) -> Entra -> Graph/PDP
//	Prototype:   Guard -> token-proxy (--mode)               -> Entra -> Graph/PDP
//
// Modes:
//
//	cert  sign the client assertion with a certificate (reproduces production)
//	fic   use a managed identity token as the client assertion (the design under test)
//	imds  return the managed identity's own token; app-only paths only
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.kubeguard.dev/guard/tests/mock-server/tokenlab"
)

const (
	defaultPort = 8080
	// defaultAuthzResource mirrors the production obo default, which falls back
	// to the ARM endpoint when the caller does not name a resource.
	defaultAuthzResource = "https://management.azure.com"
	defaultOBOResource   = "https://graph.microsoft.com"

	readTimeout     = 15 * time.Second
	writeTimeout    = 30 * time.Second
	shutdownTimeout = 5 * time.Second
)

type options struct {
	port              int
	mode              string
	apiVersion        string
	tenantID          string
	appClientID       string
	miClientID        string
	certFile          string
	keyFile           string
	oboResource       string
	authzResource     string
	imdsEndpoint      string
	authorityHost     string
	dumpClaims        bool
	passthroughErrors bool
}

func main() {
	opts := parseFlags()

	server, err := buildServer(opts)
	if err != nil {
		log.Fatalf("configuration error: %s", err)
	}

	mux := http.NewServeMux()
	// Guard's URLs are /v1/<ccpid>/token and /v1/<ccpid>/authztoken; the handler
	// dispatches on the suffix because the ccpid segment is arbitrary.
	mux.HandleFunc("/v1/", server.Route)
	// Legacy path used by older Guard builds; it is the app-only exchange.
	mux.HandleFunc("/authz/token", server.ServeAuthzToken)
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/metrics", handleMetrics(server))

	listen := fmt.Sprintf(":%d", opts.port)
	log.Printf("token-proxy listening on %s mode=%s endpoint=%s identity=%s application=%s",
		listen, opts.mode, opts.apiVersion, opts.miClientID, opts.appClientID)
	log.Printf("routes: /v1/<ccpid>/token (delegated), /v1/<ccpid>/authztoken (app-only), /health, /metrics")

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
	}

	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("server stopped: %s", err)
	}
}

func parseFlags() options {
	var opts options
	var legacyClientID string

	flag.IntVar(&opts.port, "port", defaultPort, "HTTP listen port")
	flag.StringVar(&opts.mode, "mode", string(tokenlab.ModeFIC), "credential mode: cert, fic or imds")
	flag.StringVar(&opts.apiVersion, "endpoint", string(tokenlab.APIVersionV1), "Entra token endpoint version: v1 (production parity) or v2")
	flag.StringVar(&opts.tenantID, "tenant-id", "", "Entra tenant ID (required for cert and fic modes)")
	flag.StringVar(&opts.appClientID, "app-client-id", "", "client ID of the application being authenticated (required for cert and fic modes)")
	flag.StringVar(&opts.miClientID, "mi-client-id", "", "client ID of the managed identity used via IMDS")
	flag.StringVar(&legacyClientID, "client-id", "", "deprecated alias for --mi-client-id")
	flag.StringVar(&opts.certFile, "cert-file", "", "PEM certificate (cert mode)")
	flag.StringVar(&opts.keyFile, "key-file", "", "PEM private key (cert mode; defaults to --cert-file)")
	flag.StringVar(&opts.oboResource, "obo-resource", defaultOBOResource, "default downstream resource for the delegated endpoint")
	flag.StringVar(&opts.authzResource, "authz-resource", defaultAuthzResource, "fallback resource for the app-only endpoint when the request omits one")
	flag.StringVar(&opts.imdsEndpoint, "imds-endpoint", "", "override the IMDS token endpoint (testing only)")
	flag.StringVar(&opts.authorityHost, "authority-host", "", "override the Entra authority host (sovereign clouds)")
	flag.BoolVar(&opts.dumpClaims, "dump-claims", true, "log the decoded claims of every issued token")
	flag.BoolVar(&opts.passthroughErrors, "passthrough-errors", true, "return Entra's status and body to Guard so the AADSTS code reaches kubectl")
	flag.Parse()

	// The documented recipe in authz/providers/azure/README.md passes
	// --client-id; keep it working rather than breaking an existing runbook.
	if opts.miClientID == "" {
		opts.miClientID = legacyClientID
	}

	return opts
}

// buildServer validates the options and wires the credential for the chosen
// mode. Requirements differ by mode, so validation is mode-aware rather than
// demanding every flag up front.
func buildServer(opts options) (*Server, error) {
	mode, err := tokenlab.ParseCredentialMode(opts.mode)
	if err != nil {
		return nil, err
	}

	if opts.miClientID == "" && mode != tokenlab.ModeCert {
		return nil, fmt.Errorf("--mi-client-id is required for mode %s", mode)
	}

	imds := tokenlab.NewIMDSClient(opts.imdsEndpoint, opts.miClientID)
	server := &Server{
		mode:              mode,
		imds:              imds,
		oboResource:       opts.oboResource,
		authzResource:     opts.authzResource,
		passthroughErrors: opts.passthroughErrors,
		dumpClaims:        opts.dumpClaims,
	}

	if mode == tokenlab.ModeIMDS {
		// No Entra exchange happens in this mode, so no token client is needed.
		return server, nil
	}

	credential, err := buildCredential(mode, opts)
	if err != nil {
		return nil, err
	}

	client, err := tokenlab.NewTokenClient(tokenlab.TokenClientConfig{
		AuthorityHost: opts.authorityHost,
		TenantID:      opts.tenantID,
		ClientID:      opts.appClientID,
		APIVersion:    tokenlab.APIVersion(opts.apiVersion),
		Credential:    credential,
	})
	if err != nil {
		return nil, err
	}

	server.issuer = client
	return server, nil
}

func buildCredential(mode tokenlab.CredentialMode, opts options) (tokenlab.ClientCredential, error) {
	if mode == tokenlab.ModeFIC {
		return tokenlab.NewFederatedCredential(tokenlab.NewIMDSClient(opts.imdsEndpoint, opts.miClientID)), nil
	}

	if opts.certFile == "" {
		return nil, fmt.Errorf("--cert-file is required for mode %s", tokenlab.ModeCert)
	}

	keyFile := opts.keyFile
	if keyFile == "" {
		keyFile = opts.certFile
	}

	signer, err := tokenlab.NewCertificateSignerFromPEM(opts.appClientID, opts.certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return tokenlab.NewCertificateCredential(signer), nil
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	if _, err := w.Write([]byte("OK")); err != nil {
		log.Printf("[health] status=error detail=%q", err.Error())
	}
}

func handleMetrics(server *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(server.Stats()); err != nil {
			log.Printf("[metrics] status=error detail=%q", err.Error())
		}
	}
}
