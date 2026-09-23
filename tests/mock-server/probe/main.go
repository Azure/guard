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

// probe answers, empirically, whether a Managed Identity used as a Federated
// Identity Credential can replace the certificate the AKS OBO service signs its
// client assertions with.
//
// It runs the {grant} x {credential} matrix against real Entra and prints a
// results table with the exact AADSTS code for every refusal. It needs no Guard
// and no standalone environment - only a pod with access to IMDS.
//
// Two questions drive it:
//
//	Q1  client_credentials + federated assertion  (documented; confirm here)
//	Q2  on-behalf-of       + federated assertion  (UNDOCUMENTED - the real unknown)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"go.kubeguard.dev/guard/tests/mock-server/tokenlab"
)

const (
	defaultOBOResource = "https://graph.microsoft.com"
	defaultPDPResource = "https://authorization.azure.net"
	defaultCheckAction = "Microsoft.ContainerService/managedClusters/read"
	probeTimeout       = 2 * time.Minute

	grantClientCredentials = "client_credentials"
	grantOnBehalfOf        = "on-behalf-of"
	grantNone              = "none (direct)"
)

type config struct {
	tenantID      string
	appClientID   string
	miClientID    string
	certFile      string
	keyFile       string
	userAssertion string
	oboResource   string
	pdpResource   string
	imdsEndpoint  string
	authorityHost string

	// PDP verification. Without all three of pdpEndpoint, checkSubjectOID and
	// checkResourceID the probe only proves tokens were issued, never that they
	// are accepted anywhere.
	pdpRegion       string
	pdpEndpoint     string
	checkSubjectOID string
	checkResourceID string
	checkAction     string
}

func main() {
	cfg := parseFlags()
	if err := cfg.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %s\n", err)
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	experiments, err := buildExperiments(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build experiments: %s\n", err)
		os.Exit(1)
	}

	printHeader(cfg)

	results := make([]Result, 0, len(experiments))
	for _, experiment := range experiments {
		result := experiment.Run(ctx)
		results = append(results, result)
		fmt.Printf("  %-6s %s\n", result.Outcome, experiment.Name)
	}

	printResults(results)
	printVerdicts(results)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.tenantID, "tenant-id", "", "Entra tenant ID (required)")
	flag.StringVar(&cfg.appClientID, "app-client-id", "", "client ID of the app registration under test (required)")
	flag.StringVar(&cfg.miClientID, "mi-client-id", "", "client ID of the managed identity to use via IMDS; omit to let IMDS pick the node's default assigned identity")
	flag.StringVar(&cfg.certFile, "cert-file", "", "PEM certificate for cert mode; omit to skip the certificate baseline")
	flag.StringVar(&cfg.keyFile, "key-file", "", "PEM private key for cert mode (defaults to --cert-file)")
	flag.StringVar(&cfg.userAssertion, "user-assertion-file", "", "file holding a delegated user token whose aud is --app-client-id; omit to skip the OBO experiments")
	flag.StringVar(&cfg.oboResource, "obo-resource", defaultOBOResource, "downstream resource for the OBO experiments; point this at a second test app (api://<appid>) to avoid needing admin consent on Graph")
	flag.StringVar(&cfg.pdpResource, "pdp-resource", defaultPDPResource, "resource for the app-only experiments")
	flag.StringVar(&cfg.imdsEndpoint, "imds-endpoint", "", "override the IMDS token endpoint (testing only)")
	flag.StringVar(&cfg.authorityHost, "authority-host", "", "override the Entra authority host (sovereign clouds)")
	flag.StringVar(&cfg.pdpRegion, "pdp-region", "", "region whose PDP endpoint to call, e.g. eastus2; enables end-to-end verification")
	flag.StringVar(&cfg.pdpEndpoint, "pdp-endpoint", "", "full CheckAccess URL; overrides --pdp-region")
	flag.StringVar(&cfg.checkSubjectOID, "check-subject-oid", "", "object id of the principal to evaluate access for")
	flag.StringVar(&cfg.checkResourceID, "check-resource-id", "", "REAL Azure resource id to evaluate against; PDP rejects synthetic scopes")
	flag.StringVar(&cfg.checkAction, "check-action", defaultCheckAction, "action to evaluate")
	flag.Parse()

	// A region is the convenient form; the full URL is the authoritative one.
	// Building it centrally avoids the bare-host mistake that returns 404.
	if cfg.pdpEndpoint == "" && cfg.pdpRegion != "" {
		cfg.pdpEndpoint = tokenlab.BuildPDPEndpoint(cfg.pdpRegion)
	}

	return cfg
}

func (c *config) validate() error {
	var missing []string
	if c.tenantID == "" {
		missing = append(missing, "--tenant-id")
	}
	if c.appClientID == "" {
		missing = append(missing, "--app-client-id")
	}
	// --mi-client-id is deliberately NOT required. A node may have exactly one
	// assigned identity, in which case IMDS resolves it without being told which
	// one - and on a cluster we do not own, its client id may not be readable
	// from ARM at all.
	if len(missing) > 0 {
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}
	return nil
}

// loadUserAssertion reads the delegated token used as the OBO `assertion`.
// Returns an empty string when no file was configured, which downgrades the OBO
// experiments to SKIP rather than failing the run.
func (c *config) loadUserAssertion() (string, error) {
	if c.userAssertion == "" {
		return "", nil
	}
	raw, err := os.ReadFile(c.userAssertion) // #nosec G304 - operator-supplied path by design
	if err != nil {
		return "", fmt.Errorf("read user assertion: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func printHeader(cfg config) {
	fmt.Printf("tokenlab probe\n")
	fmt.Printf("  tenant       %s\n", cfg.tenantID)
	fmt.Printf("  application  %s\n", cfg.appClientID)
	fmt.Printf("  identity     %s\n", cfg.miClientID)
	if cfg.pdpEndpoint != "" {
		fmt.Printf("  pdp          %s\n", cfg.pdpEndpoint)
		fmt.Printf("  checking     %s on %s\n", cfg.checkAction, cfg.checkResourceID)
	} else {
		fmt.Printf("  pdp          NOT CONFIGURED - tokens will be issued but never spent\n")
	}
	fmt.Printf("\nrunning experiments:\n")
}

func printResults(results []Result) {
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(writer, "\nQ\tEXPERIMENT\tGRANT\tCRED\tAPI\tOUTCOME\tAADSTS\tASSERTION\tPDP\tCLAIMS / DETAIL\n")

	for _, result := range results {
		experiment := result.Experiment
		_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			orDash(string(experiment.Question)),
			experiment.Name,
			experiment.Grant,
			orDash(string(experiment.Mode)),
			orDash(string(experiment.Version)),
			result.Outcome,
			orDash(result.AADSTS),
			orDash(result.AssertionFP),
			orDash(result.Verified),
			resultDetail(result),
		)
	}
	_ = writer.Flush()
}

// resultDetail prefers decoded claims over prose: on a pass, what the token
// actually contains is the interesting part. A refusal reverses that, because
// the reason is what matters.
func resultDetail(result Result) string {
	if result.Outcome == OutcomeRefused || result.Outcome == OutcomeError {
		return collapse(result.Detail)
	}
	if result.Claims != nil {
		return result.Claims.Summary()
	}
	return collapse(result.Detail)
}

func printVerdicts(results []Result) {
	fmt.Printf("\nanswers\n")
	fmt.Printf("  PDP end-to-end (token actually accepted)     : %s\n", PDPVerdict(results))
	fmt.Printf("  Q1  client_credentials + federated assertion : %s\n", Verdict(Q1, results))
	fmt.Printf("  Q2  on-behalf-of + federated assertion       : %s\n", Verdict(Q2, results))

	printControlCheck(results)

	fmt.Printf("\nnotes\n")
	fmt.Printf("  REFUSED means Entra issued the token but PDP rejected it (401/403) - the\n")
	fmt.Printf("  caller needs Microsoft.Authorization/checkAccess/action, available only\n")
	fmt.Printf("  via a wildcard (Contributor).\n")
	fmt.Printf("  ERROR means the CheckAccess call never returned a decision (404, 5xx,\n")
	fmt.Printf("  transport or parse failure). That says nothing about the credential.\n")
	fmt.Printf("  A PDP decision of either allowed or denied counts as success here: it\n")
	fmt.Printf("  proves the call was authenticated and evaluated.\n")
	fmt.Printf("  %s means no Federated Identity Credential matched - check that the FIC\n", tokenlab.ErrCodeNoFederatedRecord)
	fmt.Printf("  subject is the managed identity's OBJECT id (not its client id), and allow\n")
	fmt.Printf("  a few minutes for propagation after creating it.\n")
	fmt.Printf("  %s means an app-only token was offered as the OBO assertion.\n", tokenlab.ErrCodeOBOAppToken)
}

// printControlCheck reports whether the federated rows are actually comparable.
//
// Without this, "Q1 passed but Q2 failed" is not evidence that the grant type
// caused the difference - the two calls might simply have presented different
// assertions. The digests make that checkable.
func printControlCheck(results []Result) {
	federated := make([]Result, 0, len(results))
	for _, result := range results {
		if result.Experiment.Mode == tokenlab.ModeFIC {
			federated = append(federated, result)
		}
	}

	fmt.Printf("\ncontrol\n")
	established, reason := SameAssertion(federated)
	if established {
		fmt.Printf("  OK   every federated row presented the same client assertion, so any\n")
		fmt.Printf("       difference between Q1 and Q2 is attributable to the grant type.\n")
		return
	}
	fmt.Printf("  WARN control not established: %s.\n", reason)
	fmt.Printf("       A Q1/Q2 difference cannot be attributed to the grant type; re-run so\n")
	fmt.Printf("       the assertion cache covers the whole matrix.\n")
}

func orDash(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

// collapse flattens multi-line Entra descriptions so the table stays readable.
func collapse(value string) string {
	const limit = 140
	flattened := strings.Join(strings.Fields(value), " ")
	if len(flattened) > limit {
		return flattened[:limit] + "..."
	}
	return flattened
}
