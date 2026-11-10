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

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.kubeguard.dev/guard/auth/providers/azure"
	"go.kubeguard.dev/guard/auth/providers/azure/graph"
	"go.kubeguard.dev/guard/auth/providers/github"
	"go.kubeguard.dev/guard/auth/providers/gitlab"
	"go.kubeguard.dev/guard/auth/providers/google"
	"go.kubeguard.dev/guard/auth/providers/ldap"
	errutils "go.kubeguard.dev/guard/util/error"

	fuzz "github.com/google/gofuzz"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"gomodules.xyz/blobfs"
	"gomodules.xyz/cert"
	"gomodules.xyz/cert/certstore"
	auth "k8s.io/api/authentication/v1"
)

func TestServeHTTP(t *testing.T) {
	srv := Server{
		AuthRecommendedOptions: NewAuthRecommendedOptions(),
	}

	store, err := certstore.New(blobfs.NewInMemoryFS(), "/pki", "foo")
	if err != nil {
		t.Fatal(err)
	}
	err = store.InitCA()
	if err != nil {
		t.Fatal(err)
	}

	pemCertsWithOrg, _, err := store.NewClientCertPairBytes(cert.AltNames{DNSNames: []string{"guard"}}, "foo")
	if err != nil {
		t.Fatal(err)
	}
	clientCertWithOrg, err := cert.ParseCertsPEM(pemCertsWithOrg)
	if err != nil {
		t.Fatal(err)
	}

	pemCertsWithoutOrg, _, err := store.NewClientCertPairBytes(cert.AltNames{DNSNames: []string{"guard"}})
	if err != nil {
		t.Fatal(err)
	}
	clientCertWithoutOrg, err := cert.ParseCertsPEM(pemCertsWithoutOrg)
	if err != nil {
		t.Fatal(err)
	}

	type TestData struct {
		TokenReview      auth.TokenReview
		UseClientCert    bool
		IncludeClientOrg bool
	}
	f := fuzz.New().MaxDepth(3)

	for i := 0; i < 1000; i++ {
		obj := TestData{}
		f.Fuzz(&obj)

		review := new(bytes.Buffer)
		err := json.NewEncoder(review).Encode(obj.TokenReview)
		if err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest("GET", "http://guard.test/tokenreviews", review)
		if obj.UseClientCert && obj.IncludeClientOrg {
			req.TLS = &tls.ConnectionState{
				PeerCertificates: clientCertWithOrg,
			}
		} else if obj.UseClientCert && !obj.IncludeClientOrg {
			req.TLS = &tls.ConnectionState{
				PeerCertificates: clientCertWithoutOrg,
			}
		}

		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		resp := w.Result()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "unexpected response status code")
		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"), "unexpected response content-type")
		err = json.NewDecoder(resp.Body).Decode(&auth.TokenReview{})
		assert.Nil(t, err, "response body must be of kind TokenReview")
	}
}

func TestGetAuthProviderClient(t *testing.T) {
	const invalideAuthProvider = "invalid_auth_provider"

	testData := []struct {
		testName     string
		authProvider string
		expectedErr  error
	}{
		{
			"get github client",
			github.OrgType,
			nil,
		},
		{
			"get google client",
			google.OrgType,
			nil,
		},
		{
			"get gitlab client",
			gitlab.OrgType,
			nil,
		},
		{
			"get azure client",
			azure.OrgType,
			nil,
		},
		{
			"get LDAP client",
			ldap.OrgType,
			nil,
		},
		{
			"unknown auth providername",
			invalideAuthProvider,
			errors.Errorf("Client is using unknown organization %s", invalideAuthProvider),
		},
	}
	s := Server{
		AuthRecommendedOptions: NewAuthRecommendedOptions(),
	}
	ctx := context.Background()

	// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols-oidc
	// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code#jwt-token-claims
	s.AuthRecommendedOptions.Azure.TenantID = "7fe81447-da57-4385-becb-6de57f21477e"

	for _, test := range testData {
		t.Run(test.testName, func(t *testing.T) {
			client, err := s.getAuthProviderClient(ctx, test.authProvider, "")

			if test.expectedErr == nil {
				assert.Nil(t, err, "expected error nil")

				if err == nil {
					assert.Equal(t, test.authProvider, client.UID())
				}
			} else {
				assert.NotNil(t, err)

				if err != nil {
					assert.EqualError(t, err, test.expectedErr.Error())
				}
			}
		})
	}
}

func TestAzureDependencyTokenReviewResponse(t *testing.T) {
	const sensitive = "sensitive-upstream-body-and-token"
	for _, upstreamStatus := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(upstreamStatus)
			_, _ = writer.Write([]byte(`{"error":"invalid_grant","error_codes":[53003],"error_description":"` + sensitive + `"}`))
		}))
		provider := graph.NewAKSTokenProvider(upstream.URL, "tenant")
		_, dependencyErr := provider.Acquire(context.Background(), sensitive)
		upstream.Close()
		if dependencyErr == nil {
			t.Fatal("expected upstream failure")
		}
		for _, status := range []int{http.StatusUnauthorized, http.StatusOK} {
			responseErr := dependencyErr
			if status == http.StatusOK {
				responseErr = errutils.WithCode(dependencyErr, http.StatusOK)
			}
			writer := httptest.NewRecorder()
			write(writer, nil, responseErr)
			if writer.Code != status {
				t.Errorf("expected unchanged webhook status %d, got %d", status, writer.Code)
			}
			var review auth.TokenReview
			if err := json.Unmarshal(writer.Body.Bytes(), &review); err != nil {
				t.Fatal(err)
			}
			if review.Status.Authenticated || !strings.Contains(review.Status.Error, "reason=OBO_POLICY_BLOCKED") {
				t.Errorf("expected safe negative TokenReview: %+v", review.Status)
			}
			if strings.Contains(writer.Body.String(), sensitive) {
				t.Error("TokenReview exposed raw upstream response")
			}
		}
	}
}
