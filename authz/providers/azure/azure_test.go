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

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	auth "go.kubeguard.dev/guard/auth/providers/azure"
	"go.kubeguard.dev/guard/authz"
	"go.kubeguard.dev/guard/authz/providers/azure/data"
	authzOpts "go.kubeguard.dev/guard/authz/providers/azure/options"
	"go.kubeguard.dev/guard/authz/providers/azure/rbac"
	errutils "go.kubeguard.dev/guard/util/error"
	"go.kubeguard.dev/guard/util/httpclient/httpclienttesting"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	authzv1 "k8s.io/api/authorization/v1"
)

const (
	loginResp            = `{ "token_type": "Bearer", "expires_on": 1732881796, "access_token": "%v"}`
	httpClientRetryCount = 2
)

func init() {
	httpclienttesting.HijackDefaultHTTPClientTransportWithSelfSignedTLS()
}

func clientSetup(serverUrl, mode string) (*Authorizer, error) {
	c := &Authorizer{}
	opts := authzOpts.Options{
		AuthzMode:                      mode,
		ResourceId:                     "resourceId",
		ARMCallLimit:                   2000,
		SkipAuthzCheck:                 []string{"alpha, tango, charlie"},
		SkipAuthzForNonAADUsers:        true,
		AllowNonResDiscoveryPathAccess: true,
	}

	authOpts := auth.Options{
		ClientID:             "client_id",
		ClientSecret:         "client_secret",
		TenantID:             "tenant_id",
		HttpClientRetryCount: httpClientRetryCount,
	}

	authzInfo := rbac.AuthzInfo{
		AADEndpoint: serverUrl + "/login/",
		ARMEndPoint: serverUrl + "/arm/",
	}

	c.rbacClient, err = rbac.New(opts, authOpts, &authzInfo)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func serverSetup(loginResp, checkaccessResp string, loginStatus, checkaccessStatus int, sleepFor time.Duration) *httptest.Server {
	m := chi.NewRouter()

	m.Post("/login/*", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(loginStatus)
		_, _ = w.Write([]byte(loginResp))
	})

	m.Post("/arm/*", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(sleepFor)
		w.WriteHeader(checkaccessStatus)
		_, _ = w.Write([]byte(checkaccessResp))
	})

	srv := httptest.NewTLSServer(m)

	return srv
}

func getServerAndClient(t *testing.T, loginResp, checkaccessResp string, checkaccessStatus int, sleepFor time.Duration) (*httptest.Server, *Authorizer, authz.Store) {
	srv := serverSetup(loginResp, checkaccessResp, http.StatusOK, checkaccessStatus, sleepFor)

	client, err := clientSetup(srv.URL, "arc")
	if err != nil {
		t.Fatalf("Error when creatidng azure client. reason : %v", err)
	}

	testOptions := data.Options{
		HardMaxCacheSize:   1,
		Shards:             1,
		LifeWindow:         1 * time.Minute,
		CleanWindow:        1 * time.Minute,
		MaxEntriesInWindow: 10,
		MaxEntrySize:       5,
		Verbose:            false,
	}
	dataStore, _ := data.NewDataStore(testOptions)

	return srv, client, dataStore
}

func TestCheck(t *testing.T) {
	t.Run("successful request", func(t *testing.T) {
		validBody := `[{"accessDecision":"Allowed",
		"actionId":"Microsoft.Kubernetes/connectedClusters/pods/delete",
		"isDataAction":true,"roleAssignment":null,"denyAssignment":null,"timeToLiveInMs":300000}]`

		srv, client, store := getServerAndClient(t, loginResp, validBody, http.StatusOK, 1*time.Second)
		defer srv.Close()
		defer func() {
			_ = store.Close()
		}()

		request := &authzv1.SubjectAccessReviewSpec{
			User: "beta@bing.com",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "dev", Group: "", Resource: "pods",
				Subresource: "status", Version: "v1", Name: "test", Verb: "delete",
			}, Extra: map[string]authzv1.ExtraValue{"oid": {"00000000-0000-0000-0000-000000000000"}},
		}

		ctx := context.Background()
		resp, err := client.Check(ctx, request, store)
		assert.Nilf(t, err, "Should not have got error")
		assert.NotNil(t, resp)
		assert.Equal(t, resp.Allowed, true)
		assert.Equal(t, resp.Denied, false)
		if v, ok := err.(errutils.HttpStatusCode); ok {
			assert.Equal(t, v.Code(), http.StatusOK)
		}
	})

	t.Run("unsuccessful request", func(t *testing.T) {
		validBody := `""`
		srv, client, store := getServerAndClient(t, loginResp, validBody, http.StatusInternalServerError, 1*time.Second)
		defer srv.Close()
		defer func() {
			_ = store.Close()
		}()

		request := &authzv1.SubjectAccessReviewSpec{
			User: "beta@bing.com",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "dev", Group: "", Resource: "pods",
				Subresource: "status", Version: "v1", Name: "test", Verb: "delete",
			}, Extra: map[string]authzv1.ExtraValue{"oid": {"00000000-0000-0000-0000-000000000000"}},
		}

		ctx := context.Background()
		resp, err := client.Check(ctx, request, store)
		assert.Nilf(t, resp, "response should be nil")
		assert.NotNilf(t, err, "should get error")
		assert.Contains(t, err.Error(), "Authorization check failed")
		assert.Contains(t, err.Error(), fmt.Sprintf("giving up after %d attempt", httpClientRetryCount+1))
		if v, ok := err.(errutils.HttpStatusCode); ok {
			assert.Equal(t, v.Code(), http.StatusInternalServerError)
		}
	})

	t.Run("context timeout request", func(t *testing.T) {
		validBody := `""`
		srv, client, store := getServerAndClient(t, loginResp, validBody, http.StatusInternalServerError, 25*time.Second)
		defer srv.Close()
		defer func() {
			_ = store.Close()
		}()

		request := &authzv1.SubjectAccessReviewSpec{
			User: "beta@bing.com",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "dev", Group: "", Resource: "pods",
				Subresource: "status", Version: "v1", Name: "test", Verb: "delete",
			}, Extra: map[string]authzv1.ExtraValue{"oid": {"00000000-0000-0000-0000-000000000000"}},
		}

		ctx := context.Background()
		resp, err := client.Check(ctx, request, store)
		assert.Nilf(t, resp, "response should be nil")
		assert.NotNilf(t, err, "should get error")
		assert.Contains(t, err.Error(), "context deadline exceeded")
		if v, ok := err.(errutils.HttpStatusCode); ok {
			assert.Equal(t, v.Code(), http.StatusInternalServerError)
		}
	})
}

const (
	subjectTestClusterID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/c"
	subjectTestUser      = "alice@contoso.com"
	userObjectID         = "5a1d3c7e-0b2f-4e68-9d14-3c6b8a2f7e01"
	userGroupID          = "8c4e2a6d-1f3b-4a57-b9e0-6d2c4f8a1b35"
	secondUserGroupID    = "0d9f5b3a-6e1c-4f27-8a43-b2e7c5d1f964"
	allowedObjectID      = "2e7b9d1c-4a6f-4c38-8b05-9f1e3d7c5a62"
	allowedGroupID       = "6f3a1e9b-7c2d-4e84-a6b1-0c5d9e3f7a28"
)

// checkAccessStub allows allowedObjectID and allowedGroupID members and records each subject.
type checkAccessStub struct {
	mu       sync.Mutex
	subjects []rbac.SubjectInfoAttributes
}

func (s *checkAccessStub) checkAccess(w http.ResponseWriter, r *http.Request) {
	var req rbac.CheckAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	subject := req.Subject.Attributes
	s.mu.Lock()
	s.subjects = append(s.subjects, subject)
	s.mu.Unlock()

	decision := "NotAllowed"
	if subject.ObjectId == allowedObjectID || slices.Contains(subject.Groups, allowedGroupID) {
		decision = "Allowed"
	}
	decisions := make([]rbac.AuthorizationDecision, 0, len(req.Actions))
	for _, action := range req.Actions {
		decisions = append(decisions, rbac.AuthorizationDecision{Decision: decision, ActionId: action.Id, IsDataAction: true})
	}
	_ = json.NewEncoder(w).Encode(decisions)
}

func (s *checkAccessStub) recorded() []rbac.SubjectInfoAttributes {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.subjects)
}

type subjectHarness struct {
	stub       *checkAccessStub
	authorizer *Authorizer
	store      authz.Store
}

func newSubjectHarness(t *testing.T) *subjectHarness {
	t.Helper()
	stub := &checkAccessStub{}
	router := chi.NewRouter()
	router.Post("/login/*", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_on":4102444800,"access_token":"t"}`))
	})
	router.Post("/arm/*", stub.checkAccess)
	srv := httptest.NewTLSServer(router)
	t.Cleanup(srv.Close)

	opts := authzOpts.Options{
		AuthzMode:        authzOpts.AKSAuthzMode,
		ResourceId:       subjectTestClusterID,
		AKSAuthzTokenURL: srv.URL + "/login/token",
	}
	authzInfo := rbac.AuthzInfo{AADEndpoint: srv.URL + "/login/", ARMEndPoint: srv.URL + "/arm/"}
	rbacClient, err := rbac.New(opts, auth.Options{TenantID: "tenant_id", HttpClientRetryCount: httpClientRetryCount}, &authzInfo)
	if err != nil {
		t.Fatalf("rbac.New() error = %v", err)
	}
	store, err := data.NewDataStore(data.NewOptions())
	if err != nil {
		t.Fatalf("data.NewDataStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return &subjectHarness{stub: stub, authorizer: &Authorizer{rbacClient: rbacClient}, store: store}
}

// check runs Check and returns its verdict and the subjects it sent to CheckAccess.
func (h *subjectHarness) check(t *testing.T, request *authzv1.SubjectAccessReviewSpec) (bool, []rbac.SubjectInfoAttributes) {
	t.Helper()
	before := len(h.stub.recorded())
	resp, err := h.authorizer.Check(context.Background(), request, h.store)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	return resp.Allowed, h.stub.recorded()[before:]
}

func subjectRequest(objectID string, groups []string, attr authzv1.ResourceAttributes) *authzv1.SubjectAccessReviewSpec {
	return &authzv1.SubjectAccessReviewSpec{
		User:               subjectTestUser,
		Groups:             append([]string{"system:authenticated"}, groups...),
		Extra:              map[string]authzv1.ExtraValue{"oid": {objectID}},
		ResourceAttributes: &attr,
	}
}

type subjectStep struct {
	objectID string
	groups   []string
	allowed  bool
}

// runSubjectSteps runs steps on one harness; each must reach CheckAccess once, for its own subject.
func runSubjectSteps(t *testing.T, attr authzv1.ResourceAttributes, steps ...subjectStep) {
	t.Helper()
	h := newSubjectHarness(t)
	for i, s := range steps {
		allowed, asked := h.check(t, subjectRequest(s.objectID, s.groups, attr))
		assert.Equalf(t, s.allowed, allowed, "request %d verdict", i+1)
		assert.Equalf(t, []rbac.SubjectInfoAttributes{{ObjectId: s.objectID, Groups: s.groups}}, asked,
			"request %d CheckAccess subjects", i+1)
	}
}

// TestCheck_cachedDecisionIsScopedToSubject asserts a verdict is never reused for another subject.
func TestCheck_cachedDecisionIsScopedToSubject(t *testing.T) {
	requests := []struct {
		name string
		attr authzv1.ResourceAttributes
	}{
		{"get configmaps", authzv1.ResourceAttributes{Namespace: "default", Resource: "configmaps", Verb: "get"}},
		{"create clusterrolebindings", authzv1.ResourceAttributes{
			Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Verb: "create",
		}},
		{"escalate clusterroles", authzv1.ResourceAttributes{
			Group: "rbac.authorization.k8s.io", Resource: "clusterroles", Verb: "escalate",
		}},
	}
	own := []string{userGroupID}
	ownAndAllowed := []string{userGroupID, allowedGroupID}
	scenarios := []struct {
		name          string
		first, second subjectStep
	}{
		{"allowed object id, then own object id", subjectStep{allowedObjectID, own, true}, subjectStep{userObjectID, own, false}},
		{"allowed group added, then own groups", subjectStep{userObjectID, ownAndAllowed, true}, subjectStep{userObjectID, own, false}},
		{"denied object id, then allowed object id", subjectStep{userObjectID, own, false}, subjectStep{allowedObjectID, own, true}},
	}

	for _, req := range requests {
		for _, sc := range scenarios {
			t.Run(req.name+"/"+sc.name, func(t *testing.T) {
				runSubjectSteps(t, req.attr, sc.first, sc.second)
			})
		}
	}
}

// TestCheck_cachedDecisionIsReusedForSameSubject asserts a repeated subject is served from cache.
func TestCheck_cachedDecisionIsReusedForSameSubject(t *testing.T) {
	attr := authzv1.ResourceAttributes{Namespace: "default", Resource: "configmaps", Verb: "get"}
	groups := []string{userGroupID, secondUserGroupID}
	reordered := []string{secondUserGroupID, userGroupID}

	for _, tc := range []struct {
		name     string
		objectID string
		allowed  bool
	}{
		{"allowed", allowedObjectID, true},
		{"denied", userObjectID, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSubjectHarness(t)
			firstAllowed, firstAsked := h.check(t, subjectRequest(tc.objectID, groups, attr))
			assert.Equal(t, tc.allowed, firstAllowed)
			assert.Len(t, firstAsked, 1)
			for _, g := range [][]string{groups, reordered} {
				allowed, asked := h.check(t, subjectRequest(tc.objectID, g, attr))
				assert.Equalf(t, tc.allowed, allowed, "groups %v verdict", g)
				assert.Emptyf(t, asked, "groups %v must be served from the cache", g)
			}
		})
	}
}
