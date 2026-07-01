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

package installer

import (
	"testing"

	"go.kubeguard.dev/guard/auth/providers/azure"

	"github.com/stretchr/testify/assert"
	core "k8s.io/api/core/v1"
)

func TestEntraSDKEnvVars(t *testing.T) {
	tests := []struct {
		testName    string
		opts        azure.Options
		expectedEnv []core.EnvVar
		expectedErr string
	}{
		{
			testName: "returns expected env vars for public cloud",
			opts: azure.Options{
				ClientID: "client-id",
				TenantID: "tenant-id",
			},
			expectedEnv: []core.EnvVar{
				{Name: "AzureAd__Instance", Value: "https://login.microsoftonline.com/"},
				{Name: "AzureAd__TenantId", Value: "tenant-id"},
				{Name: "AzureAd__ClientId", Value: "client-id"},
				{Name: "AzureAd__Audience", Value: "client-id"},
			},
		},
		{
			testName: "uses configured azure environment",
			opts: azure.Options{
				Environment: "AzureChinaCloud",
				ClientID:    "client-id",
				TenantID:    "tenant-id",
			},
			expectedEnv: []core.EnvVar{
				{Name: "AzureAd__Instance", Value: "https://login.chinacloudapi.cn/"},
				{Name: "AzureAd__TenantId", Value: "tenant-id"},
				{Name: "AzureAd__ClientId", Value: "client-id"},
				{Name: "AzureAd__Audience", Value: "client-id"},
			},
		},
		{
			testName: "returns error when client id is missing",
			opts: azure.Options{
				TenantID: "tenant-id",
			},
			expectedErr: "azure.client-id must be non-empty when Entra SDK is enabled",
		},
		{
			testName: "returns error when tenant id is missing",
			opts: azure.Options{
				ClientID: "client-id",
			},
			expectedErr: "azure.tenant-id must be non-empty when Entra SDK is enabled",
		},
		{
			testName: "returns error when environment is invalid",
			opts: azure.Options{
				Environment: "definitely-not-a-real-cloud",
				ClientID:    "client-id",
				TenantID:    "tenant-id",
			},
			expectedErr: "failed to resolve Entra SDK Azure AD instance: autorest/azure: There is no cloud environment matching the name \"DEFINITELY-NOT-A-REAL-CLOUD\"",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			envVars, err := entraSDKEnvVars(test.opts)

			if test.expectedErr != "" {
				assert.EqualError(t, err, test.expectedErr)
				return
			}

			if assert.NoError(t, err) {
				assert.Equal(t, test.expectedEnv, envVars)
			}
		})
	}
}
