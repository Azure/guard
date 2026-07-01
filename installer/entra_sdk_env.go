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
	"go.kubeguard.dev/guard/auth/providers/azure"

	autorestazure "github.com/Azure/go-autorest/autorest/azure"
	"github.com/pkg/errors"
	core "k8s.io/api/core/v1"
)

func entraSDKEnvVars(opts azure.Options) ([]core.EnvVar, error) {
	if opts.ClientID == "" {
		return nil, errors.New("azure.client-id must be non-empty when Entra SDK is enabled")
	}
	if opts.TenantID == "" {
		return nil, errors.New("azure.tenant-id must be non-empty when Entra SDK is enabled")
	}

	env := autorestazure.PublicCloud
	if opts.Environment != "" {
		resolved, err := autorestazure.EnvironmentFromName(opts.Environment)
		if err != nil {
			return nil, errors.Wrap(err, "failed to resolve Entra SDK Azure AD instance")
		}
		env = resolved
	}

	return []core.EnvVar{
		{Name: "AzureAd__Instance", Value: env.ActiveDirectoryEndpoint},
		{Name: "AzureAd__TenantId", Value: opts.TenantID},
		{Name: "AzureAd__ClientId", Value: opts.ClientID},
		{Name: "AzureAd__Audience", Value: opts.ClientID},
	}, nil
}
