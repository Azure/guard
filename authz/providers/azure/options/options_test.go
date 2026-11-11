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

package options

import (
	"slices"
	"testing"

	"go.kubeguard.dev/guard/auth/providers/azure"

	"github.com/spf13/pflag"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

func validAKSOptions() Options {
	o := NewOptions()
	o.AuthzMode = AKSAuthzMode
	o.ResourceId = "/subscriptions/sub/resourcegroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster"
	o.AKSAuthzTokenURL = "https://localhost/authz/token"
	return o
}

func Test_AddFlags_defaultsEnableCustomResourceTypeCheckWithDiscovery(t *testing.T) {
	o := NewOptions()
	fs := pflag.NewFlagSet("guard", pflag.ContinueOnError)
	o.AddFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse(): %v", err)
	}

	if !o.AllowCustomResourceTypeCheck || !o.DiscoverResources {
		t.Errorf("defaults: want AllowCustomResourceTypeCheck and DiscoverResources true, got %v and %v",
			o.AllowCustomResourceTypeCheck, o.DiscoverResources)
	}
}

// Turning discovery off must not stop guard from starting, so the check alone is never a validation error.
func Test_Validate_customResourceTypeCheckWithAndWithoutDiscovery(t *testing.T) {
	tests := []struct {
		name              string
		discoverResources bool
	}{
		{name: "defaults", discoverResources: true},
		{name: "discovery disabled, check left on", discoverResources: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := validAKSOptions()
			o.DiscoverResources = tt.discoverResources

			if errs := o.Validate(azure.Options{}); len(errs) != 0 {
				t.Errorf("Validate(): want no errors, got %v", errs)
			}
		})
	}
}

func Test_Apply_rendersDiscoverResources(t *testing.T) {
	tests := []struct {
		name              string
		discoverResources bool
		want              string
	}{
		{name: "enabled", discoverResources: true, want: "--azure.discover-resources=true"},
		{name: "disabled", discoverResources: false, want: "--azure.discover-resources=false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := validAKSOptions()
			o.DiscoverResources = tt.discoverResources
			d := &apps.Deployment{}
			d.Spec.Template.Spec.Containers = []core.Container{{}}

			if _, err := o.Apply(d); err != nil {
				t.Fatalf("Apply(): %v", err)
			}
			if args := d.Spec.Template.Spec.Containers[0].Args; !slices.Contains(args, tt.want) {
				t.Errorf("Apply() args = %v, want %s", args, tt.want)
			}
		})
	}
}
