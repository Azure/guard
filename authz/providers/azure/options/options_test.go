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
	"testing"

	"go.kubeguard.dev/guard/auth/providers/azure"
)

// Test_NewOptionsAllowsCustomResourceTypeCheckByDefault pins the default of
// AllowCustomResourceTypeCheck.
//
// The value of this option decides which DataAction a custom resource request
// resolves to, and only the customresources form carries the customResources
// group/kind attributes that a condition scoped to those attributes evaluates. A
// deployment that does not pass the flag therefore inherits whichever behaviour
// this default selects, so the default is itself the control - and it has to be the
// one that leaves such conditions evaluable.
func Test_NewOptionsAllowsCustomResourceTypeCheckByDefault(t *testing.T) {
	if got := NewOptions().AllowCustomResourceTypeCheck; !got {
		t.Errorf("NewOptions().AllowCustomResourceTypeCheck: want true, got %v", got)
	}
}

// Test_ValidateAcceptsDefaultCustomResourceTypeCheck guards the default against a
// validation rule that would make it unreachable.
//
// AllowCustomResourceTypeCheck defaults to true while DiscoverResources defaults to
// false, so any rule rejecting that pair would reject every unconfigured deployment
// and force operators to turn the check off to start guard at all. The pair is safe
// because the check reports itself unavailable at request time when the operations
// map is empty, which is what an absent discovery run leaves behind.
func Test_ValidateAcceptsDefaultCustomResourceTypeCheck(t *testing.T) {
	o := NewOptions()
	o.AuthzMode = AKSAuthzMode
	o.ResourceId = "/subscriptions/sub/resourcegroups/rg/providers/Microsoft.ContainerService/managedClusters/cluster"
	o.AKSAuthzTokenURL = "https://localhost/authz/token"

	if !o.AllowCustomResourceTypeCheck || o.DiscoverResources {
		t.Fatalf("precondition: want AllowCustomResourceTypeCheck=true and DiscoverResources=false, got %v and %v",
			o.AllowCustomResourceTypeCheck, o.DiscoverResources)
	}

	if errs := o.Validate(azure.Options{}); len(errs) != 0 {
		t.Errorf("Validate on default options: want no errors, got %v", errs)
	}
}
