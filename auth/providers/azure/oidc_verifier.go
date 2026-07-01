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
	"fmt"

	"github.com/coreos/go-oidc"
)

var (
	_ accessTokenVerifier = (*oidcAccessTokenVerifier)(nil)
	_ verifiedAccessToken = (*oidcVerifiedAccessToken)(nil)
)

type oidcAccessTokenVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func (o *oidcAccessTokenVerifier) Verify(ctx context.Context, rawAccessToken string) (verifiedAccessToken, error) {
	token, err := o.verifier.Verify(ctx, rawAccessToken)
	if err != nil {
		return nil, err
	}

	return &oidcVerifiedAccessToken{token: token}, nil
}

type oidcVerifiedAccessToken struct {
	token *oidc.IDToken
}

func (t *oidcVerifiedAccessToken) Claims() (claims, error) {
	if t.token == nil {
		return nil, fmt.Errorf("claims not set")
	}

	parsedClaims := claims{}
	if err := t.token.Claims(&parsedClaims); err != nil {
		return nil, err
	}

	return parsedClaims, nil
}
