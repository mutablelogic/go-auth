// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"context"
	"strings"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// Provider defines the browser and code-exchange hooks for an identity provider.
type Provider interface {
	// Key returns the stable provider key.
	Key() string

	// PublicConfig returns the safe-to-expose client configuration.
	PublicConfig() schema.PublicClientConfiguration

	// HTTPHandler returns the provider-owned browser handler for caller-defined mounts.
	HTTPHandler() httprequest.PathItem

	// BeginAuthorization starts the browser authorization flow.
	BeginAuthorization(context.Context, AuthorizationRequest) (*AuthorizationResponse, error)

	// ExchangeAuthorizationCode converts a code into a normalized identity,
	// which can be inserted into the database and used to issue local session tokens.
	ExchangeAuthorizationCode(context.Context, ExchangeRequest) (*schema.IdentityInsert, error)
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthorizationRequest struct {
	RedirectURL         string `json:"redirect_uri" jsonschema:"Client callback URI that receives the authorization result." format:"uri" example:"http://127.0.0.1:8085/callback" required:""`
	ProviderURL         string `json:"-"`
	State               string `json:"state" jsonschema:"Opaque client state value that is forwarded through the authorization flow." example:"b1c2d3e4f5" required:""`
	Scope               string `json:"scope,omitempty" jsonschema:"Optional space-delimited scopes requested from the selected provider." example:"openid email profile"`
	Nonce               string `json:"nonce,omitempty" jsonschema:"Optional nonce forwarded to OIDC-capable providers." example:"n-0S6_WzA2Mj"`
	CodeChallenge       string `json:"code_challenge" jsonschema:"PKCE code challenge derived from the client verifier." example:"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" required:""`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" jsonschema:"PKCE code challenge method. Defaults to S256 when omitted." default:"S256" example:"S256"`
	LoginHint           string `json:"login_hint,omitempty" jsonschema:"Optional login hint forwarded to the provider. The local provider uses this as the suggested email address." example:"user@example.com"`
}

func (req AuthorizationRequest) ScopeList() []string {
	if scope := strings.TrimSpace(req.Scope); scope != "" {
		return strings.Fields(scope)
	}
	return nil
}

type AuthorizationResponse struct {
	RedirectURL string
}

type ExchangeRequest struct {
	Code         string
	RedirectURL  string
	CodeVerifier string
	Nonce        string
}
