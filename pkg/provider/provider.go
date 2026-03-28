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
	"net/http"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/auth"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
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
	// The OpenAPI path item may be nil.
	HTTPHandler() (http.HandlerFunc, *openapi.PathItem)

	// BeginAuthorization starts the browser authorization flow.
	BeginAuthorization(context.Context, AuthorizationRequest) (*AuthorizationResponse, error)

	// ExchangeAuthorizationCode converts a code into a normalized identity,
	// which can be inserted into the database and used to issue local session tokens.
	ExchangeAuthorizationCode(context.Context, ExchangeRequest) (*schema.IdentityInsert, error)
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type AuthorizationRequest struct {
	RedirectURL         string
	ProviderURL         string
	State               string
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	LoginHint           string
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
