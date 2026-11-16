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

// Package provider has the interfaces of the providers people sign in with,
// such as Google, GitHub and LDAP, which exchange what proves who someone
// is for an identity.
package provider

import (
	"context"
	"encoding/json"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	credential "github.com/mutablelogic/go-auth/credential"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// Provider is signed in with, and exchanges a credential for an identity:
// an error, which is not authorized when the credential isn't right, or
// the identity of the person it's for
type Provider interface {
	// Meta describes the provider, for anyone to see
	Meta() schema.ProviderMeta

	// Exchange returns the identity a credential is for
	Exchange(ctx context.Context, credential schema.Credential) (*schema.Identity, error)
}

// RedirectProvider is a provider which is signed in with at its own pages,
// such as Google's, which redirect back with a code, which is exchanged
type RedirectProvider interface {
	Provider

	// AuthCodeURL returns the URL of the provider's sign-in page, which
	// redirects to the redirect URL with a code, and the state, when the
	// person has signed in. The code is only exchanged with the verifier,
	// as PKCE.
	AuthCodeURL(ctx context.Context, redirectURL, state, verifier string) (string, error)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// NewVerifier returns a new PKCE verifier, or state, which is random
func NewVerifier() string {
	return oauth2.GenerateVerifier()
}

// Client returns the OAuth client which is the credential's value, at the
// key, which needs a client ID. It's read each time it's needed, so a
// changed secret is used without a restart.
func Client(ctx context.Context, credentials credential.CredentialProvider, key string) (*schema.OAuthClient, error) {
	if credentials == nil || key == "" {
		return nil, httpresponse.ErrInternalError.With("No credential of the OAuth client")
	}
	value, err := credentials.Get(ctx, key)
	if err != nil {
		return nil, httpresponse.ErrInternalError.Withf("The OAuth client's credential %q: %v", key, err)
	}
	var client schema.OAuthClient
	if err := json.Unmarshal(value, &client); err != nil || client.ClientID == "" {
		return nil, httpresponse.ErrInternalError.Withf("The credential %q isn't an OAuth client, with a client_id and client_secret", key)
	}
	return &client, nil
}
