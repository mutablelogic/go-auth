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

package schema

import (
	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Identity is who a provider says someone is, once they've signed in with
// it, which is exchanged for a session, when it's allowed. It's by the
// provider's issuer and subject, which don't change, unlike an email
// address.
type Identity struct {
	Provider      string         `json:"provider" help:"Name of the provider which was signed in with, such as google"`
	Issuer        string         `json:"iss" help:"Issuer of the identity, such as https://accounts.google.com"`
	Subject       string         `json:"sub" help:"Subject, which identifies the person at the issuer, and doesn't change"`
	Email         string         `json:"email,omitempty" help:"Email address"`
	EmailVerified bool           `json:"email_verified,omitempty" help:"Whether the issuer has verified the email address"`
	Name          string         `json:"name,omitempty" help:"Name, to show"`
	Groups        []string       `json:"groups,omitempty" help:"Groups the person is in, at the issuer, such as LDAP groups or GitHub organisations"`
	Claims        map[string]any `json:"claims,omitempty" help:"Other claims the issuer made about the person"`
}

// Credential is what's exchanged with a provider for an identity: the code
// from a redirect provider's callback, with the PKCE verifier and the
// redirect URL it was for, or the username and password for a password
// provider
type Credential struct {
	Code         string `json:"code,omitempty" help:"Authorization code, from the provider's callback"`
	CodeVerifier string `json:"code_verifier,omitempty" help:"PKCE verifier of the code"`
	RedirectURL  string `json:"redirect_uri,omitempty" help:"Redirect URL the code was for"`
	Username     string `json:"username,omitempty" help:"Username, for a password provider"`
	Password     string `json:"password,omitempty" help:"Password, for a password provider"`
}

// OAuthClient is a client's registration at a provider, such as Google or
// GitHub, which is a credential's value, so its secret is stored encrypted
type OAuthClient struct {
	ClientID     string `json:"client_id" help:"Client ID, at the provider"`
	ClientSecret string `json:"client_secret,omitempty" help:"Client secret, at the provider"`
}

// ProviderKind is how a provider is signed in with: by a redirect to the
// provider, such as Google or GitHub, or a username and password, such as
// LDAP
type ProviderKind string

// ProviderMeta describes a provider, which is safe for anyone to see, such
// as for a sign-in page
type ProviderMeta struct {
	Name  string       `json:"name" help:"Name of the provider, which is in its paths, such as google"`
	Label string       `json:"label" help:"Label, to show, such as Google"`
	Kind  ProviderKind `json:"kind" help:"How it's signed in with: redirect, or password" enum:"redirect,password"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	ProviderKindRedirect ProviderKind = "redirect"
	ProviderKindPassword ProviderKind = "password"
)

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (i Identity) String() string {
	return types.Stringify(i)
}

func (m ProviderMeta) String() string {
	return types.Stringify(m)
}

// String doesn't include the secret
func (c OAuthClient) String() string {
	safe := c
	if safe.ClientSecret != "" {
		safe.ClientSecret = "***"
	}
	return types.Stringify(safe)
}

// String doesn't include the password, or the code
func (c Credential) String() string {
	safe := c
	if safe.Password != "" {
		safe.Password = "***"
	}
	if safe.Code != "" {
		safe.Code = "***"
	}
	if safe.CodeVerifier != "" {
		safe.CodeVerifier = "***"
	}
	return types.Stringify(safe)
}
