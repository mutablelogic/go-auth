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
	auth "github.com/mutablelogic/go-auth"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// AuthorizationCodeRequest contains the provider key and authorization code
// that should be exchanged server-side for a verified identity token.
type AuthorizationCodeRequest struct {
	Provider     string  `json:"provider" jsonschema:"Provider key that owns the authorization code. Required when grant_type is authorization_code." example:"google"`
	Code         string  `json:"code" jsonschema:"Authorization code returned by the selected provider." example:"4/0AQSTgQExampleCode"`
	RedirectURI  string  `json:"redirect_uri" jsonschema:"Callback URI used during the authorization step. Must match the URI bound to the code." format:"uri" example:"http://127.0.0.1:8085/callback"`
	CodeVerifier string  `json:"code_verifier,omitempty" jsonschema:"PKCE verifier paired with the original code_challenge when PKCE is used." example:"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"`
	Nonce        string  `json:"nonce,omitempty" jsonschema:"Optional expected nonce for ID token validation." example:"n-0S6_WzA2Mj"`
	Meta         MetaMap `json:"meta,omitempty" jsonschema:"Optional metadata forwarded into the local login flow after identity exchange."`
}

// RefreshRequest contains a previously issued local session token.
type RefreshRequest struct {
	Token string `json:"token"`
}

// UserInfo is the client-facing authenticated identity view exposed by the
// auth APIs.
type UserInfo struct {
	Sub    UserID   `json:"sub" jsonschema:"Stable subject identifier for the authenticated local user." format:"uuid" example:"123e4567-e89b-12d3-a456-426614174000" readonly:""`
	Email  string   `json:"email,omitempty" jsonschema:"Primary email address for the authenticated user, when available." format:"email" example:"user@example.com" readonly:""`
	Name   string   `json:"name,omitempty" jsonschema:"Display name for the authenticated user, when available." example:"Example User" readonly:""`
	Groups []string `json:"groups,omitempty" jsonschema:"Group memberships associated with the authenticated user." readonly:""`
	Scopes []string `json:"scopes,omitempty" jsonschema:"Scopes granted to the current local bearer token." readonly:""`
}

// TokenResponse is returned by token-issuing auth endpoints.
type TokenResponse struct {
	Token    string    `json:"token" readonly:""`
	UserInfo *UserInfo `json:"userinfo,omitempty" readonly:""`
}

// PublicClientConfiguration contains the upstream provider details that are
// safe to expose to clients that need to initiate authentication.
type PublicClientConfiguration struct {
	Issuer   string `json:"issuer" jsonschema:"OIDC or OAuth issuer URL for the upstream provider." format:"url" example:"https://accounts.google.com"`
	ClientID string `json:"client_id,omitempty" jsonschema:"Public client identifier used when the upstream provider requires it for browser or CLI authorization requests." example:"1234567890-abcdefg.apps.googleusercontent.com"`
}

// PublicClientConfigurations contains shareable client configuration keyed by
// provider or role name.
type PublicClientConfigurations map[string]PublicClientConfiguration

func (cfg PublicClientConfigurations) String() string {
	return types.Stringify(cfg)
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// ProviderKeyLocal is the reserved provider key for the built-in local
	// issuer. When this provider is not registered, the server has no local
	// issuer and cannot mint local session tokens from the browser login flow.
	ProviderKeyLocal = "local"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewUserInfo(user *User) *UserInfo {
	if user == nil {
		return nil
	}
	return &UserInfo{
		Sub:    user.ID,
		Email:  user.Email,
		Name:   user.Name,
		Groups: user.Groups,
		Scopes: user.Scopes,
	}
}

func (req *AuthorizationCodeRequest) Validate() error {
	if req.Provider == "" {
		return auth.ErrInvalidProvider.With("provider is required")
	} else if req.Code == "" {
		return auth.ErrBadParameter.With("code is required")
	} else if req.RedirectURI == "" {
		return auth.ErrBadParameter.With("redirect_uri is required")
	}
	return nil
}
