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
	Provider     string  `json:"provider"`
	Code         string  `json:"code"`
	RedirectURL  string  `json:"redirect_url"`
	CodeVerifier string  `json:"code_verifier,omitempty"`
	Nonce        string  `json:"nonce,omitempty"`
	Meta         MetaMap `json:"meta,omitempty"`
}

// RefreshRequest contains a previously issued local session token.
type RefreshRequest struct {
	Token string `json:"token"`
}

// UserInfo is the client-facing authenticated identity view exposed by the
// auth APIs.
type UserInfo struct {
	Sub    UserID   `json:"sub" format:"uuid" readonly:""`
	Email  string   `json:"email,omitempty" readonly:""`
	Name   string   `json:"name,omitempty" readonly:""`
	Groups []string `json:"groups,omitempty" readonly:""`
	Scopes []string `json:"scopes,omitempty" readonly:""`
}

// TokenResponse is returned by token-issuing auth endpoints.
type TokenResponse struct {
	Token    string    `json:"token" readonly:""`
	UserInfo *UserInfo `json:"userinfo,omitempty" readonly:""`
}

// PublicClientConfiguration contains the upstream provider details that are
// safe to expose to clients that need to initiate authentication.
type PublicClientConfiguration struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id,omitempty"`
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
	} else if req.RedirectURL == "" {
		return auth.ErrBadParameter.With("redirect_url is required")
	}
	return nil
}
