package schema

import (
	"context"

	// Packages
	auth "github.com/djthorpe/go-auth"
	authoidc "github.com/djthorpe/go-auth/pkg/oidc"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type TokenRequest struct {
	Provider string  `json:"provider" enum:"oauth"`
	Token    string  `json:"token"`
	Meta     MetaMap `json:"meta,omitempty"`
}

// AuthorizationCodeRequest contains the upstream provider key and OAuth
// authorization code that should be exchanged server-side for a verified
// identity token.
type AuthorizationCodeRequest struct {
	Provider     string  `json:"provider"`
	Code         string  `json:"code"`
	RedirectURL  string  `json:"redirect_url"`
	CodeVerifier string  `json:"code_verifier,omitempty"`
	Nonce        string  `json:"nonce,omitempty"`
	Meta         MetaMap `json:"meta,omitempty"`
}

// RefreshRequest contains a previously issued local session token that should
// be verified and, if still eligible, refreshed.
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

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	ProviderOAuth = "oauth"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

func (req *TokenRequest) Validate(ctx context.Context) (map[string]any, error) {
	if req.Provider == "" {
		return nil, auth.ErrInvalidProvider.With("provider is required")
	} else if req.Token == "" {
		return nil, auth.ErrBadParameter.With("token is required")
	}

	switch req.Provider {
	case ProviderOAuth:
		return authoidc.VerifyToken(ctx, req.Token)
	default:
		return nil, auth.ErrInvalidProvider.Withf("unsupported provider %q", req.Provider)
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
