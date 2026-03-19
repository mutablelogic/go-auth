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
	Provider string         `json:"provider"`
	Token    string         `json:"token"`
	Meta     map[string]any `json:"meta,omitempty"`
}

// RefreshRequest contains a previously issued local session token that should
// be verified and, if still eligible, refreshed.
type RefreshRequest struct {
	Token string `json:"token"`
}

// TokenResponse is returned by the auth exchange endpoint after a provider
// token has been validated and mapped to a local user and session.
type TokenResponse struct {
	Token   string  `json:"token"`
	User    User    `json:"user"`
	Session Session `json:"session"`
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
