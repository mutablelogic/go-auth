package schema

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type TokenRequest struct {
	Provider string         `json:"provider"`
	Token    string         `json:"token"`
	Meta     map[string]any `json:"meta,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	ProviderOAuth = "oauth"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

func (req *TokenRequest) Validate() (map[string]any, error) {
	if req.Provider == "" {
		return nil, auth.ErrInvalidProvider.With("provider is required")
	} else if req.Token == "" {
		return nil, auth.ErrBadParameter.With("token is required")
	}

	switch req.Provider {
	case ProviderOAuth:
		iss, err := jwtIssuer(req.Token)
		if err != nil {
			return nil, err
		}
		return map[string]any{"iss": iss}, nil
	default:
		return nil, auth.ErrInvalidProvider.Withf("unsupported provider %q", req.Provider)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// jwtIssuer extracts the iss claim from the JWT payload without verifying the
// signature. The issuer is then used to perform OIDC discovery for verification.
func jwtIssuer(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", auth.ErrBadParameter.With("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", auth.ErrBadParameter.Withf("decode JWT payload: %v", err)
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", auth.ErrBadParameter.Withf("unmarshal JWT claims: %v", err)
	}
	if claims.Iss == "" {
		return "", auth.ErrBadParameter.With("JWT missing iss claim")
	}
	return claims.Iss, nil
}
