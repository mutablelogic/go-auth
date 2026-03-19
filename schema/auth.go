package schema

import (
	"context"

	// Packages
	oidc "github.com/coreos/go-oidc/v3/oidc"
	auth "github.com/djthorpe/go-auth"
	jwt "github.com/golang-jwt/jwt/v5"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type TokenRequest struct {
	Provider string         `json:"provider"`
	Token    string         `json:"token"`
	Meta     map[string]any `json:"meta,omitempty"`
}

type OpenIDConfiguration struct {
	Issuer            string   `json:"issuer"`
	JwksURI           string   `json:"jwks_uri"`
	SigningAlgorithms []string `json:"id_token_signing_alg_values_supported"`
	SubjectTypes      []string `json:"subject_types_supported"`
	ResponseTypes     []string `json:"response_types_supported"`
	ClaimsSupported   []string `json:"claims_supported"`
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
		issuer, err := jwtIssuer(req.Token)
		if err != nil {
			return nil, err
		}
		return jwtVerify(ctx, issuer, req.Token)
	default:
		return nil, auth.ErrInvalidProvider.Withf("unsupported provider %q", req.Provider)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC FUNCTIONS

// jwtIssuer extracts the iss claim from the JWT payload without verifying the
// signature. The issuer is then used to perform OIDC discovery for verification.
func jwtIssuer(token string) (string, error) {
	claims := new(jwt.RegisteredClaims)
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return "", auth.ErrBadParameter.Withf("parse JWT: %v", err)
	}
	if claims.Issuer == "" {
		return "", auth.ErrBadParameter.With("JWT missing iss claim")
	}
	return claims.Issuer, nil
}

func jwtVerify(ctx context.Context, issuer, encrypted string) (map[string]any, error) {
	// Create a provider
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{
		SkipClientIDCheck: true,
	})

	// Verify the token and extract claims
	token, err := verifier.Verify(ctx, encrypted)
	if err != nil {
		return nil, err
	}

	var claims = map[string]any{}
	if err := token.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}
