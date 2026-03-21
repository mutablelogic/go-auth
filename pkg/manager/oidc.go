package manager

import (
	"net/http"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// OIDCJWKSet returns the public JSON Web Key Set for the manager's signing key.
func (m *Manager) OIDCJWKSet() (jwk.Set, error) {
	return oidc.PublicJWKSet(m.privateKey)
}

// OIDCSign signs the supplied claims with the manager's configured private key.
// It returns an error if no signing key has been configured.
func (m *Manager) OIDCSign(claims jwt.Claims) (string, error) {
	if m.privateKey == nil {
		return "", auth.ErrBadParameter.With("private key is required for signing")
	}
	return oidc.SignToken(m.privateKey, claims)
}

// OIDCVerify verifies a locally signed JWT using the manager's configured
// signing key and expected issuer.
func (m *Manager) OIDCVerify(token, issuer string) (map[string]any, error) {
	if m.privateKey == nil {
		return nil, auth.ErrBadParameter.With("private key is required for verification")
	}
	return oidc.VerifySignedToken(&m.privateKey.PublicKey, token, issuer)
}

// OIDCIssuer returns the canonical issuer for locally signed tokens.
func (m *Manager) OIDCIssuer(r *http.Request) (string, error) {
	if config, ok := m.oauth[oidc.OAuthClientKeyLocal]; ok {
		if issuer := strings.TrimSpace(config.Issuer); issuer != "" {
			return issuer, nil
		}
	}
	_ = r
	return "", auth.ErrBadParameter.With("issuer is not configured")
}

func (m *Manager) OIDCConfig(r *http.Request) (oidc.Configuration, error) {
	issuer, err := m.OIDCIssuer(r)
	if err != nil {
		return oidc.Configuration{}, err
	}
	return oidc.Configuration{
		Issuer:            issuer,
		UserInfoEndpoint:  oidc.UserInfoURL(issuer),
		JwksURI:           oidc.JWKSURL(issuer),
		SigningAlgorithms: []string{oidc.SigningAlgorithm},
		SubjectTypes:      []string{"public"},
		ResponseTypes:     []string{"id_token"},
		ScopesSupported:   []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		ClaimsSupported:   []string{"iss", "sub", "sid", "aud", "exp", "iat", "nbf", "email", "email_verified", "name", "groups", "scopes", "user", "session"},
	}, nil
}

// AuthConfig returns the shareable upstream provider configuration exposed by
// /auth/config. The client secret remains server-side.

func (m *Manager) AuthConfig() (oidc.PublicClientConfigurations, error) {
	if len(m.oauth) == 0 {
		return nil, auth.ErrNotFound.With("oauth clients are not configured")
	}
	return m.oauth.Public(), nil
}
