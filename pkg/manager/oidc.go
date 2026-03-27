package manager

import (
	"net/http"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
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
func (m *Manager) OIDCIssuer() (string, error) {
	if provider, ok := m.providers[schema.ProviderKeyLocal]; ok && provider != nil {
		if issuer := strings.TrimSpace(provider.PublicConfig().Issuer); issuer != "" {
			return issuer, nil
		}
	}
	return "", auth.ErrBadParameter.With("issuer is not configured")
}

func (m *Manager) OIDCConfig(r *http.Request) (oidc.OIDCConfiguration, error) {
	issuer, err := m.OIDCIssuer()
	if err != nil {
		return oidc.OIDCConfiguration{}, err
	}
	return oidc.OIDCConfiguration{
		BaseConfiguration: oidc.BaseConfiguration{
			Issuer:                issuer,
			AuthorizationEndpoint: oidc.AuthorizationURL(issuer),
			TokenEndpoint:         oidc.AuthCodeURL(issuer),
			RevocationEndpoint:    oidc.AuthRevokeURL(issuer),
			ResponseTypes:         []string{oidc.ResponseTypeCode},
			GrantTypesSupported:   []string{"authorization_code", "refresh_token"},
			ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
			CodeChallengeMethods:  []string{oidc.CodeChallengeMethodS256},
		},
		UserInfoEndpoint:  oidc.UserInfoURL(issuer),
		JwksURI:           oidc.JWKSURL(issuer),
		SigningAlgorithms: []string{oidc.SigningAlgorithm},
		SubjectTypes:      []string{"public"},
		ClaimsSupported:   []string{"iss", "sub", "sid", "aud", "exp", "iat", "nbf", "email", "email_verified", "name", "groups", "scopes", "user", "session"},
	}, nil
}

// ProtectedResourceMetadata returns OAuth protected-resource metadata for this server.
func (m *Manager) ProtectedResourceMetadata(r *http.Request) (oidc.ProtectedResourceMetadata, error) {
	issuer, err := m.OIDCIssuer()
	if err != nil {
		return oidc.ProtectedResourceMetadata{}, err
	}
	return oidc.ProtectedResourceMetadata{
		Resource:               issuer,
		AuthorizationServers:   []string{issuer},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "go-auth",
	}, nil
}
