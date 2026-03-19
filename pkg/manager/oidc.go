package manager

import (
	// Packages
	"net/http"
	"strings"

	auth "github.com/djthorpe/go-auth"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
)

const authPath = "/auth/login"
const refreshPath = "/auth/refresh"

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

func (m *Manager) OIDCConfig(r *http.Request) (oidc.Configuration, error) {
	return oidc.Configuration{
		Issuer:            issuerFromRequest(r),
		JwksURI:           issuerFromRequest(r) + "/" + oidc.JWKSPath,
		SigningAlgorithms: []string{oidc.SigningAlgorithm},
		SubjectTypes:      []string{"public"},
		ResponseTypes:     []string{"id_token"},
		ClaimsSupported:   []string{"iss", "sub", "sid", "aud", "exp", "iat", "nbf", "email", "email_verified", "name", "groups", "scopes", "user", "session"},
	}, nil
}

func issuerFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	path := r.URL.Path
	for _, suffix := range []string{"/" + oidc.ConfigPath, "/" + oidc.JWKSPath, authPath, refreshPath} {
		path = strings.TrimSuffix(path, suffix)
	}
	return scheme + "://" + r.Host + path
}
