package manager

import (
	"crypto/tls"
	"net/http"
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	jwt "github.com/golang-jwt/jwt/v5"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_oidc_internal_001(t *testing.T) {
	t.Run("OIDCIssuerConfigured", func(t *testing.T) {
		assert := assert.New(t)

		mgr := &Manager{opt: opt{issuer: "https://issuer.example.test/api"}}
		issuer, err := mgr.OIDCIssuer(nil)
		assert.NoError(err)
		assert.Equal("https://issuer.example.test/api", issuer)
	})

	t.Run("OIDCIssuerMissingWithoutRequest", func(t *testing.T) {
		assert := assert.New(t)

		mgr := &Manager{}
		_, err := mgr.OIDCIssuer(nil)
		assert.Error(err)
		assert.Contains(err.Error(), "issuer is not configured")
	})

	t.Run("OIDCIssuerDerivedFromRequest", func(t *testing.T) {
		assert := assert.New(t)

		mgr := &Manager{}
		req := httptestRequest("http", "example.test", "/api/auth/login")
		issuer, err := mgr.OIDCIssuer(req)
		assert.NoError(err)
		assert.Equal("http://example.test/api", issuer)
	})

	t.Run("OIDCConfigUsesConfiguredIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := &Manager{opt: opt{issuer: "https://issuer.example.test/api"}}
		cfg, err := mgr.OIDCConfig(nil)
		require.NoError(err)
		assert.Equal("https://issuer.example.test/api", cfg.Issuer)
		assert.Equal("https://issuer.example.test/api/.well-known/jwks.json", cfg.JwksURI)
		assert.Contains(cfg.ClaimsSupported, "session")
	})

	t.Run("IssuerFromRequestHonorsForwardedProtoAndSuffixTrim", func(t *testing.T) {
		assert := assert.New(t)

		req := httptestRequest("http", "example.test", "/api/.well-known/openid-configuration")
		req.Header.Set("X-Forwarded-Proto", "https")
		assert.Equal("https://example.test/api", issuerFromRequest(req))

		req = httptestRequest("http", "example.test", "/api/auth/revoke")
		assert.Equal("http://example.test/api", issuerFromRequest(req))

		req = httptestRequest("https", "example.test", "/api/user")
		req.TLS = &tls.ConnectionState{}
		assert.Equal("https://example.test/api/user", issuerFromRequest(req))
	})

	t.Run("OIDCVerifySuccessAndIssuerMismatch", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key, err := authcrypto.GeneratePrivateKey()
		require.NoError(err)
		mgr := &Manager{opt: opt{privateKey: key}}
		token, err := mgr.OIDCSign(jwt.MapClaims{"iss": "https://issuer.example.test/api"})
		require.NoError(err)

		claims, err := mgr.OIDCVerify(token, "https://issuer.example.test/api")
		require.NoError(err)
		assert.Equal("https://issuer.example.test/api", claims["iss"])

		_, err = mgr.OIDCVerify(token, "https://wrong.example.test/api")
		assert.Error(err)
		assert.Contains(err.Error(), "issuer")
	})

	t.Run("OIDCJWKSetRequiresKey", func(t *testing.T) {
		assert := assert.New(t)
		mgr := &Manager{}
		_, err := mgr.OIDCJWKSet()
		assert.Error(err)
	})
}

func httptestRequest(scheme, host, path string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, scheme+"://"+host+path, nil)
	req.Host = host
	return req
}
