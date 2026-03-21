package manager

import (
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_oidc_internal_001(t *testing.T) {
	t.Run("OIDCIssuerConfigured", func(t *testing.T) {
		assert := assert.New(t)

		mgr := &Manager{opt: opt{oauth: oidc.ClientConfigurations{
			oidc.OAuthClientKeyLocal: {
				PublicClientConfiguration: oidc.PublicClientConfiguration{
					Issuer:   "https://issuer.example.test/api",
					Provider: "oauth",
				},
			},
		}}}
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

	t.Run("OIDCIssuerRequiresConfiguredLocalIssuer", func(t *testing.T) {
		assert := assert.New(t)

		mgr := &Manager{}
		_, err := mgr.OIDCIssuer(nil)
		assert.Error(err)
		assert.Contains(err.Error(), "issuer is not configured")
	})

	t.Run("OIDCConfigUsesConfiguredIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := &Manager{opt: opt{oauth: oidc.ClientConfigurations{
			oidc.OAuthClientKeyLocal: {
				PublicClientConfiguration: oidc.PublicClientConfiguration{
					Issuer:   "https://issuer.example.test/api",
					Provider: "oauth",
				},
			},
		}}}
		cfg, err := mgr.OIDCConfig(nil)
		require.NoError(err)
		assert.Equal("https://issuer.example.test/api", cfg.Issuer)
		assert.Equal("https://issuer.example.test/api/.well-known/jwks.json", cfg.JwksURI)
		assert.Contains(cfg.ClaimsSupported, "session")
	})

	t.Run("AuthConfigUsesPublicGoogleConfiguration", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr := &Manager{opt: opt{oauth: oidc.ClientConfigurations{
			oidc.OAuthClientKeyLocal: {
				PublicClientConfiguration: oidc.PublicClientConfiguration{
					Issuer:   "https://issuer.example.test/api",
					Provider: "oauth",
				},
			},
			"google": {
				PublicClientConfiguration: oidc.PublicClientConfiguration{
					Issuer:   oidc.GoogleIssuer,
					ClientID: "google-client-id",
					Provider: "oauth",
				},
				ClientSecret: "google-client-secret",
			},
		}}}
		cfg, err := mgr.AuthConfig()
		require.NoError(err)
		local, ok := cfg[oidc.OAuthClientKeyLocal]
		require.True(ok)
		assert.Equal("https://issuer.example.test/api", local.Issuer)
		assert.Equal("", local.ClientID)
		assert.Equal("oauth", local.Provider)
		google, ok := cfg["google"]
		require.True(ok)
		assert.Equal(oidc.GoogleIssuer, google.Issuer)
		assert.Equal("google-client-id", google.ClientID)
		assert.Equal("oauth", google.Provider)
	})

	t.Run("AuthConfigRequiresConfiguredClients", func(t *testing.T) {
		assert := assert.New(t)

		mgr := &Manager{}
		_, err := mgr.AuthConfig()
		assert.Error(err)
		assert.Contains(err.Error(), "oauth clients")
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
