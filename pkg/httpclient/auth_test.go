package httpclient

import (
	"crypto/rsa"
	"testing"
	"time"

	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssueToken(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		key := mustRSAKey(t)
		claims := jwt.MapClaims{
			"iss":   "https://issuer.example.com",
			"email": "alice@example.com",
		}
		before := time.Now().UTC()

		token, err := oidc.IssueToken(key, claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Contains(t, claims, "iat")
		assert.Contains(t, claims, "nbf")
		assert.Contains(t, claims, "exp")
		assert.GreaterOrEqual(t, claims["iat"], before.Unix())
		assert.GreaterOrEqual(t, claims["nbf"], before.Unix())
		assert.Greater(t, claims["exp"], claims["iat"])
	})

	t.Run("MissingClaims", func(t *testing.T) {
		_, err := oidc.IssueToken(mustRSAKey(t), nil)
		require.Error(t, err)
	})

	t.Run("MissingIssuer", func(t *testing.T) {
		_, err := oidc.IssueToken(mustRSAKey(t), jwt.MapClaims{"email": "alice@example.com"})
		require.Error(t, err)
	})

	t.Run("MissingKeyUsesNoneAlgorithm", func(t *testing.T) {
		token, err := oidc.IssueToken(nil, jwt.MapClaims{"iss": "https://issuer.example.com"})
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
			assert.Equal(t, jwt.SigningMethodNone.Alg(), token.Method.Alg())
			return jwt.UnsafeAllowNoneSignatureType, nil
		})
		require.NoError(t, err)
		assert.True(t, parsed.Valid)
	})
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}
