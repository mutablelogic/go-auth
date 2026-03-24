package manager_test

import (
	"crypto/rsa"
	"fmt"
	"testing"

	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestOIDCJWKSet(t *testing.T) {
	key := mustRSAKey(t)

	jwks, err := oidc.PublicJWKSet(key)
	require.NoError(t, err)

	require.Equal(t, 1, jwks.Len())
	entry, ok := jwks.LookupKeyID(oidc.KeyID)
	require.True(t, ok)
	alg, ok := entry.Get("alg")
	require.True(t, ok)
	assert.Equal(t, oidc.SigningAlgorithm, fmt.Sprint(alg))
}

func TestPublicJWKSetRequiresKey(t *testing.T) {
	_, err := oidc.PublicJWKSet(nil)
	require.Error(t, err)
}

func TestManagerOIDCSignRequiresKey(t *testing.T) {
	mgr := new(manager.Manager)
	_, err := mgr.OIDCSign(jwt.MapClaims{"iss": "https://issuer.example.com"})
	require.Error(t, err)
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}
