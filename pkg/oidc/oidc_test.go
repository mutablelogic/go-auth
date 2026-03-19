package oidc_test

import (
	"fmt"
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "alice",
	}

	token, err := oidc.SignToken(key, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		assert.Equal(t, oidc.SigningAlgorithm, token.Method.Alg())
		assert.Equal(t, oidc.KeyID, token.Header["kid"])
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Equal(t, oidc.KeyID, parsed.Header["kid"])
}

func TestSignWithoutKeyUsesNoneAlgorithm(t *testing.T) {
	token, err := oidc.SignToken(nil, jwt.MapClaims{"iss": "https://issuer.example.com"})
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		assert.Equal(t, jwt.SigningMethodNone.Alg(), token.Method.Alg())
		_, exists := token.Header["kid"]
		assert.False(t, exists)
		return jwt.UnsafeAllowNoneSignatureType, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestIssueToken(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	claims := jwt.MapClaims{"sub": "alice"}
	claims["iss"] = "https://issuer.example.com"
	token, err := oidc.IssueToken(key, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, "https://issuer.example.com", claims["iss"])
	assert.Contains(t, claims, "iat")
	assert.Contains(t, claims, "nbf")
	assert.Contains(t, claims, "exp")
}

func TestIssueTokenRequiresIssuer(t *testing.T) {
	_, err := oidc.IssueToken(nil, jwt.MapClaims{"sub": "alice"})
	require.Error(t, err)
}

func TestSignTokenRequiresClaims(t *testing.T) {
	_, err := oidc.SignToken(nil, nil)
	require.Error(t, err)
}

func TestPublicJWKSet(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	jwks, err := oidc.PublicJWKSet(key)
	require.NoError(t, err)

	require.Equal(t, 1, jwks.Len())
	entry, ok := jwks.LookupKeyID(oidc.KeyID)
	require.True(t, ok)

	alg, ok := entry.Get(jwk.AlgorithmKey)
	require.True(t, ok)
	use, ok := entry.Get(jwk.KeyUsageKey)
	require.True(t, ok)
	kty, ok := entry.Get(jwk.KeyTypeKey)
	require.True(t, ok)
	n, ok := entry.Get("n")
	require.True(t, ok)
	e, ok := entry.Get("e")
	require.True(t, ok)

	assert.Equal(t, oidc.SigningAlgorithm, fmt.Sprint(alg))
	assert.Equal(t, "sig", fmt.Sprint(use))
	assert.Equal(t, "RSA", fmt.Sprint(kty))
	assert.NotEmpty(t, n)
	assert.NotEmpty(t, e)
}
