package oidc_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestVerifySignedToken(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := mustVerifyRSAKey(t)
		token, err := oidc.SignToken(key, jwt.MapClaims{
			"iss": "https://issuer.example.com",
			"sub": "alice",
		})
		require.NoError(err)

		claims, err := oidc.VerifySignedToken(&key.PublicKey, token, "https://issuer.example.com")
		require.NoError(err)
		assert.Equal("alice", claims["sub"])
	})

	t.Run("MissingKey", func(t *testing.T) {
		assert := assert.New(t)
		claims, err := oidc.VerifySignedToken(nil, "token", "https://issuer.example.com")
		assert.Nil(claims)
		assert.Error(err)
	})

	t.Run("WrongAlgorithm", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := mustVerifyRSAKey(t)
		token, err := oidc.SignToken(nil, jwt.MapClaims{"iss": "https://issuer.example.com"})
		require.NoError(err)

		claims, err := oidc.VerifySignedToken(&key.PublicKey, token, "https://issuer.example.com")
		assert.Nil(claims)
		assert.Error(err)
		assert.Contains(err.Error(), "unexpected signing algorithm")
	})

	t.Run("IssuerMismatch", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := mustVerifyRSAKey(t)
		token, err := oidc.SignToken(key, jwt.MapClaims{"iss": "https://issuer.example.com"})
		require.NoError(err)

		claims, err := oidc.VerifySignedToken(&key.PublicKey, token, "https://wrong.example.com")
		assert.Nil(claims)
		assert.Error(err)
		assert.Contains(err.Error(), "issuer does not match")
	})
}

func TestVerifyToken(t *testing.T) {
	t.Run("DiscoveryAndJWKS", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := mustVerifyRSAKey(t)
		server, issuer := newOIDCTestServer(t, key)
		defer server.Close()

		token, err := oidc.IssueToken(key, jwt.MapClaims{
			"iss": issuer,
			"sub": "alice",
		})
		require.NoError(err)

		claims, err := oidc.VerifyToken(context.Background(), token)
		require.NoError(err)
		assert.Equal(issuer, claims["iss"])
		assert.Equal("alice", claims["sub"])
	})

	t.Run("BadToken", func(t *testing.T) {
		assert := assert.New(t)
		claims, err := oidc.VerifyToken(context.Background(), "not-a-jwt")
		assert.Nil(claims)
		assert.Error(err)
	})
}

func newOIDCTestServer(t *testing.T, key *rsa.PrivateKey) (*httptest.Server, string) {
	t.Helper()

	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":   issuer,
				"jwks_uri": issuer + "/.well-known/jwks.json",
			}))
		case "/.well-known/jwks.json":
			jwks, err := oidc.PublicJWKSet(key)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(jwks))
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = server.URL

	return server, issuer
}

func mustVerifyRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}
