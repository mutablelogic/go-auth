package httpclient

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	authschema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
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

func TestClientAuthMethods(t *testing.T) {
	t.Run("LoginPostsProviderToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		key := mustRSAKey(t)
		var request authschema.TokenRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/login", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			require.Equal(authschema.ProviderOAuth, request.Provider)

			issuer, err := oidc.ExtractIssuer(request.Token)
			require.NoError(err)
			assert.Equal("https://issuer.example.test", issuer)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.TokenResponse{
				Token: "local-token",
				User: authschema.User{
					ID: authschema.UserID(uuid.New()),
					UserMeta: authschema.UserMeta{
						Name:  "Alice",
						Email: "alice@example.com",
					},
				},
				Session: authschema.Session{
					ID:   authschema.SessionID(uuid.New()),
					User: authschema.UserID(uuid.New()),
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Login(context.Background(), key, jwt.MapClaims{
			"iss":   "https://issuer.example.test",
			"email": "alice@example.com",
		})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("local-token", response.Token)
		assert.Equal("alice@example.com", response.User.Email)
	})

	t.Run("LoginRejectsMissingIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.NotFoundHandler())
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Login(context.Background(), mustRSAKey(t), jwt.MapClaims{"email": "alice@example.com"})
		require.Error(err)
		assert.Nil(response)
	})

	t.Run("RefreshPostsToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		var request authschema.RefreshRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/refresh", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			assert.Equal("refresh-token", request.Token)

			userID := authschema.UserID(uuid.New())
			now := time.Now().UTC()
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.TokenResponse{
				Token: "refreshed-token",
				User: authschema.User{
					ID:       userID,
					UserMeta: authschema.UserMeta{Email: "refresh@example.com"},
				},
				Session: authschema.Session{
					ID:        authschema.SessionID(uuid.New()),
					User:      userID,
					ExpiresAt: now.Add(time.Hour),
					CreatedAt: now,
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Refresh(context.Background(), "refresh-token")
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("refreshed-token", response.Token)
		assert.Equal("refresh@example.com", response.User.Email)
	})

	t.Run("RevokePostsToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		sessionID := authschema.SessionID(uuid.New())
		var request authschema.RefreshRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/auth/revoke", r.URL.Path)
			require.NoError(json.NewDecoder(r.Body).Decode(&request))
			assert.Equal("revoke-token", request.Token)

			revokedAt := time.Now().UTC()
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(authschema.Session{
				ID:        sessionID,
				User:      authschema.UserID(uuid.New()),
				ExpiresAt: revokedAt.Add(time.Hour),
				CreatedAt: revokedAt.Add(-time.Hour),
				SessionMeta: authschema.SessionMeta{
					RevokedAt: &revokedAt,
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Revoke(context.Background(), "revoke-token")
		require.NoError(err)
		require.NotNil(response)
		assert.Equal(sessionID, response.ID)
		require.NotNil(response.RevokedAt)
	})

	t.Run("RefreshPropagatesServerError", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad token", http.StatusBadRequest)
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)
		response, err := client.Refresh(context.Background(), "bad-token")
		require.Error(err)
		assert.Nil(response)
	})
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	return key
}
