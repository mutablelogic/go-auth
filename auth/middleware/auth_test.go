// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	localprovider "github.com/mutablelogic/go-auth/auth/provider/local"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	pg "github.com/mutablelogic/go-pg"
	test "github.com/mutablelogic/go-pg/pkg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

var conn test.Conn

func TestMain(m *testing.M) {
	test.Main(m, func(pool pg.PoolConn) (func(), error) {
		conn = test.Conn{PoolConn: pool}
		return nil, nil
	})
}

func Test_auth_001(t *testing.T) {
	t.Run("BearerToken", func(t *testing.T) {
		assert := assert.New(t)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		_, ok := bearerToken(req)
		assert.False(ok)

		req.Header.Set("Authorization", "Bearer token-value")
		token, ok := bearerToken(req)
		assert.True(ok)
		assert.Equal("token-value", token)

		req.Header.Set("Authorization", "Basic token-value")
		_, ok = bearerToken(req)
		assert.False(ok)

		req.Header.Set("Authorization", "Bearer   ")
		_, ok = bearerToken(req)
		assert.False(ok)
	})

	t.Run("ContextHelpers", func(t *testing.T) {
		assert := assert.New(t)

		user := &schema.UserInfo{Sub: schema.UserID(uuid.New())}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.Sub, ExpiresAt: time.Now().Add(time.Minute)}

		ctx := withAuthContext(context.Background(), user, session)
		gotUser := UserFromContext(ctx)
		assert.Equal(user, gotUser)
		gotSession := SessionFromContext(ctx)
		assert.Equal(session, gotSession)
	})

	t.Run("NewMiddlewareRejectsInvalidTokenWithoutConfiguredIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		handler := AuthN(&manager.Manager{})(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer anything")
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusInternalServerError, res.Code)
		assert.Contains(res.Body.String(), "issuer is not configured")
		assert.Empty(res.Header().Get("WWW-Authenticate"))
	})

	t.Run("NewMiddlewareSetsAuthenticateHeaderWhenBearerMissing", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Header().Get("WWW-Authenticate"), `Bearer error="invalid_request"`)
		assert.Contains(res.Header().Get("WWW-Authenticate"), `error_description="missing bearer token or API key"`)
		assert.Contains(res.Header().Get("WWW-Authenticate"), `resource_metadata="`+issuer+`/.well-known/oauth-protected-resource"`)
	})

	t.Run("NewMiddlewareAllowsValidAPIKeyAndSetsContext", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newMiddlewareTestManager(t)
		status := schema.UserStatusActive
		user, err := mgr.CreateUser(context.Background(), schema.UserMeta{
			Name:   "API Key User",
			Email:  "apikey@example.com",
			Status: &status,
		}, nil)
		require.NoError(err)

		key, err := mgr.CreateKey(context.Background(), user.ID, schema.KeyMeta{Name: "middleware-key"})
		require.NoError(err)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) {
			gotUser := UserFromContext(r.Context())
			require.NotNil(gotUser)
			assert.Equal(user.ID, gotUser.Sub)

			gotKey := KeyFromContext(r.Context())
			require.NotNil(gotKey)
			assert.Equal(key.ID, gotKey.ID)
			assert.Nil(SessionFromContext(r.Context()))
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-API-Key", key.Token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusNoContent, res.Code)
	})

	t.Run("NewMiddlewareAllowsValidTokenAndSetsContext", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive)}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now()}
		token := mustSignToken(t, mgr, issuer, user, session)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) {
			gotUser := UserFromContext(r.Context())
			require.NotNil(gotUser)
			assert.Equal(user.ID, gotUser.Sub)
			assert.Equal(user.Email, gotUser.Email)
			assert.Equal(user.Name, gotUser.Name)
			assert.Equal(user.Groups, gotUser.Groups)
			assert.Equal(user.Scopes, gotUser.Scopes)
			gotSession := SessionFromContext(r.Context())
			require.NotNil(gotSession)
			assert.Equal(session.ID, gotSession.ID)
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusNoContent, res.Code)
	})

	t.Run("NewMiddlewareRejectsWrongIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive)}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now()}
		token := mustSignToken(t, mgr, "https://wrong.example.test/api", user, session)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "issuer")
		assert.Contains(res.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
		assert.Contains(res.Header().Get("WWW-Authenticate"), `error_description=`)
		assert.Contains(res.Header().Get("WWW-Authenticate"), `resource_metadata="`+issuer+`/.well-known/oauth-protected-resource"`)
	})

	t.Run("NewMiddlewareRejectsExpiredSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive)}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now()}
		claims := jwt.MapClaims{
			"iss":     issuer,
			"sub":     uuid.UUID(user.ID).String(),
			"sid":     uuid.UUID(session.ID).String(),
			"iat":     time.Now().UTC().Unix(),
			"nbf":     time.Now().UTC().Unix(),
			"exp":     time.Now().UTC().Add(15 * time.Minute).Unix(),
			"user":    user,
			"session": session,
		}
		token, err := mgr.OIDCSign(claims)
		require.NoError(err)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "session is expired")
	})

	t.Run("NewMiddlewareRejectsRefreshToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive)}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(15 * time.Minute), RefreshExpiresAt: time.Now().Add(24 * time.Hour), RefreshCounter: 1, CreatedAt: time.Now()}
		claims := jwt.MapClaims{
			"iss":             issuer,
			"sub":             uuid.UUID(user.ID).String(),
			"sid":             uuid.UUID(session.ID).String(),
			"iat":             time.Now().UTC().Unix(),
			"nbf":             time.Now().UTC().Unix(),
			"exp":             session.RefreshExpiresAt.UTC().Unix(),
			"token_use":       "refresh",
			"refresh_counter": session.RefreshCounter,
		}
		token, err := mgr.OIDCSign(claims)
		require.NoError(err)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "token token_use must be")
		assert.Contains(res.Header().Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
		assert.Contains(res.Header().Get("WWW-Authenticate"), `error_description="Bad Request: token token_use must be \"access\""`)
	})

	t.Run("NewMiddlewareAllowsLegacyTokenWithoutTokenUse", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive)}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now()}
		token := mustSignToken(t, mgr, issuer, user, session)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusNoContent, res.Code)
		assert.Empty(res.Body.String())
	})

	t.Run("NewMiddlewareRejectsExpiredUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		expiredAt := time.Now().Add(-time.Minute)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive), ExpiresAt: &expiredAt}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now()}
		token := mustSignToken(t, mgr, issuer, user, session)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "user is expired")
	})

	t.Run("NewMiddlewareRejectsInactiveUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusInactive)}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now()}
		token := mustSignToken(t, mgr, issuer, user, session)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "user is not active")
	})

	t.Run("NewMiddlewareRejectsMissingEmbeddedSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive)}}
		claims := jwt.MapClaims{
			"iss":  issuer,
			"sub":  uuid.UUID(user.ID).String(),
			"sid":  uuid.NewString(),
			"iat":  time.Now().UTC().Unix(),
			"nbf":  time.Now().UTC().Unix(),
			"exp":  time.Now().UTC().Add(15 * time.Minute).Unix(),
			"user": user,
		}
		token, err := mgr.OIDCSign(claims)
		require.NoError(err)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "missing session claim")
	})

	t.Run("NewMiddlewareRejectsRevokedSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		revokedAt := time.Now().UTC()
		user := &schema.User{ID: schema.UserID(uuid.New()), UserMeta: schema.UserMeta{Name: "Test User", Email: "test@example.com", Status: ptr(schema.UserStatusActive)}}
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: user.ID, ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now(), SessionMeta: schema.SessionMeta{RevokedAt: &revokedAt}}
		token := mustSignToken(t, mgr, issuer, user, session)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "session is revoked")
	})

	t.Run("NewMiddlewareRejectsMissingEmbeddedUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newMiddlewareTestManager(t)
		session := &schema.Session{ID: schema.SessionID(uuid.New()), User: schema.UserID(uuid.New()), ExpiresAt: time.Now().Add(15 * time.Minute), CreatedAt: time.Now()}
		claims := jwt.MapClaims{
			"iss":     issuer,
			"sub":     uuid.NewString(),
			"sid":     uuid.UUID(session.ID).String(),
			"iat":     time.Now().UTC().Unix(),
			"nbf":     time.Now().UTC().Unix(),
			"exp":     time.Now().UTC().Add(15 * time.Minute).Unix(),
			"session": session,
		}
		token, err := mgr.OIDCSign(claims)
		require.NoError(err)

		handler := AuthN(mgr)(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		handler(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "missing user claim")
	})
}

func newMiddlewareTestManager(t *testing.T) (*manager.Manager, string) {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	issuer := "http://localhost:8084/api"
	localProvider, err := localprovider.New(issuer, key)
	require.NoError(t, err)
	mgr, err := manager.New(
		context.Background(),
		c,
		"middleware",
		"test",
		manager.WithIssuer(issuer),
		manager.WithSigner("local-main", key),
		manager.WithProvider(localProvider),
	)
	require.NoError(t, err)
	return mgr, issuer
}

func mustSignToken(t *testing.T, mgr *manager.Manager, issuer string, user *schema.User, session *schema.Session) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":     issuer,
		"sub":     uuid.UUID(user.ID).String(),
		"sid":     uuid.UUID(session.ID).String(),
		"iat":     time.Now().UTC().Unix(),
		"nbf":     time.Now().UTC().Unix(),
		"exp":     session.ExpiresAt.UTC().Unix(),
		"user":    user,
		"session": session,
	}
	token, err := mgr.OIDCSign(claims)
	require.NoError(t, err)
	return token
}

func ptr[T any](v T) *T {
	return &v
}
