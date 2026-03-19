package httphandler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	middleware "github.com/djthorpe/go-auth/pkg/middleware"
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	test "github.com/mutablelogic/go-pg/pkg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

var conn test.Conn

func TestMain(m *testing.M) {
	test.Main(m, &conn)
}

func Test_http_001(t *testing.T) {
	t.Run("AuthHandlerSuccess", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		prevValidate := validateTokenRequest
		prevIdentity := newIdentityFromClaims
		defer func() {
			validateTokenRequest = prevValidate
			newIdentityFromClaims = prevIdentity
		}()

		validateTokenRequest = func(ctx context.Context, req *schema.TokenRequest) (map[string]any, error) {
			return map[string]any{
				"iss":   "https://accounts.google.com",
				"sub":   "auth-handler-success",
				"email": "auth.handler.success@example.com",
				"name":  "Auth Handler Success",
			}, nil
		}
		newIdentityFromClaims = schema.NewIdentityFromClaims

		_, handler, _ := AuthHandler(mgr)
		res := httptest.NewRecorder()
		body := mustJSONBody(t, schema.TokenRequest{Provider: schema.ProviderOAuth, Token: "upstream-token"})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		req.Host = "localhost:8084"
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response schema.TokenResponse
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.NotEmpty(response.Token)
		assert.Equal("auth.handler.success@example.com", response.User.Email)
		assert.Equal(issuer, mustExtractIssuer(t, response.Token))
	})

	t.Run("AuthHandlerValidateFailure", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		prevValidate := validateTokenRequest
		defer func() { validateTokenRequest = prevValidate }()
		validateTokenRequest = func(ctx context.Context, req *schema.TokenRequest) (map[string]any, error) {
			return nil, errors.New("boom")
		}

		_, handler, _ := AuthHandler(mgr)
		res := httptest.NewRecorder()
		body := mustJSONBody(t, schema.TokenRequest{Provider: schema.ProviderOAuth, Token: "upstream-token"})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "boom")
	})

	t.Run("AuthHandlerRejectsUnsupportedProvider", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := AuthHandler(mgr)
		res := httptest.NewRecorder()
		body := mustJSONBody(t, schema.TokenRequest{Provider: "unknown", Token: "abc"})
		req := httptest.NewRequest(http.MethodPost, "/auth/login", body)
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "unsupported provider")
	})

	t.Run("ConfigHandlerReturnsIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		_, handler, _ := ConfigHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
		req.Host = "localhost:8084"

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response map[string]any
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.Equal(issuer, response["issuer"])
	})

	t.Run("JWKSHandlerReturnsKeys", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := JWKSHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response map[string]any
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		keys, ok := response["keys"].([]any)
		require.True(ok)
		assert.NotEmpty(keys)
	})

	t.Run("ProtectedUserRejectsMissingBearer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		user, _, token := mustLoginToken(t, mgr, issuer)
		_ = token

		_, handler, _ := UserItemHandler(mgr)
		protected := middleware.NewMiddleware(mgr)(handler)

		req := httptest.NewRequest(http.MethodGet, "/user/"+uuid.UUID(user.ID).String(), nil)
		req.SetPathValue("user", uuid.UUID(user.ID).String())
		res := httptest.NewRecorder()

		protected(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "missing bearer token")
	})

	t.Run("UserHandlerCreateAndList", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := UserHandler(mgr)

		createRes := httptest.NewRecorder()
		createReq := httptest.NewRequest(http.MethodPost, "/user", mustJSONBody(t, schema.UserMeta{
			Name:  "Created User",
			Email: "created.user@example.com",
		}))
		createReq.Header.Set("Content-Type", "application/json")
		handler(createRes, createReq)

		require.Equal(http.StatusCreated, createRes.Code)
		var created schema.User
		require.NoError(json.Unmarshal(createRes.Body.Bytes(), &created))
		assert.Equal("created.user@example.com", created.Email)

		listRes := httptest.NewRecorder()
		listReq := httptest.NewRequest(http.MethodGet, "/user?email=created.user@example.com", nil)
		handler(listRes, listReq)

		require.Equal(http.StatusOK, listRes.Code)
		var list schema.UserList
		require.NoError(json.Unmarshal(listRes.Body.Bytes(), &list))
		assert.NotEmpty(list.Body)
	})

	t.Run("ProtectedUserRejectsWrongIssuer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		user, session := mustLoginSession(t, mgr)
		token, err := mgr.OIDCSign(loginTokenClaims("https://wrong.example.test/api", user, session))
		require.NoError(err)

		_, handler, _ := UserItemHandler(mgr)
		protected := middleware.NewMiddleware(mgr)(handler)

		req := httptest.NewRequest(http.MethodGet, "/user/"+uuid.UUID(user.ID).String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.SetPathValue("user", uuid.UUID(user.ID).String())
		res := httptest.NewRecorder()

		protected(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "issuer")
	})

	t.Run("ProtectedUserRejectsInvalidSessionBinding", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		user, session := mustLoginSession(t, mgr)
		session.User = schema.UserID(uuid.New())
		token, err := mgr.OIDCSign(loginTokenClaims(issuer, user, session))
		require.NoError(err)

		_, handler, _ := UserItemHandler(mgr)
		protected := middleware.NewMiddleware(mgr)(handler)

		req := httptest.NewRequest(http.MethodGet, "/user/"+uuid.UUID(user.ID).String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.SetPathValue("user", uuid.UUID(user.ID).String())
		res := httptest.NewRecorder()

		protected(res, req)

		require.Equal(http.StatusUnauthorized, res.Code)
		assert.Contains(res.Body.String(), "session does not match")
	})

	t.Run("ProtectedUserAllowsValidToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		user, _, token := mustLoginToken(t, mgr, issuer)

		_, handler, _ := UserItemHandler(mgr)
		protected := middleware.NewMiddleware(mgr)(handler)

		req := httptest.NewRequest(http.MethodGet, "/user/"+uuid.UUID(user.ID).String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.SetPathValue("user", uuid.UUID(user.ID).String())
		res := httptest.NewRecorder()

		protected(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response schema.User
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.Equal(user.ID, response.ID)
	})

	t.Run("UserItemHandlerUpdateAndDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		user, _ := mustLoginSession(t, mgr)
		_, handler, _ := UserItemHandler(mgr)

		patchRes := httptest.NewRecorder()
		patchReq := httptest.NewRequest(http.MethodPatch, "/user/"+uuid.UUID(user.ID).String(), mustJSONBody(t, schema.UserMeta{
			Name:  "Updated User",
			Email: user.Email,
		}))
		patchReq.Header.Set("Content-Type", "application/json")
		patchReq.SetPathValue("user", uuid.UUID(user.ID).String())
		handler(patchRes, patchReq)

		require.Equal(http.StatusOK, patchRes.Code)
		var updated schema.User
		require.NoError(json.Unmarshal(patchRes.Body.Bytes(), &updated))
		assert.Equal("Updated User", updated.Name)

		deleteRes := httptest.NewRecorder()
		deleteReq := httptest.NewRequest(http.MethodDelete, "/user/"+uuid.UUID(user.ID).String(), nil)
		deleteReq.SetPathValue("user", uuid.UUID(user.ID).String())
		handler(deleteRes, deleteReq)

		require.Equal(http.StatusNoContent, deleteRes.Code)

		getRes := httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, "/user/"+uuid.UUID(user.ID).String(), nil)
		getReq.SetPathValue("user", uuid.UUID(user.ID).String())
		handler(getRes, getReq)
		require.Equal(http.StatusNotFound, getRes.Code)
	})

	t.Run("RefreshHandlerReturnsRefreshedToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		user, session, token := mustLoginToken(t, mgr, issuer)

		_, handler, _ := RefreshHandler(mgr)
		res := httptest.NewRecorder()
		body := mustJSONBody(t, schema.RefreshRequest{Token: token})
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", body)
		req.Host = "localhost:8084"
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response schema.TokenResponse
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.NotEmpty(response.Token)
		assert.Equal(user.ID, response.User.ID)
		assert.Equal(session.ID, response.Session.ID)
		assert.True(response.Session.ExpiresAt.After(session.ExpiresAt))
	})

	t.Run("RevokeHandlerReturnsRevokedSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		_, session, token := mustLoginToken(t, mgr, issuer)

		_, handler, _ := RevokeHandler(mgr)
		res := httptest.NewRecorder()
		body := mustJSONBody(t, schema.RefreshRequest{Token: token})
		req := httptest.NewRequest(http.MethodPost, "/auth/revoke", body)
		req.Host = "localhost:8084"
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response schema.Session
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.Equal(session.ID, response.ID)
		require.NotNil(response.RevokedAt)
		assert.False(response.RevokedAt.IsZero())
	})
}

func mustExtractIssuer(t *testing.T, token string) string {
	t.Helper()
	claims, err := newHTTPTestManagerForToken(t, token)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := claims["iss"].(string)
	return issuer
}

func newHTTPTestManagerForToken(t *testing.T, token string) (map[string]any, error) {
	t.Helper()
	parts := bytes.Split([]byte(token), []byte("."))
	if len(parts) < 2 {
		return nil, errors.New("invalid token")
	}
	data := parts[1]
	decoded := make([]byte, len(data)*2)
	// raw URL encoding without padding
	n, err := base64.RawURLEncoding.Decode(decoded, data)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{}
	if err := json.Unmarshal(decoded[:n], &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func newHTTPTestManager(t *testing.T) (*manager.Manager, string) {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	issuer := "http://localhost:8084/api"
	mgr, err := manager.New(
		context.Background(),
		c,
		manager.WithPrivateKey(key),
		manager.WithIssuer(issuer),
		manager.WithSessionTTL(15*time.Minute),
	)
	require.NoError(t, err)
	require.NoError(t, mgr.Exec(context.Background(), "TRUNCATE auth.user CASCADE"))

	return mgr, issuer
}

func mustLoginSession(t *testing.T, mgr *manager.Manager) (*schema.User, *schema.Session) {
	t.Helper()

	user, session, err := mgr.LoginWithIdentity(context.Background(), schema.IdentityInsert{
		IdentityKey: schema.IdentityKey{
			Provider: "https://accounts.google.com",
			Sub:      uuid.NewString(),
		},
		IdentityMeta: schema.IdentityMeta{
			Email: "http-test-" + uuid.NewString() + "@example.com",
			Claims: map[string]any{
				"name":  "HTTP Test User",
				"email": "http-test@example.com",
			},
		},
	})
	require.NoError(t, err)
	return user, session
}

func mustLoginToken(t *testing.T, mgr *manager.Manager, issuer string) (*schema.User, *schema.Session, string) {
	t.Helper()
	user, session := mustLoginSession(t, mgr)
	token, err := mgr.OIDCSign(loginTokenClaims(issuer, user, session))
	require.NoError(t, err)
	return user, session, token
}

func mustJSONBody(t *testing.T, value any) *bytes.Reader {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return bytes.NewReader(data)
}
