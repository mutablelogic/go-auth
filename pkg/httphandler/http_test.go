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
	t.Run("AuthHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := AuthHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
	})

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
		require.NotNil(response.UserInfo)
		assert.Equal("auth.handler.success@example.com", response.UserInfo.Email)
		assert.Equal(issuer, mustExtractIssuer(t, response.Token))
	})

	t.Run("UserInfoHandlerReturnsAuthenticatedUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		user, _, token := mustLoginToken(t, mgr, issuer)

		_, handler, _ := UserInfoHandler(mgr)
		protected := middleware.NewMiddleware(mgr)(handler)

		req := httptest.NewRequest(http.MethodGet, "/auth/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()

		protected(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response schema.UserInfo
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.Equal(user.ID, response.Sub)
		assert.Equal(user.Email, response.Email)
	})

	t.Run("UserInfoHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := UserInfoHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/userinfo", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
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

	t.Run("AuthHandlerIdentityFailure", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		prevValidate := validateTokenRequest
		prevIdentity := newIdentityFromClaims
		defer func() {
			validateTokenRequest = prevValidate
			newIdentityFromClaims = prevIdentity
		}()

		validateTokenRequest = func(ctx context.Context, req *schema.TokenRequest) (map[string]any, error) {
			return map[string]any{"iss": "https://accounts.google.com"}, nil
		}
		newIdentityFromClaims = schema.NewIdentityFromClaims

		_, handler, _ := AuthHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/login", mustJSONBody(t, schema.TokenRequest{Provider: schema.ProviderOAuth, Token: "upstream-token"}))
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "claims missing sub")
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

	t.Run("ConfigHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := ConfigHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/openid-configuration", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
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

	t.Run("JWKSHandlerInternalError", func(t *testing.T) {
		require := require.New(t)

		_, handler, _ := JWKSHandler(&manager.Manager{})
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

		handler(res, req)

		require.Equal(http.StatusInternalServerError, res.Code)
	})

	t.Run("JWKSHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := JWKSHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
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

	t.Run("GroupHandlerCreateAndList", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := GroupHandler(mgr)

		createRes := httptest.NewRecorder()
		description := "Created Group"
		createReq := httptest.NewRequest(http.MethodPost, "/group", mustJSONBody(t, schema.GroupInsert{
			ID: "created-group",
			GroupMeta: schema.GroupMeta{
				Description: &description,
				Scopes:      []string{"read", "write"},
			},
		}))
		createReq.Header.Set("Content-Type", "application/json")
		handler(createRes, createReq)

		require.Equal(http.StatusCreated, createRes.Code)
		var created schema.Group
		require.NoError(json.Unmarshal(createRes.Body.Bytes(), &created))
		assert.Equal("created-group", created.ID)
		if assert.NotNil(created.Description) {
			assert.Equal(description, *created.Description)
		}

		listRes := httptest.NewRecorder()
		listReq := httptest.NewRequest(http.MethodGet, "/group?limit=10", nil)
		handler(listRes, listReq)

		require.Equal(http.StatusOK, listRes.Code)
		var list schema.GroupList
		require.NoError(json.Unmarshal(listRes.Body.Bytes(), &list))
		assert.NotEmpty(list.Body)
		assert.Contains(list.Body, created)
	})

	t.Run("GroupItemHandlerGetUpdateAndDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		description := "Original Group"
		created, err := mgr.CreateGroup(context.Background(), schema.GroupInsert{
			ID: "managed-group",
			GroupMeta: schema.GroupMeta{
				Description: &description,
				Scopes:      []string{"read"},
			},
		})
		require.NoError(err)

		_, handler, _ := GroupItemHandler(mgr)

		getRes := httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, "/group/managed-group", nil)
		getReq.SetPathValue("group", created.ID)
		handler(getRes, getReq)

		require.Equal(http.StatusOK, getRes.Code)
		var fetched schema.Group
		require.NoError(json.Unmarshal(getRes.Body.Bytes(), &fetched))
		assert.Equal(created.ID, fetched.ID)

		updatedDescription := "Updated Group"
		patchRes := httptest.NewRecorder()
		patchReq := httptest.NewRequest(http.MethodPatch, "/group/managed-group", mustJSONBody(t, schema.GroupMeta{
			Description: &updatedDescription,
			Scopes:      []string{"read", "write"},
		}))
		patchReq.Header.Set("Content-Type", "application/json")
		patchReq.SetPathValue("group", created.ID)
		handler(patchRes, patchReq)

		require.Equal(http.StatusOK, patchRes.Code)
		var updated schema.Group
		require.NoError(json.Unmarshal(patchRes.Body.Bytes(), &updated))
		if assert.NotNil(updated.Description) {
			assert.Equal(updatedDescription, *updated.Description)
		}
		assert.Equal([]string{"read", "write"}, updated.Scopes)

		deleteRes := httptest.NewRecorder()
		deleteReq := httptest.NewRequest(http.MethodDelete, "/group/managed-group", nil)
		deleteReq.SetPathValue("group", created.ID)
		handler(deleteRes, deleteReq)

		require.Equal(http.StatusNoContent, deleteRes.Code)

		missingRes := httptest.NewRecorder()
		missingReq := httptest.NewRequest(http.MethodGet, "/group/managed-group", nil)
		missingReq.SetPathValue("group", created.ID)
		handler(missingRes, missingReq)
		require.Equal(http.StatusNotFound, missingRes.Code)
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
		assert.Nil(response.UserInfo)
		claims, err := newHTTPTestManagerForToken(t, response.Token)
		require.NoError(err)
		assert.Equal(issuer, claims["iss"])
		assert.Equal(uuid.UUID(user.ID).String(), claims["sub"])
		assert.Equal(uuid.UUID(session.ID).String(), claims["sid"])
		assert.Contains(claims, "user")
		assert.Contains(claims, "session")
	})

	t.Run("RefreshHandlerMissingToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := RefreshHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", mustJSONBody(t, schema.RefreshRequest{}))
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "token is required")
	})

	t.Run("RefreshHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := RefreshHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/refresh", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
	})

	t.Run("RevokeHandlerReturnsNoContent", func(t *testing.T) {
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

		require.Equal(http.StatusNoContent, res.Code)
		assert.Empty(res.Body.String())
		revoked, err := mgr.GetSession(context.Background(), session.ID)
		require.NoError(err)
		require.NotNil(revoked.RevokedAt)
		assert.False(revoked.RevokedAt.IsZero())
	})

	t.Run("RevokeHandlerMissingToken", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := RevokeHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/revoke", mustJSONBody(t, schema.RefreshRequest{}))
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "token is required")
	})

	t.Run("RevokeHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := RevokeHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/revoke", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
	})

	t.Run("SessionIDFromClaimsValidation", func(t *testing.T) {
		assert := assert.New(t)

		_, err := sessionIDFromClaims(map[string]any{})
		assert.Error(err)
		assert.Contains(err.Error(), "missing sid claim")

		_, err = sessionIDFromClaims(map[string]any{"sid": "not-a-uuid"})
		assert.Error(err)
	})

	t.Run("OpenAPIHelpers", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("uuid", uuidSchema().Format)
		assert.NotNil(groupSchema())
		assert.NotNil(groupListSchema())
		userGroupList := userGroupListSchema()
		if assert.NotNil(userGroupList) {
			assert.Equal("array", userGroupList.Type)
			if assert.NotNil(userGroupList.Items) {
				assert.Equal("string", userGroupList.Items.Type)
			}
		}
		user := userSchema()
		if assert.NotNil(user) {
			assert.NotNil(schemaProperty(user, "groups"))
		}
		userMeta := userMetaSchema()
		if assert.NotNil(userMeta) {
			assert.NotNil(schemaProperty(userMeta, "groups"))
		}
		assert.NotNil(userListSchema())
		assert.NotNil(userInfoSchema())
		assert.NotNil(sessionSchema())
		assert.NotNil(tokenResponseSchema())
		assert.Nil(schemaProperty(nil, "missing"))
		setSchemaProperty(nil, "missing", nil)
		assert.Nil(unwrapSchema(nil))
	})

	t.Run("UserGroupHandlerOpenAPI", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		path, _, spec := UserGroupHandler(mgr)

		require.Equal("user/{user}/group", path)
		require.NotNil(spec)
		require.NotNil(spec.Post)
		require.NotNil(spec.Delete)

		assert.Equal("Add user groups", spec.Post.Summary)
		assert.Equal("Remove user groups", spec.Delete.Summary)
		require.NotNil(spec.Post.RequestBody)
		require.NotNil(spec.Delete.RequestBody)

		postBody := spec.Post.RequestBody.Content["application/json"].Schema
		deleteBody := spec.Delete.RequestBody.Content["application/json"].Schema
		require.NotNil(postBody)
		require.NotNil(deleteBody)
		assert.Equal("array", postBody.Type)
		assert.Equal("array", deleteBody.Type)

		postResponse := spec.Post.Responses["200"].Content["application/json"].Schema
		deleteResponse := spec.Delete.Responses["200"].Content["application/json"].Schema
		require.NotNil(postResponse)
		require.NotNil(deleteResponse)
		assert.NotNil(postResponse.Properties["id"])
		assert.NotNil(deleteResponse.Properties["id"])
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
