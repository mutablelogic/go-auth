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

package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	managerpkg "github.com/djthorpe/go-auth/pkg/authmanager"
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	managerhandler "github.com/djthorpe/go-auth/pkg/httphandler/manager"
	middleware "github.com/djthorpe/go-auth/pkg/middleware"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	googleprovider "github.com/djthorpe/go-auth/pkg/provider/google"
	localprovider "github.com/djthorpe/go-auth/pkg/provider/local"
	schema "github.com/djthorpe/go-auth/schema/auth"
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	test "github.com/mutablelogic/go-pg/pkg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

type streamRecorder struct {
	mu     sync.Mutex
	header http.Header
	body   bytes.Buffer
	code   int
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{header: make(http.Header)}
}

func (r *streamRecorder) Header() http.Header {
	return r.header
}

func (r *streamRecorder) WriteHeader(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		r.code = code
	}
}

func (r *streamRecorder) Write(data []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(data)
}

func (r *streamRecorder) Flush() {}

func (r *streamRecorder) BodyString() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}

func (r *streamRecorder) Code() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.code
}

var conn test.Conn

var (
	ChangesHandler   = managerhandler.ChangesHandler
	GroupHandler     = managerhandler.GroupHandler
	GroupItemHandler = managerhandler.GroupItemHandler
	ScopeHandler     = managerhandler.ScopeHandler
	UserHandler      = managerhandler.UserHandler
	UserItemHandler  = managerhandler.UserItemHandler
	UserGroupHandler = managerhandler.UserGroupHandler
)

func TestMain(m *testing.M) {
	test.Main(m, &conn)
}

func Test_http_001(t *testing.T) {
	t.Run("ChangesHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := ChangesHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/changes", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
	})

	t.Run("ChangesHandlerRequiresTextStreamAccept", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManagerWithOpts(t, managerpkg.WithNotificationChannel("backend.table_change"))
		_, handler, _ := ChangesHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/changes", nil)
		req.Header.Set("Accept", "application/json")

		handler(res, req)

		require.Equal(http.StatusNotAcceptable, res.Code)
		assert.Contains(res.Body.String(), "text/event-stream")
	})

	t.Run("ChangesHandlerStreamsNotifications", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManagerWithOpts(t, managerpkg.WithNotificationChannel("backend.table_change"))
		_, handler, _ := ChangesHandler(mgr)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req := httptest.NewRequest(http.MethodGet, "/changes", nil).WithContext(ctx)
		req.Header.Set("Accept", "text/event-stream")
		res := newStreamRecorder()

		done := make(chan struct{})
		go func() {
			defer close(done)
			handler(res, req)
		}()

		require.NoError(mgr.Exec(context.Background(), `
			INSERT INTO auth."group" (id, description)
			VALUES ('changes-handler-group', 'Changes Handler Group')
		`))

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			body := res.BodyString()
			if strings.Contains(body, "event: change\n") && strings.Contains(body, `"table":"group"`) {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}

		cancel()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for changes handler to exit")
		}

		require.Equal(http.StatusOK, res.Code())
		assert.Equal("text/event-stream", res.Header().Get("Content-Type"))
		assert.Contains(res.BodyString(), "event: change\n")
		assert.Contains(res.BodyString(), `"schema":"auth"`)
		assert.Contains(res.BodyString(), `"table":"group"`)
		assert.Contains(res.BodyString(), `"action":"INSERT"`)
	})

	t.Run("AuthorizationHandlerRedirectsToLocalCallbackByDefault", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := AuthorizationHandler(mgr)
		challenge := codeChallengeForVerifier("verifier-123")
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A8085%2Fcallback&response_type=code&state=state-123&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&login_hint=local.success%40example.com", nil)
		req.Host = "localhost:8084"

		handler(res, req)

		require.Equal(http.StatusFound, res.Code)
		location := res.Header().Get("Location")
		require.NotEmpty(location)
		uri, err := url.Parse(location)
		require.NoError(err)
		assert.Equal("/auth/provider/local", uri.Path)
		assert.Equal("http://127.0.0.1:8085/callback", uri.Query().Get("redirect_uri"))
		assert.Equal("state-123", uri.Query().Get("state"))
		assert.Equal(challenge, uri.Query().Get("code_challenge"))
		assert.Equal("S256", uri.Query().Get("code_challenge_method"))
		assert.Equal("local.success@example.com", uri.Query().Get("login_hint"))
	})

	t.Run("AuthorizationHandlerPreservesPrefixForLocalProviderRoute", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := AuthorizationHandler(mgr)
		challenge := codeChallengeForVerifier("verifier-123")
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A8085%2Fcallback&response_type=code&state=state-123&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256", nil)

		handler(res, req)

		require.Equal(http.StatusFound, res.Code)
		location := res.Header().Get("Location")
		require.NotEmpty(location)
		uri, err := url.Parse(location)
		require.NoError(err)
		assert.Equal("/api/auth/provider/local", uri.Path)
	})

	t.Run("AuthCodeHandlerLocalAuthorizationCodeGrantSuccess", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		_, authorizeHandler, _ := AuthorizationHandler(mgr)
		challenge := codeChallengeForVerifier("verifier-123")
		authorizeRes := httptest.NewRecorder()
		authorizeReq := httptest.NewRequest(http.MethodGet, "/auth/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A8085%2Fcallback&response_type=code&state=state-123&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256&login_hint=local.success%40example.com", nil)
		authorizeReq.Host = "localhost:8084"
		authorizeHandler(authorizeRes, authorizeReq)
		require.Equal(http.StatusFound, authorizeRes.Code)
		providerURL, err := url.Parse(authorizeRes.Header().Get("Location"))
		require.NoError(err)
		registeredProvider, err := mgr.Provider(schema.ProviderKeyLocal)
		require.NoError(err)
		providerHandler, spec := registeredProvider.HTTPHandler()
		require.NotNil(providerHandler)
		require.NotNil(spec)
		providerRes := httptest.NewRecorder()
		providerReq := httptest.NewRequest(http.MethodPost, providerURL.Path, strings.NewReader(providerURL.Query().Encode()))
		providerReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		providerHandler(providerRes, providerReq)
		require.Equal(http.StatusFound, providerRes.Code)
		callbackURL, err := url.Parse(providerRes.Header().Get("Location"))
		require.NoError(err)
		code := callbackURL.Query().Get("code")
		require.NotEmpty(code)

		_, handler, _ := AuthCodeHandler(mgr)
		res := httptest.NewRecorder()
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"provider":      {"local"},
			"code":          {code},
			"redirect_uri":  {"http://127.0.0.1:8085/callback"},
			"code_verifier": {"verifier-123"},
		}
		req := httptest.NewRequest(http.MethodPost, "/auth/code", strings.NewReader(form.Encode()))
		req.Host = "localhost:8084"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response map[string]any
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		accessToken, _ := response["access_token"].(string)
		refreshToken, _ := response["refresh_token"].(string)
		assert.NotEmpty(accessToken)
		assert.NotEmpty(refreshToken)
		assert.Equal("Bearer", response["token_type"])
		assert.Equal(issuer, mustExtractIssuer(t, accessToken))

		listed, err := mgr.ListUsers(context.Background(), schema.UserListRequest{Email: "local.success@example.com"})
		require.NoError(err)
		require.Len(listed.Body, 1)
	})

	t.Run("AuthCodeHandlerSuccess", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		provider := newTestOIDCProvider(t, "google-client-id", "google-client-secret", "nonce-123")
		defer provider.Close()

		google, err := googleprovider.NewWithIssuer("google-client-id", "google-client-secret", provider.Issuer())
		require.NoError(err)
		mgr, issuer := newHTTPTestManagerWithOpts(t, managerpkg.WithProvider(google))
		_, handler, _ := AuthCodeHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/code", mustJSONBody(t, schema.AuthorizationCodeRequest{
			Provider:     "google",
			Code:         "auth-code",
			RedirectURL:  "http://127.0.0.1:8085/callback",
			CodeVerifier: "verifier-123",
			Nonce:        "nonce-123",
		}))
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response schema.TokenResponse
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.NotEmpty(response.Token)
		require.NotNil(response.UserInfo)
		assert.Equal("auth.code.success@example.com", response.UserInfo.Email)
		assert.Equal(issuer, mustExtractIssuer(t, response.Token))
		assert.Equal("auth-code", provider.FormValue("code"))
		assert.Equal("http://127.0.0.1:8085/callback", provider.FormValue("redirect_uri"))
		assert.Equal("verifier-123", provider.FormValue("code_verifier"))
	})

	t.Run("AuthCodeHandlerFormSuccess", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		provider := newTestOIDCProvider(t, "google-client-id", "google-client-secret", "nonce-123")
		defer provider.Close()

		google, err := googleprovider.NewWithIssuer("google-client-id", "google-client-secret", provider.Issuer())
		require.NoError(err)
		mgr, issuer := newHTTPTestManagerWithOpts(t, managerpkg.WithProvider(google))
		_, handler, _ := AuthCodeHandler(mgr)
		res := httptest.NewRecorder()
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"provider":      {"google"},
			"code":          {"auth-code"},
			"redirect_uri":  {"http://127.0.0.1:8085/callback"},
			"code_verifier": {"verifier-123"},
			"nonce":         {"nonce-123"},
		}
		req := httptest.NewRequest(http.MethodPost, "/auth/code", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response map[string]any
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		accessToken, _ := response["access_token"].(string)
		assert.NotEmpty(accessToken)
		assert.Equal("Bearer", response["token_type"])
		assert.Equal(issuer, mustExtractIssuer(t, accessToken))
		assert.Equal("auth-code", provider.FormValue("code"))
		assert.Equal("http://127.0.0.1:8085/callback", provider.FormValue("redirect_uri"))
		assert.Equal("verifier-123", provider.FormValue("code_verifier"))
	})

	t.Run("AuthCodeHandlerRejectsNonceMismatch", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		provider := newTestOIDCProvider(t, "google-client-id", "google-client-secret", "wrong-nonce")
		defer provider.Close()

		google, err := googleprovider.NewWithIssuer("google-client-id", "google-client-secret", provider.Issuer())
		require.NoError(err)
		mgr, _ := newHTTPTestManagerWithOpts(t, managerpkg.WithProvider(google))
		_, handler, _ := AuthCodeHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/code", mustJSONBody(t, schema.AuthorizationCodeRequest{
			Provider:    "google",
			Code:        "auth-code",
			RedirectURL: "http://127.0.0.1:8085/callback",
			Nonce:       "nonce-123",
		}))
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "token nonce mismatch")
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
		var response oidc.OIDCConfiguration
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.Equal(issuer, response.Issuer)
		assert.Equal(oidc.AuthorizationURL(issuer), response.AuthorizationEndpoint)
		assert.Equal(oidc.AuthCodeURL(issuer), response.TokenEndpoint)
		assert.Equal([]string{oidc.ResponseTypeCode}, response.ResponseTypes)
		assert.Equal([]string{"authorization_code", "refresh_token"}, response.GrantTypesSupported)
		assert.Equal([]string{oidc.CodeChallengeMethodS256}, response.CodeChallengeMethods)
	})

	t.Run("AuthorizationHandlerRedirectsToConfiguredProvider", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		providerURL := ""
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				_ = json.NewEncoder(w).Encode(oidc.OIDCConfiguration{
					BaseConfiguration: oidc.BaseConfiguration{
						Issuer:                providerURL,
						AuthorizationEndpoint: providerURL + "/authorize",
						TokenEndpoint:         providerURL + "/token",
					},
					JwksURI: providerURL + "/jwks",
				})
			case "/authorize":
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
		providerURL = provider.URL
		defer provider.Close()

		google, err := googleprovider.NewWithIssuer("google-client-id", "google-client-secret", provider.URL)
		require.NoError(err)
		mgr, _ := newHTTPTestManagerWithOpts(t, managerpkg.WithProvider(google))
		_, handler, _ := AuthorizationHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?provider=google&redirect_uri=http%3A%2F%2F127.0.0.1%3A8085%2Fcallback&response_type=code&state=state-123&code_challenge=challenge-123&code_challenge_method=S256", nil)

		handler(res, req)

		require.Equal(http.StatusFound, res.Code)
		location := res.Header().Get("Location")
		require.NotEmpty(location)
		uri, err := url.Parse(location)
		require.NoError(err)
		assert.Equal("/authorize", uri.Path)
		query := uri.Query()
		assert.Equal("google-client-id", query.Get("client_id"))
		assert.Equal("http://127.0.0.1:8085/callback", query.Get("redirect_uri"))
		assert.Equal("code", query.Get("response_type"))
		assert.Equal("state-123", query.Get("state"))
		assert.Equal("challenge-123", query.Get("code_challenge"))
		assert.Equal("S256", query.Get("code_challenge_method"))
		assert.Equal("openid email profile", query.Get("scope"))
	})

	t.Run("AuthorizationHandlerRejectsLocalWhenProviderNotRegistered", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		c := conn.Begin(t)
		defer c.Close()

		key, err := authcrypto.GeneratePrivateKey()
		require.NoError(err)
		mgr, err := managerpkg.New(context.Background(), c,
			managerpkg.WithPrivateKey(key),
			managerpkg.WithSessionTTL(15*time.Minute),
		)
		require.NoError(err)

		_, handler, _ := AuthorizationHandler(mgr)
		res := httptest.NewRecorder()
		challenge := codeChallengeForVerifier("verifier-123")
		req := httptest.NewRequest(http.MethodGet, "/auth/authorize?provider=local&redirect_uri=http%3A%2F%2F127.0.0.1%3A8085%2Fcallback&response_type=code&state=state-123&code_challenge="+url.QueryEscape(challenge)+"&code_challenge_method=S256", nil)

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		var response map[string]any
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		reason, _ := response["reason"].(string)
		assert.Contains(reason, `unsupported provider "local"`)
	})

	t.Run("AuthorizationHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := AuthorizationHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/authorize", nil)

		handler(res, req)

		require.Equal(http.StatusMethodNotAllowed, res.Code)
	})

	t.Run("ProtectedResourceHandlerReturnsMetadata", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		_, handler, _ := ProtectedResourceHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		req.Host = "localhost:8084"

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)
		var response oidc.ProtectedResourceMetadata
		require.NoError(json.Unmarshal(res.Body.Bytes(), &response))
		assert.Equal(issuer, response.Resource)
		assert.Equal([]string{issuer}, response.AuthorizationServers)
		assert.Equal([]string{"header"}, response.BearerMethodsSupported)
		assert.Equal("go-auth", response.ResourceName)
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

	t.Run("ProtectedResourceHandlerMethodNotAllowed", func(t *testing.T) {
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		_, handler, _ := ProtectedResourceHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)

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

		_, handler, _ := JWKSHandler(&managerpkg.Manager{})
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

	t.Run("UserResponsesIncludeEffectiveMetaAndDisabledGroups", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		enabled := true
		disabled := false
		_, err := mgr.CreateGroup(context.Background(), schema.GroupInsert{
			ID: "admins",
			GroupMeta: schema.GroupMeta{
				Enabled: &enabled,
				Scopes:  []string{"user.read"},
				Meta:    schema.MetaMap{"group_admin": "hello"},
			},
		})
		require.NoError(err)
		_, err = mgr.CreateGroup(context.Background(), schema.GroupInsert{
			ID: "disabled-group",
			GroupMeta: schema.GroupMeta{
				Enabled: &disabled,
				Scopes:  []string{"admin.all"},
			},
		})
		require.NoError(err)

		created, err := mgr.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Meta User",
			Email:  "meta.user@example.com",
			Meta:   schema.MetaMap{"source": "local"},
			Groups: []string{"admins", "disabled-group"},
		}, nil)
		require.NoError(err)

		_, itemHandler, _ := UserItemHandler(mgr)
		getRes := httptest.NewRecorder()
		getReq := httptest.NewRequest(http.MethodGet, "/user/"+uuid.UUID(created.ID).String(), nil)
		getReq.SetPathValue("user", uuid.UUID(created.ID).String())
		itemHandler(getRes, getReq)

		require.Equal(http.StatusOK, getRes.Code)
		var fetched schema.User
		require.NoError(json.Unmarshal(getRes.Body.Bytes(), &fetched))
		assert.Equal(schema.MetaMap{"source": "local"}, fetched.Meta)
		assert.Equal(schema.MetaMap{"group_admin": "hello", "source": "local"}, fetched.EffectiveMeta)
		assert.Equal([]string{"admins"}, fetched.Groups)
		assert.Equal([]string{"disabled-group"}, fetched.DisabledGroups)

		_, collectionHandler, _ := UserHandler(mgr)
		listRes := httptest.NewRecorder()
		listReq := httptest.NewRequest(http.MethodGet, "/user?email=meta.user@example.com", nil)
		collectionHandler(listRes, listReq)

		require.Equal(http.StatusOK, listRes.Code)
		var list schema.UserList
		require.NoError(json.Unmarshal(listRes.Body.Bytes(), &list))
		require.Len(list.Body, 1)
		assert.Equal(schema.MetaMap{"source": "local"}, list.Body[0].Meta)
		assert.Equal(schema.MetaMap{"group_admin": "hello", "source": "local"}, list.Body[0].EffectiveMeta)
		assert.Equal([]string{"admins"}, list.Body[0].Groups)
		assert.Equal([]string{"disabled-group"}, list.Body[0].DisabledGroups)
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

	t.Run("ScopeHandlerList", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, _ := newHTTPTestManager(t)
		enabled := true
		disabled := false
		suffix := time.Now().UnixNano()
		filter := fmt.Sprintf("scope-%d", suffix)
		scopeAdmin := fmt.Sprintf("%s-admin.all", filter)
		scopeProfile := fmt.Sprintf("%s-profile.read", filter)
		scopeTeam := fmt.Sprintf("%s-team.manage", filter)
		scopeUserRead := fmt.Sprintf("%s-user.read", filter)
		scopeUserWrite := fmt.Sprintf("%s-user.write", filter)
		_, err := mgr.CreateGroup(context.Background(), schema.GroupInsert{
			ID: fmt.Sprintf("scope-admins-%d", suffix),
			GroupMeta: schema.GroupMeta{
				Enabled: &enabled,
				Scopes:  []string{scopeUserRead, scopeUserWrite, scopeProfile},
			},
		})
		require.NoError(err)
		_, err = mgr.CreateGroup(context.Background(), schema.GroupInsert{
			ID: fmt.Sprintf("scope-staff-%d", suffix),
			GroupMeta: schema.GroupMeta{
				Enabled: &enabled,
				Scopes:  []string{scopeProfile, scopeTeam},
			},
		})
		require.NoError(err)
		_, err = mgr.CreateGroup(context.Background(), schema.GroupInsert{
			ID: fmt.Sprintf("scope-suspended-%d", suffix),
			GroupMeta: schema.GroupMeta{
				Enabled: &disabled,
				Scopes:  []string{scopeAdmin},
			},
		})
		require.NoError(err)

		path, handler, spec := ScopeHandler(mgr)
		assert.Equal("scope", path)
		require.NotNil(spec)
		require.NotNil(spec.Get)

		listRes := httptest.NewRecorder()
		listReq := httptest.NewRequest(http.MethodGet, "/scope?q="+filter+"&limit=3&offset=1", nil)
		handler(listRes, listReq)

		require.Equal(http.StatusOK, listRes.Code)
		var list schema.ScopeList
		require.NoError(json.Unmarshal(listRes.Body.Bytes(), &list))
		assert.Equal(uint(5), list.Count)
		assert.Equal(uint64(1), list.Offset)
		require.NotNil(list.Limit)
		assert.Equal(uint64(3), *list.Limit)
		assert.Equal([]string{scopeProfile, scopeTeam, scopeUserRead}, list.Body)

		filteredRes := httptest.NewRecorder()
		filteredReq := httptest.NewRequest(http.MethodGet, "/scope?q="+scopeUserRead, nil)
		handler(filteredRes, filteredReq)

		require.Equal(http.StatusOK, filteredRes.Code)
		var filtered schema.ScopeList
		require.NoError(json.Unmarshal(filteredRes.Body.Bytes(), &filtered))
		assert.Equal(uint(1), filtered.Count)
		assert.Equal([]string{scopeUserRead}, filtered.Body)

		badRes := httptest.NewRecorder()
		badReq := httptest.NewRequest(http.MethodGet, "/scope?offset=-1", nil)
		handler(badRes, badReq)
		require.Equal(http.StatusBadRequest, badRes.Code)

		methodRes := httptest.NewRecorder()
		methodReq := httptest.NewRequest(http.MethodPost, "/scope", nil)
		handler(methodRes, methodReq)
		require.Equal(http.StatusMethodNotAllowed, methodRes.Code)
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

	t.Run("RevokeHandlerMissingSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		mgr, issuer := newHTTPTestManager(t)
		user, _ := mustLoginSession(t, mgr)
		token := mustSignTokenForSession(t, mgr, issuer, user, schema.Session{
			ID:        schema.SessionID(uuid.New()),
			User:      user.ID,
			ExpiresAt: time.Now().Add(15 * time.Minute),
		})

		_, handler, _ := RevokeHandler(mgr)
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/revoke", mustJSONBody(t, schema.RefreshRequest{Token: token}))
		req.Host = "localhost:8084"
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusNotFound, res.Code)
		assert.Contains(res.Body.String(), "not found")
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
		scopeList := scopeListSchema()
		if assert.NotNil(scopeList) {
			body := schemaProperty(scopeList, "body")
			if assert.NotNil(body) {
				require.NotNil(t, body.Items)
				assert.Equal("string", body.Items.Type)
			}
		}
		userGroupList := userGroupListSchema()
		if assert.NotNil(userGroupList) {
			if assert.NotNil(userGroupList.Items) {
				assert.Equal("string", userGroupList.Items.Type)
			}
		}
		user := userSchema()
		if assert.NotNil(user) {
			assert.NotNil(schemaProperty(user, "groups"))
			assert.NotNil(schemaProperty(user, "disabled_groups"))
			assert.NotNil(schemaProperty(user, "effective_meta"))
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
		require.NotNil(postBody.Items)
		require.NotNil(deleteBody.Items)
		assert.Equal("string", postBody.Items.Type)
		assert.Equal("string", deleteBody.Items.Type)

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
		return nil, fmt.Errorf("invalid token")
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

func newHTTPTestManager(t *testing.T) (*managerpkg.Manager, string) {
	t.Helper()
	return newHTTPTestManagerWithOpts(t)
}

func newHTTPTestManagerWithOpts(t *testing.T, opts ...managerpkg.Opt) (*managerpkg.Manager, string) {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	issuer := "http://localhost:8084/api"
	localProvider, err := localprovider.New(issuer, key)
	require.NoError(t, err)
	managerOpts := append([]managerpkg.Opt{
		managerpkg.WithPrivateKey(key),
		managerpkg.WithProvider(localProvider),
		managerpkg.WithSessionTTL(15 * time.Minute),
	}, opts...)
	mgr, err := managerpkg.New(context.Background(), c, managerOpts...)
	require.NoError(t, err)
	require.NoError(t, mgr.Exec(context.Background(), "TRUNCATE auth.user CASCADE"))

	return mgr, issuer
}

func mustLoginSession(t *testing.T, mgr *managerpkg.Manager) (*schema.User, *schema.Session) {
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
	}, nil)
	require.NoError(t, err)
	return user, session
}

func mustLoginToken(t *testing.T, mgr *managerpkg.Manager, issuer string) (*schema.User, *schema.Session, string) {
	t.Helper()
	user, session := mustLoginSession(t, mgr)
	return user, session, mustSignTokenForSession(t, mgr, issuer, user, *session)
}

func mustSignTokenForSession(t *testing.T, mgr *managerpkg.Manager, issuer string, user *schema.User, session schema.Session) string {
	t.Helper()
	token, err := mgr.OIDCSign(loginTokenClaims(issuer, user, &session))
	require.NoError(t, err)
	return token
}

func mustJSONBody(t *testing.T, value any) *bytes.Reader {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return bytes.NewReader(data)
}

func codeChallengeForVerifier(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type testOIDCProvider struct {
	server       *httptest.Server
	key          any
	clientID     string
	clientSecret string
	nonce        string
	lastForm     url.Values
}

func newTestOIDCProvider(t *testing.T, clientID, clientSecret, nonce string) *testOIDCProvider {
	t.Helper()

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	provider := &testOIDCProvider{
		key:          key,
		clientID:     clientID,
		clientSecret: clientSecret,
		nonce:        nonce,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+oidc.ConfigPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(oidc.OIDCConfiguration{
			BaseConfiguration: oidc.BaseConfiguration{
				Issuer:              provider.server.URL,
				TokenEndpoint:       provider.server.URL + "/token",
				ResponseTypes:       []string{oidc.ResponseTypeCode},
				GrantTypesSupported: []string{"authorization_code"},
				ScopesSupported:     []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
			},
			JwksURI:           oidc.JWKSURL(provider.server.URL),
			SigningAlgorithms: []string{oidc.SigningAlgorithm},
			SubjectTypes:      []string{"public"},
			ClaimsSupported:   []string{"iss", "sub", "aud", "exp", "iat", "email", "name", "nonce"},
		}))
	})
	mux.HandleFunc("/"+oidc.JWKSPath, func(w http.ResponseWriter, r *http.Request) {
		set, err := oidc.PublicJWKSet(key)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(set))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		provider.lastForm = cloneValues(r.PostForm)

		basicUser, basicPass, ok := r.BasicAuth()
		if !ok {
			basicUser = r.PostForm.Get("client_id")
			basicPass = r.PostForm.Get("client_secret")
		}
		assert.Equal(t, provider.clientID, basicUser)
		assert.Equal(t, provider.clientSecret, basicPass)

		idToken, err := oidc.SignToken(key, jwt.MapClaims{
			"iss":   provider.server.URL,
			"sub":   "auth-code-success",
			"aud":   provider.clientID,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"email": "auth.code.success@example.com",
			"name":  "Auth Code Success",
			"nonce": provider.nonce,
		})
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-access-token",
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		}))
	})
	provider.server = httptest.NewServer(mux)
	return provider
}

func (p *testOIDCProvider) Close() {
	if p != nil && p.server != nil {
		p.server.Close()
	}
}

func (p *testOIDCProvider) Issuer() string {
	if p == nil || p.server == nil {
		return ""
	}
	return p.server.URL
}

func (p *testOIDCProvider) FormValue(key string) string {
	if p == nil || p.lastForm == nil {
		return ""
	}
	return p.lastForm.Get(key)
}

func (p *testOIDCProvider) IssueToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	require.NotNil(t, p)
	require.NotNil(t, p.key)
	rsaKey, ok := p.key.(*rsa.PrivateKey)
	require.True(t, ok)
	token, err := oidc.SignToken(rsaKey, claims)
	require.NoError(t, err)
	return token
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = append([]string(nil), entries...)
	}
	return clone
}
