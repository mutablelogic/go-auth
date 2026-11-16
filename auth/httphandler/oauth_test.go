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

package httphandler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	// Packages
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	httphandler "github.com/mutablelogic/go-auth/auth/httphandler"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	file "github.com/mutablelogic/go-auth/auth/provider/file"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	security "github.com/mutablelogic/go-auth/auth/security"
	store "github.com/mutablelogic/go-auth/auth/store"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// newOAuthServer returns a server, which is an OAuth server, whose users
// sign in with a password, and alice's session cookie
func newOAuthServer(t *testing.T, opt ...httphandler.Opt) (*test.Server, *http.Cookie) {
	t.Helper()
	return newOAuthServerIn(t, filepath.Join(t.TempDir(), "sessions"), opt...)
}

// newOAuthServerIn returns an OAuth server, whose sessions are in the
// directory, which another server can share
func newOAuthServerIn(t *testing.T, dir string, opt ...httphandler.Opt) (*test.Server, *http.Cookie) {
	t.Helper()
	sessions, err := file.New(dir)
	require.NoError(t, err)
	exchanger, err := store.NewExchanger(sessions)
	require.NoError(t, err)
	scheme, err := security.New(sessions, security.WithResourceMetadata(httphandler.ResourceMetadataPath("/api")))
	require.NoError(t, err)
	opt = append([]httphandler.Opt{httphandler.WithExchange(exchanger.Exchange, store.ResponseSchema()), httphandler.WithSessions(sessions)}, opt...)
	register := httphandler.RegisterHandlers([]provider.Provider{local{}}, opt...)
	s := test.NewServer(t, func(router *httprouter.Router) error {
		if err := router.RegisterSecurityScheme(security.Name, scheme); err != nil {
			return err
		}
		return register(router)
	})

	// Alice signs in, with a browser
	resp, _ := newClient(t, s).do(http.MethodPost, "auth/local/login", strings.NewReader("username=alice&password=secret"), "application/x-www-form-urlencoded")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	for _, cookie := range resp.Cookies() {
		if cookie.Name == security.CookieName {
			return s, cookie
		}
	}
	t.Fatal("No session cookie")
	return nil, nil
}

// get returns the response of a GET of the URL, with the cookie, which
// isn't redirected
func get(t *testing.T, c *client, u string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	require.NoError(t, err)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := c.http.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	return resp
}

func Test_OAuth(t *testing.T) {
	ctx := context.Background()
	s, cookie := newOAuthServer(t, httphandler.WithOAuth("https://app.example.com/callback"))
	c := newClient(t, s)
	resource := s.URL + "/api"

	// A 401 says where the metadata is
	resp, _ := c.do(http.MethodGet, "auth/session", nil, "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `resource_metadata="`+s.URL+`/.well-known/oauth-protected-resource/api"`)

	// The client discovers the server, from the API's URL, and registers,
	// with a loopback redirect
	oauth, err := httpclient.New(resource)
	require.NoError(t, err)
	metadata, err := oauth.Discover(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, resource, metadata.Resource.Resource)
	require.Len(t, metadata.AuthorizationServers, 1)
	server := metadata.AuthorizationServers[0]
	assert.Equal(t, s.URL, server.Issuer)
	assert.True(t, server.SupportsS256())
	registration, err := oauth.Register(ctx, server, "Test", []string{"http://127.0.0.1/callback"})
	require.NoError(t, err)
	assert.NotEmpty(t, registration.ClientID)
	assert.Empty(t, registration.ClientSecret)

	// Alice authorizes it, on another port, which a loopback redirect can
	// be, and it's exchanged for a session of its own
	redirect := "http://127.0.0.1:8123/callback"
	authorize := func(t *testing.T, scopes ...string) (*httpclient.Authorization, url.Values) {
		t.Helper()
		a, err := oauth.Authorize(metadata, *registration, redirect, scopes...)
		require.NoError(t, err)
		resp := get(t, c, a.URL, cookie)
		require.Equal(t, http.StatusFound, resp.StatusCode)
		to, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, redirect, to.Scheme+"://"+to.Host+to.Path)
		assert.Equal(t, s.URL, to.Query().Get("iss"))
		return a, to.Query()
	}
	t.Run("Exchange", func(t *testing.T) {
		a, query := authorize(t)
		grant, err := oauth.Exchange(ctx, a, query)
		require.NoError(t, err)
		assert.Equal(t, "Bearer", grant.Token.TokenType)
		assert.Empty(t, grant.Token.RefreshToken)

		// Its token is a session's, for the client
		var session schema.Session
		resp, body := c.do(http.MethodGet, "auth/session", nil, "", &http.Cookie{Name: security.CookieName, Value: grant.Token.AccessToken})
		require.Equal(t, http.StatusOK, resp.StatusCode, body)
		require.NoError(t, json.Unmarshal([]byte(body), &session))
		assert.Equal(t, "Alice", session.User.Name)
		assert.Equal(t, "Test", session.Client)

		// The code is only exchanged once
		_, err = oauth.Exchange(ctx, a, query)
		assert.ErrorContains(t, err, "invalid_grant")
	})

	t.Run("Scopes", func(t *testing.T) {
		// Alice has no scopes, so none she asks for are given
		// Alice has no scopes, so none she asks for are given, which the
		// response says, with an empty scope
		a, query := authorize(t, "admin")
		resp, err := http.PostForm(server.TokenEndpoint, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {query.Get("code")},
			"redirect_uri":  {redirect},
			"client_id":     {registration.ClientID},
			"code_verifier": {a.Verifier},
		})
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var token map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&token))
		assert.Contains(t, token, "scope")
		assert.Equal(t, "", token["scope"])
	})

	t.Run("Verifier", func(t *testing.T) {
		a, query := authorize(t)
		a.Verifier = strings.Repeat("x", 43)
		_, err := oauth.Exchange(ctx, a, query)
		assert.ErrorContains(t, err, "invalid_grant")
	})

	t.Run("SignIn", func(t *testing.T) {
		// Without a session, there's no sign-in page to go to
		a, err := oauth.Authorize(metadata, *registration, redirect)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, get(t, c, a.URL, nil).StatusCode)
	})

	t.Run("Register", func(t *testing.T) {
		// Only loopback, and allowed, redirects
		_, err := oauth.Register(ctx, server, "Allowed", []string{"https://app.example.com/callback", "http://[::1]:8080/cb", "http://localhost/cb"})
		require.NoError(t, err)
		_, err = oauth.Register(ctx, server, strings.Repeat("x", 5000), []string{"http://127.0.0.1/callback"})
		assert.ErrorContains(t, err, "invalid_client_metadata", "too large")
		for _, redirect := range []string{"https://evil.example.com/callback", "https://app.example.com/callback/x", "http://example.com/callback", "http://127.0.0.1/cb#x"} {
			_, err := oauth.Register(ctx, server, "Refused", []string{redirect})
			assert.ErrorContains(t, err, "invalid_redirect_uri", redirect)
		}
	})

	t.Run("Authorize", func(t *testing.T) {
		a, err := oauth.Authorize(metadata, *registration, redirect)
		require.NoError(t, err)
		u, err := url.Parse(a.URL)
		require.NoError(t, err)
		with := func(key, value string) string {
			query := u.Query()
			query.Set(key, value)
			v := *u
			v.RawQuery = query.Encode()
			return v.String()
		}

		// Not another client, or redirect, which there's nowhere to say
		assert.Equal(t, http.StatusBadRequest, get(t, c, with("client_id", "another"), cookie).StatusCode)
		assert.Equal(t, http.StatusBadRequest, get(t, c, with("redirect_uri", "http://127.0.0.1:8123/elsewhere"), cookie).StatusCode)
		assert.Equal(t, http.StatusBadRequest, get(t, c, with("redirect_uri", "https://app.example.com/callback"), cookie).StatusCode, "another client's")

		// Which the client is told of
		for key, value := range map[string]string{"code_challenge_method": "plain", "response_type": "token", "resource": "https://other.example.com"} {
			resp := get(t, c, with(key, value), cookie)
			require.Equal(t, http.StatusFound, resp.StatusCode, key)
			to, err := url.Parse(resp.Header.Get("Location"))
			require.NoError(t, err)
			assert.NotEmpty(t, to.Query().Get("error"), key)
			assert.Empty(t, to.Query().Get("code"), key)
			assert.Equal(t, a.State, to.Query().Get("state"), key)
		}
	})
}

func Test_OAuthShared(t *testing.T) {
	// Two servers, with the same key and sessions, as replicas are
	ctx := context.Background()
	key := []byte(strings.Repeat("k", 32))
	dir := filepath.Join(t.TempDir(), "sessions")
	allowed := "https://app.example.com/callback"
	a, cookie := newOAuthServerIn(t, dir, httphandler.WithKey(key), httphandler.WithOAuth(allowed))
	b, _ := newOAuthServerIn(t, dir, httphandler.WithKey(key), httphandler.WithOAuth())
	discover := func(s *test.Server) (*httpclient.Client, *httpclient.Metadata) {
		oauth, err := httpclient.New(s.URL + "/api")
		require.NoError(t, err)
		metadata, err := oauth.Discover(ctx, "")
		require.NoError(t, err)
		return oauth, metadata
	}
	oauthA, metadataA := discover(a)
	oauthB, metadataB := discover(b)
	registration, err := oauthA.Register(ctx, metadataA.AuthorizationServers[0], "Test", []string{"http://127.0.0.1/callback", allowed})
	require.NoError(t, err)

	t.Run("Replay", func(t *testing.T) {
		// A code exchanged with one isn't exchanged again with the other
		auth, err := oauthA.Authorize(metadataA, *registration, "http://127.0.0.1/callback")
		require.NoError(t, err)
		resp := get(t, newClient(t, a), auth.URL, cookie)
		require.Equal(t, http.StatusFound, resp.StatusCode)
		to, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		_, err = oauthA.Exchange(ctx, auth, to.Query())
		require.NoError(t, err)
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {to.Query().Get("code")},
			"redirect_uri":  {"http://127.0.0.1/callback"},
			"client_id":     {registration.ClientID},
			"code_verifier": {auth.Verifier},
		}
		replay, err := http.PostForm(metadataB.AuthorizationServers[0].TokenEndpoint, form)
		require.NoError(t, err)
		replay.Body.Close()
		assert.Equal(t, http.StatusBadRequest, replay.StatusCode)
	})

	t.Run("Redirect", func(t *testing.T) {
		// A redirect the other doesn't allow isn't, though the client
		// registered it
		auth, err := oauthB.Authorize(metadataB, *registration, allowed)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, get(t, newClient(t, b), auth.URL, cookie).StatusCode)
	})
}

func Test_OAuthSignIn(t *testing.T) {
	ctx := context.Background()
	s, _ := newOAuthServer(t, httphandler.WithOAuth(), httphandler.WithSignIn("/login"))
	oauth, err := httpclient.New(s.URL + "/api")
	require.NoError(t, err)
	metadata, err := oauth.Discover(ctx, "")
	require.NoError(t, err)
	registration, err := oauth.Register(ctx, metadata.AuthorizationServers[0], "Test", []string{"http://127.0.0.1/callback"})
	require.NoError(t, err)

	// Without a session, it's the sign-in page, which returns to authorize
	a, err := oauth.Authorize(metadata, *registration, "http://127.0.0.1/callback")
	require.NoError(t, err)
	resp := get(t, newClient(t, s), a.URL, nil)
	require.Equal(t, http.StatusFound, resp.StatusCode)
	to, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/login", to.Path)
	back, err := url.Parse(to.Query().Get("return"))
	require.NoError(t, err)
	assert.Equal(t, "/api/auth/authorize", back.Path)
	assert.Equal(t, a.State, back.Query().Get("state"))
}

func Test_OAuthOptions(t *testing.T) {
	router := func() *httprouter.Router {
		router, err := httprouter.NewRouter(context.Background(), http.NewServeMux(), "/api", "", "test", "test")
		require.NoError(t, err)
		return router
	}

	// It needs sessions, and the options are checked
	assert.ErrorIs(t, httphandler.RegisterHandlers(nil, httphandler.WithOAuth())(router()), httpresponse.ErrBadRequest)
	for _, opt := range []httphandler.Opt{httphandler.WithOAuth("ftp://example.com/x"), httphandler.WithOAuth("https://example.com/cb#x"), httphandler.WithSignIn("https://example.com/login")} {
		assert.ErrorIs(t, httphandler.RegisterHandlers(nil, opt)(router()), httpresponse.ErrBadRequest)
	}
}
