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
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	// Packages
	httphandler "github.com/mutablelogic/go-auth/auth/httphandler"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	file "github.com/mutablelogic/go-auth/auth/provider/file"
	oidc "github.com/mutablelogic/go-auth/auth/provider/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	security "github.com/mutablelogic/go-auth/auth/security"
	store "github.com/mutablelogic/go-auth/auth/store"
	authtest "github.com/mutablelogic/go-auth/auth/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// local is a password provider, whose only user is alice
type local struct{}

func (local) Meta() schema.ProviderMeta {
	return schema.ProviderMeta{Name: "local", Label: "Local", Kind: schema.ProviderKindPassword}
}

func (local) Exchange(_ context.Context, credential schema.Credential) (*schema.Identity, error) {
	switch {
	case credential.Username == "" || credential.Password == "":
		return nil, httpresponse.ErrBadRequest.With("A username and password are needed")
	case credential.Username == "alice" && credential.Password == "secret":
		return &schema.Identity{Provider: "local", Issuer: "local", Subject: "alice", Name: "Alice"}, nil
	default:
		return nil, httpresponse.ErrNotAuthorized.With("The username or password isn't right")
	}
}

// client sends requests to the server, without following redirects, so
// the redirect to the provider is seen
type client struct {
	t      *testing.T
	server *test.Server
	http   *http.Client
}

func newClient(t *testing.T, s *test.Server) *client {
	return &client{t: t, server: s, http: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// do sends a request, with the cookies, and returns the response, whose
// body is read
func (c *client) do(method, path string, body io.Reader, contentType string, cookies ...*http.Cookie) (*http.Response, string) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.server.URL+"/api/"+path, body)
	require.NoError(c.t, err)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := c.http.Do(req)
	require.NoError(c.t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(c.t, err)
	return resp, string(data)
}

// signInCookie returns the sign-in's cookie a response sets
func signInCookie(resp *http.Response) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "goauth_signin" {
			return cookie
		}
	}
	return nil
}

func newServer(t *testing.T) (*test.Server, *authtest.OIDC) {
	t.Helper()
	i := authtest.NewOIDC(t)
	p, err := oidc.New("oidc", "Fake OIDC", i.URL, authtest.NewCredentials().WithClient("oidc", i.Audience, "secret"), "oidc")
	require.NoError(t, err)
	return test.NewServer(t, httphandler.RegisterHandlers([]provider.Provider{p, local{}})), i
}

func Test_Providers(t *testing.T) {
	s, _ := newServer(t)
	var providers []schema.ProviderMeta
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "auth/provider", nil, &providers))
	assert.Equal(t, []schema.ProviderMeta{
		{Name: "oidc", Label: "Fake OIDC", Kind: schema.ProviderKindRedirect},
		{Name: "local", Label: "Local", Kind: schema.ProviderKindPassword},
	}, providers)
	assert.Empty(t, s.Verify())
}

func Test_Redirect(t *testing.T) {
	s, i := newServer(t)
	c := newClient(t, s)

	// signIn starts a sign-in, and returns its cookie, state, and the code
	// the issuer gives for its challenge
	signIn := func() (*http.Cookie, string, string) {
		t.Helper()
		resp, _ := c.do(http.MethodGet, "auth/oidc/login", nil, "")
		require.Equal(t, http.StatusFound, resp.StatusCode)
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
		location, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, i.URL+"/authorize", location.Scheme+"://"+location.Host+location.Path)
		assert.Equal(t, s.URL+"/api/auth/oidc/callback", location.Query().Get("redirect_uri"))
		cookie := signInCookie(resp)
		require.NotNil(t, cookie)
		assert.Equal(t, "/api/auth/oidc", cookie.Path)
		assert.True(t, cookie.HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
		code := i.Code(location.Query().Get("code_challenge"), map[string]any{"sub": "u1", "email": "alice@example.com", "name": "Alice"})
		return cookie, location.Query().Get("state"), code
	}

	t.Run("SignIn", func(t *testing.T) {
		cookie, state, code := signIn()
		resp, body := c.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, "", cookie)
		require.Equal(t, http.StatusOK, resp.StatusCode, body)
		var identity schema.Identity
		require.NoError(t, json.Unmarshal([]byte(body), &identity))
		assert.Equal(t, "oidc", identity.Provider)
		assert.Equal(t, "u1", identity.Subject)
		assert.Equal(t, "alice@example.com", identity.Email)
		cleared := signInCookie(resp)
		require.NotNil(t, cleared, "the cookie is cleared")
		assert.Negative(t, cleared.MaxAge)

		// The same sign-in again, which the issuer refuses, as its code has
		// been used
		resp, _ = c.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, "", cookie)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("WrongState", func(t *testing.T) {
		cookie, _, code := signIn()
		resp, _ := c.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"code": {code}, "state": {"another"}}.Encode(), nil, "", cookie)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("NoCookie", func(t *testing.T) {
		_, state, code := signIn()
		resp, _ := c.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("ChangedCookie", func(t *testing.T) {
		cookie, state, code := signIn()
		// Its first character, which is always another, and base64url
		first := "A"
		if cookie.Value[0] == 'A' {
			first = "B"
		}
		cookie.Value = first + cookie.Value[1:]
		resp, _ := c.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"code": {code}, "state": {state}}.Encode(), nil, "", cookie)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Refused", func(t *testing.T) {
		cookie, state, _ := signIn()
		resp, body := c.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"error": {"access_denied"}, "error_description": {"Not today"}, "state": {state}}.Encode(), nil, "", cookie)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, body, "Not today")
	})

	t.Run("NotRedirect", func(t *testing.T) {
		resp, _ := c.do(http.MethodGet, "auth/local/login", nil, "")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp, _ = c.do(http.MethodGet, "auth/missing/login", nil, "")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	assert.Empty(t, s.Verify())
}

func Test_Password(t *testing.T) {
	s, _ := newServer(t)
	c := newClient(t, s)

	// As JSON
	resp, body := c.do(http.MethodPost, "auth/local/login", strings.NewReader(`{"username":"alice","password":"secret"}`), "application/json")
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	var identity schema.Identity
	require.NoError(t, json.Unmarshal([]byte(body), &identity))
	assert.Equal(t, "alice", identity.Subject)

	// As a form, on a server whose exchanges aren't verified, as go-server's
	// test server doesn't read forms which are URL-encoded
	forms := test.NewServer(t, httphandler.RegisterHandlers([]provider.Provider{local{}}))
	resp, body = newClient(t, forms).do(http.MethodPost, "auth/local/login", strings.NewReader(url.Values{"username": {"alice"}, "password": {"secret"}}.Encode()), "application/x-www-form-urlencoded")
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	forms.Reset()

	// The wrong password, and none
	resp, _ = c.do(http.MethodPost, "auth/local/login", strings.NewReader(`{"username":"alice","password":"wrong"}`), "application/json")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp, _ = c.do(http.MethodPost, "auth/local/login", strings.NewReader(`{"username":"alice"}`), "application/json")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	// Not a password provider
	resp, _ = c.do(http.MethodPost, "auth/oidc/login", strings.NewReader(`{"username":"alice","password":"secret"}`), "application/json")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	assert.Empty(t, s.Verify())
}

func Test_Exchange(t *testing.T) {
	// What an identity is exchanged for is the response, and its error
	// refuses the sign-in
	exchange := func(_ context.Context, identity *schema.Identity) (any, error) {
		if identity.Subject != "alice" {
			return nil, httpresponse.ErrForbidden.With("Only alice")
		}
		return map[string]string{"session": "for " + identity.Subject}, nil
	}
	s := test.NewServer(t, httphandler.RegisterHandlers([]provider.Provider{local{}}, httphandler.WithExchange(exchange, jsonschema.MustFor[map[string]string]())))
	var result map[string]string
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPost, "auth/local/login", map[string]string{"username": "alice", "password": "secret"}, &result))
	assert.Equal(t, map[string]string{"session": "for alice"}, result)

	// Its schema is the response's, which the exchange is checked against,
	// rather than an identity's
	assert.Empty(t, s.Verify())
}

func Test_Options(t *testing.T) {
	router, err := httprouter.NewRouter(context.Background(), http.NewServeMux(), "/api", "", "test", "test")
	require.NoError(t, err)

	// Providers' names are unique, and the options are checked
	assert.ErrorIs(t, httphandler.RegisterHandlers([]provider.Provider{local{}, local{}})(router), httpresponse.ErrConflict)
	assert.ErrorIs(t, httphandler.RegisterHandlers(nil, httphandler.WithKey([]byte("short")))(router), httpresponse.ErrBadRequest)
	assert.ErrorIs(t, httphandler.RegisterHandlers(nil, httphandler.WithBaseURL("not a url"))(router), httpresponse.ErrBadRequest)
}

func Test_BaseURL(t *testing.T) {
	// The callback is at the base URL, rather than the request's, and the
	// cookie is secure, with https
	i := authtest.NewOIDC(t)
	p, err := oidc.New("oidc", "", i.URL, authtest.NewCredentials().WithClient("oidc", i.Audience, "secret"), "oidc")
	require.NoError(t, err)
	s := test.NewServer(t, httphandler.RegisterHandlers([]provider.Provider{p}, httphandler.WithBaseURL("https://auth.example.com/")))
	resp, _ := newClient(t, s).do(http.MethodGet, "auth/oidc/login", nil, "")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/api/auth/oidc/callback", location.Query().Get("redirect_uri"))
	assert.True(t, signInCookie(resp).Secure)
}

func Test_Session(t *testing.T) {
	// Signing in is exchanged for a session, whose token is the store's
	ctx := context.Background()
	i := authtest.NewOIDC(t)
	p, err := oidc.New("oidc", "", i.URL, authtest.NewCredentials().WithClient("oidc", i.Audience, "secret"), "oidc")
	require.NoError(t, err)
	sessions, err := file.New(filepath.Join(t.TempDir(), "sessions"))
	require.NoError(t, err)
	exchanger, err := store.NewExchanger(sessions)
	require.NoError(t, err)
	s := test.NewServer(t, httphandler.RegisterHandlers([]provider.Provider{p}, httphandler.WithExchange(exchanger.Exchange, store.ResponseSchema())))
	c := newClient(t, s)

	resp, _ := c.do(http.MethodGet, "auth/oidc/login", nil, "")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := i.Code(location.Query().Get("code_challenge"), map[string]any{"sub": "u1", "email": "alice@example.com", "name": "Alice"})
	resp, body := c.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"code": {code}, "state": {location.Query().Get("state")}}.Encode(), nil, "", signInCookie(resp))
	require.Equal(t, http.StatusOK, resp.StatusCode, body)

	var token schema.SessionToken
	require.NoError(t, json.Unmarshal([]byte(body), &token))
	assert.NotEmpty(t, token.Token)
	assert.Equal(t, store.IdentityID(&schema.Identity{Issuer: i.URL, Subject: "u1"}), token.User.ID)
	session, err := sessions.Session(ctx, token.Token)
	require.NoError(t, err)
	assert.Equal(t, token.ID, session.ID)
	assert.Empty(t, s.Verify())
}

// newSessionServer returns a server which signs in with the local provider,
// for a session, whose cookie it sets, with the security scheme
func newSessionServer(t *testing.T) *test.Server {
	t.Helper()
	sessions, err := file.New(t.TempDir())
	require.NoError(t, err)
	exchanger, err := store.NewExchanger(sessions)
	require.NoError(t, err)
	scheme, err := security.New(sessions)
	require.NoError(t, err)
	register := httphandler.RegisterHandlers([]provider.Provider{local{}}, httphandler.WithExchange(exchanger.Exchange, store.ResponseSchema()), httphandler.WithSessions(sessions))
	return test.NewServer(t, func(router *httprouter.Router) error {
		if err := router.RegisterSecurityScheme(security.Name, scheme); err != nil {
			return err
		}
		return register(router)
	})
}

// sessionCookie returns the session's cookie a response sets
func sessionCookie(resp *http.Response) *http.Cookie {
	for _, cookie := range resp.Cookies() {
		if cookie.Name == security.CookieName {
			return cookie
		}
	}
	return nil
}

func Test_SessionCookie(t *testing.T) {
	s := newSessionServer(t)
	c := newClient(t, s)

	// Signing in sets the session's cookie, for the API, until it expires
	resp, body := c.do(http.MethodPost, "auth/local/login", strings.NewReader(`{"username":"alice","password":"secret"}`), "application/json")
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	cookie := sessionCookie(resp)
	require.NotNil(t, cookie)
	assert.Equal(t, "/api", cookie.Path)
	assert.True(t, cookie.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.False(t, cookie.Expires.IsZero())
	var token schema.SessionToken
	require.NoError(t, json.Unmarshal([]byte(body), &token))
	assert.Equal(t, token.Token, cookie.Value)

	// The session, with the cookie, or the token
	resp, body = c.do(http.MethodGet, "auth/session", nil, "", cookie)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	assert.Contains(t, body, `"id": "local:alice"`)
	status, _, _ := s.Request(t, http.MethodGet, "auth/session", http.Header{"Authorization": {"Bearer " + token.Token}})
	assert.Equal(t, http.StatusOK, status)

	// Signing out ends it, and clears the cookie
	resp, _ = c.do(http.MethodPost, "auth/logout", nil, "", cookie)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	cleared := sessionCookie(resp)
	require.NotNil(t, cleared)
	assert.Negative(t, cleared.MaxAge)
	resp, _ = c.do(http.MethodGet, "auth/session", nil, "", cookie)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp, _ = c.do(http.MethodPost, "auth/logout", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	assert.Empty(t, s.Verify())
}

func Test_Return(t *testing.T) {
	s := newSessionServer(t)
	c := newClient(t, s)

	// With a path to return to, signing in redirects there, with the cookie
	resp, _ := c.do(http.MethodPost, "auth/local/login", strings.NewReader(`{"username":"alice","password":"secret","return":"/#ldap-users"}`), "application/json")
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/#ldap-users", resp.Header.Get("Location"))
	assert.NotNil(t, sessionCookie(resp))

	// Not to another site
	for _, path := range []string{"https://evil.test/", "//evil.test/", "/\\evil.test", "evil", "/\r\nX: y"} {
		body, err := json.Marshal(map[string]string{"username": "alice", "password": "secret", "return": path})
		require.NoError(t, err)
		resp, _ = c.do(http.MethodPost, "auth/local/login", strings.NewReader(string(body)), "application/json")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, path)
	}

	// The callback of a redirect provider returns too
	i := authtest.NewOIDC(t)
	p, err := oidc.New("oidc", "", i.URL, authtest.NewCredentials().WithClient("oidc", i.Audience, "secret"), "oidc")
	require.NoError(t, err)
	sessions, err := file.New(t.TempDir())
	require.NoError(t, err)
	exchanger, err := store.NewExchanger(sessions)
	require.NoError(t, err)
	redirect := test.NewServer(t, httphandler.RegisterHandlers([]provider.Provider{p}, httphandler.WithExchange(exchanger.Exchange, store.ResponseSchema())))
	rc := newClient(t, redirect)
	resp, _ = rc.do(http.MethodGet, "auth/oidc/login?return=%2Fhome", nil, "")
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	code := i.Code(location.Query().Get("code_challenge"), map[string]any{"sub": "u1"})
	resp, _ = rc.do(http.MethodGet, "auth/oidc/callback?"+url.Values{"code": {code}, "state": {location.Query().Get("state")}}.Encode(), nil, "", signInCookie(resp))
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
	assert.Equal(t, "/home", resp.Header.Get("Location"))
	resp, _ = rc.do(http.MethodGet, "auth/oidc/login?return=https%3A%2F%2Fevil.test", nil, "")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	assert.Empty(t, s.Verify())
	assert.Empty(t, redirect.Verify())
}
