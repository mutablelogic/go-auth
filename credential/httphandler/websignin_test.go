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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	// Packages
	authclient "github.com/mutablelogic/go-auth/auth/httpclient"
	credential "github.com/mutablelogic/go-auth/credential"
	filecredential "github.com/mutablelogic/go-auth/credential/file"
	httphandler "github.com/mutablelogic/go-auth/credential/httphandler"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

// newWebTokenServer returns an authorization server, whose token endpoint
// exchanges "code", or "noscope", which says no scope, for the web
// application's client "web-1", whose secret is "web-secret", of the
// redirect, and any verifier, which it records
func newWebTokenServer(t *testing.T, redirect string, verifiers *[]string) authclient.ServerMetadata {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.FormValue("client_id") != "web-1" || r.FormValue("client_secret") != "web-secret":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		case (r.FormValue("code") != "code" && r.FormValue("code") != "noscope") || r.FormValue("redirect_uri") != redirect:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		default:
			*verifiers = append(*verifiers, r.FormValue("code_verifier"))
			response := map[string]any{"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh", "expires_in": 3600}
			if r.FormValue("code") == "code" {
				response["scope"] = "tasks"
			}
			_ = json.NewEncoder(w).Encode(response)
		}
	}))
	t.Cleanup(server.Close)
	return authclient.ServerMetadata{
		Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: server.URL + "/token",
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
	}
}

// authorized asks for a sign-in as the key, and returns its state, and the
// cookie of the browser which asked for it
func authorized(t *testing.T, s *test.Server, key string, authorize credential.CredentialAuthorize) (url.Values, string) {
	t.Helper()
	data, err := json.Marshal(authorize)
	require.NoError(t, err)
	status, header, body := s.Send(t, http.MethodPost, "credential/"+key+"/authorize", http.Header{"Content-Type": {"application/json"}}, data)
	require.Equal(t, http.StatusOK, status, string(body))
	var authorization credential.CredentialAuthorization
	require.NoError(t, json.Unmarshal(body, &authorization))
	u, err := url.Parse(authorization.URL)
	require.NoError(t, err)
	cookie := header.Get("Set-Cookie")
	require.True(t, strings.HasPrefix(cookie, "credential_signin="), cookie)
	assert.Contains(t, cookie, "HttpOnly")
	assert.Contains(t, cookie, "SameSite=Lax")
	assert.Contains(t, cookie, "Path=/api/credential-signin/callback")
	assert.Contains(t, cookie, "Secure")
	return u.Query(), strings.SplitN(cookie, ";", 2)[0]
}

// callback calls the callback, of the query, with the cookie, when it's set
func callback(t *testing.T, s *test.Server, query, cookie string) (int, string) {
	t.Helper()
	header := http.Header{}
	if cookie != "" {
		header.Set("Cookie", cookie)
	}
	status, _, body := s.Request(t, http.MethodGet, "credential-signin/callback?"+query, header)
	return status, string(body)
}

func Test_WebSignIn(t *testing.T) {
	ctx := context.Background()
	redirect := "https://filer.example.com/api/credential-signin/callback"
	var verifiers []string
	server := newWebTokenServer(t, redirect, &verifiers)
	mgr, err := filecredential.New(t.TempDir(), filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	authorize := credential.CredentialAuthorize{RedirectURI: redirect, Scopes: []string{"tasks"}}

	// Without web sign-in, there's no path
	loopback := test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false, httphandler.WithSignIn("EXAMPLE_", server, "EXAMPLE_CLIENT")))
	status, _ := loopback.Do(t, http.MethodPost, "credential/EXAMPLE_TOKEN/authorize", authorize)
	assert.Equal(t, http.StatusNotFound, status)

	// Without the client's credential, no one can sign in
	s := test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false,
		httphandler.WithSignIn("EXAMPLE_", server, "EXAMPLE_CLIENT"),
		httphandler.WithWebSignIn("EXAMPLE_", oauth2.AccessTypeOffline),
	))
	status, _ = s.Do(t, http.MethodPost, "credential/EXAMPLE_TOKEN/authorize", authorize)
	assert.Equal(t, http.StatusServiceUnavailable, status)

	// A desktop app's client can't redirect to the server
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"installed":{"client_id":"desktop-1","client_secret":"secret"}}`)))
	status, body := s.Do(t, http.MethodPost, "credential/EXAMPLE_TOKEN/authorize", authorize)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "desktop app's client")

	// A web application's client signs in, in a browser: the URL to sign in
	// at, of the client, the callback, a state, the PKCE challenge, the
	// scopes, and the options, and the browser's cookie
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"web":{"client_id":"web-1","client_secret":"web-secret"}}`)))
	query, cookie := authorized(t, s, "EXAMPLE_TOKEN", authorize)
	assert.Equal(t, "web-1", query.Get("client_id"))
	assert.Equal(t, redirect, query.Get("redirect_uri"))
	assert.Equal(t, "tasks", query.Get("scope"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.Equal(t, "offline", query.Get("access_type"))
	state := url.QueryEscape(query.Get("state"))
	require.NotEmpty(t, state)

	// The callback, of its state, and the browser's cookie, exchanges the
	// code, with the client, and the verifier, whose challenge was sent, and
	// stores the grant, without the secret, and its page tells the window
	// which opened it
	status, page := callback(t, s, "code=code&state="+state, cookie)
	require.Equal(t, http.StatusOK, status, page)
	assert.Contains(t, page, "You're signed in")
	assert.Contains(t, page, `"credential-signin"`)
	require.Len(t, verifiers, 1)
	assert.Equal(t, oauth2.S256ChallengeFromVerifier(verifiers[0]), query.Get("code_challenge"))
	data, err := mgr.Get(ctx, "EXAMPLE_TOKEN")
	require.NoError(t, err)
	var grant authclient.Grant
	require.NoError(t, json.Unmarshal(data, &grant))
	assert.Equal(t, authclient.Registration{ClientID: "web-1"}, grant.Client)
	assert.Equal(t, []string{"tasks"}, grant.Scopes)
	assert.Equal(t, "refresh", grant.Token.RefreshToken)
	assert.NotContains(t, string(data), "web-secret")

	// Its state is done once, and one which isn't asked for isn't anything
	status, page = callback(t, s, "code=code&state="+state, cookie)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, page, "expired, or was done already")
	status, _ = callback(t, s, "code=code&state=other", cookie)
	assert.Equal(t, http.StatusBadRequest, status)

	// It's only completed by the browser which asked for it, not one which
	// is sent its URL, without the cookie, or with another's, which ends it
	query, _ = authorized(t, s, "EXAMPLE_VICTIM", authorize)
	_, other := authorized(t, s, "EXAMPLE_OTHER", authorize)
	status, page = callback(t, s, "code=code&state="+url.QueryEscape(query.Get("state")), "")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, page, "another browser")
	query, _ = authorized(t, s, "EXAMPLE_VICTIM", authorize)
	status, _ = callback(t, s, "code=code&state="+url.QueryEscape(query.Get("state")), other)
	assert.Equal(t, http.StatusBadRequest, status)
	_, err = mgr.Get(ctx, "EXAMPLE_VICTIM")
	assert.Error(t, err, "it isn't stored")

	// The scopes it asked for are the grant's, when the server doesn't say
	query, cookie = authorized(t, s, "EXAMPLE_NOSCOPE", authorize)
	status, page = callback(t, s, "code=noscope&state="+url.QueryEscape(query.Get("state")), cookie)
	require.Equal(t, http.StatusOK, status, page)
	data, err = mgr.Get(ctx, "EXAMPLE_NOSCOPE")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &grant))
	assert.Equal(t, []string{"tasks"}, grant.Scopes)

	// A sign-in the person refuses says why
	query, cookie = authorized(t, s, "EXAMPLE_REFUSED", authorize)
	status, page = callback(t, s, "error=access_denied&state="+url.QueryEscape(query.Get("state")), cookie)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, page, "access_denied")
	_, err = mgr.Get(ctx, "EXAMPLE_REFUSED")
	assert.Error(t, err)

	// A client which the server refuses is the server's problem
	query, cookie = authorized(t, s, "EXAMPLE_WRONG", authorize)
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"web":{"client_id":"web-1","client_secret":"wrong"}}`)))
	status, page = callback(t, s, "code=code&state="+url.QueryEscape(query.Get("state")), cookie)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, page, "refused the client")
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"web":{"client_id":"web-1","client_secret":"web-secret"}}`)))

	// The callback isn't a credential's, so a credential named callback is
	require.NoError(t, mgr.Set(ctx, "callback", json.RawMessage(`"value"`)))
	status, _ = s.Do(t, http.MethodGet, "credential/callback", nil)
	assert.Equal(t, http.StatusOK, status)

	// Errors
	for name, test := range map[string]struct {
		key  string
		body any
		want int
	}{
		"NotASignIn":  {"OTHER_TOKEN", authorize, http.StatusBadRequest},
		"TheClient":   {"EXAMPLE_CLIENT", authorize, http.StatusBadRequest},
		"BadKey":      {"not-a-key!", authorize, http.StatusBadRequest},
		"NotCallback": {"EXAMPLE_TOKEN", credential.CredentialAuthorize{RedirectURI: "https://filer.example.com/other"}, http.StatusBadRequest},
		"WithQuery":   {"EXAMPLE_TOKEN", credential.CredentialAuthorize{RedirectURI: redirect + "?next=evil"}, http.StatusBadRequest},
		"NotHTTP":     {"EXAMPLE_TOKEN", credential.CredentialAuthorize{RedirectURI: "ftp://filer.example.com/api/credential-signin/callback"}, http.StatusBadRequest},
		"Body":        {"EXAMPLE_TOKEN", "not a request", http.StatusBadRequest},
	} {
		status, _ := s.Do(t, http.MethodPost, "credential/"+test.key+"/authorize", test.body)
		assert.Equal(t, test.want, status, name)
	}
}
