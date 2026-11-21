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
// exchanges "code", for the web application's client "web-1", whose secret
// is "web-secret", of the redirect, and any verifier, which it records
func newWebTokenServer(t *testing.T, redirect string, verifiers *[]string) authclient.ServerMetadata {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.FormValue("client_id") != "web-1" || r.FormValue("client_secret") != "web-secret":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		case r.FormValue("code") != "code" || r.FormValue("redirect_uri") != redirect:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		default:
			*verifiers = append(*verifiers, r.FormValue("code_verifier"))
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh", "expires_in": 3600, "scope": "tasks"})
		}
	}))
	t.Cleanup(server.Close)
	return authclient.ServerMetadata{Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: server.URL + "/token"}
}

func Test_WebSignIn(t *testing.T) {
	ctx := context.Background()
	redirect := "https://filer.example.com/api/credential/callback"
	var verifiers []string
	server := newWebTokenServer(t, redirect, &verifiers)
	mgr, err := filecredential.New(t.TempDir(), filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	authorize := credential.CredentialAuthorize{RedirectURI: redirect, Scopes: []string{"tasks"}}

	// Without a web client, there's no path
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

	// A web application's client signs in, in a browser
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"web":{"client_id":"web-1","client_secret":"web-secret"}}`)))

	// The URL to sign in at, of the web client, the callback, a state, the
	// PKCE challenge, the scopes, and the options
	var authorization credential.CredentialAuthorization
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPost, "credential/EXAMPLE_TOKEN/authorize", authorize, &authorization))
	u, err := url.Parse(authorization.URL)
	require.NoError(t, err)
	query := u.Query()
	assert.Equal(t, "issuer.example.com", u.Host)
	assert.Equal(t, "web-1", query.Get("client_id"))
	assert.Equal(t, redirect, query.Get("redirect_uri"))
	assert.Equal(t, "tasks", query.Get("scope"))
	assert.Equal(t, "S256", query.Get("code_challenge_method"))
	assert.Equal(t, "offline", query.Get("access_type"))
	state := query.Get("state")
	require.NotEmpty(t, state)

	// The callback, of its state, exchanges the code, with the web client,
	// and the verifier, whose challenge was sent, and stores the grant,
	// without the secret, and its page tells the window which opened it
	status, body = s.Do(t, http.MethodGet, "credential/callback?code=code&state="+url.QueryEscape(state), nil)
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Contains(t, string(body), "You're signed in")
	assert.Contains(t, string(body), `"credential-signin"`)
	require.Len(t, verifiers, 1)
	assert.Equal(t, oauth2.S256ChallengeFromVerifier(verifiers[0]), query.Get("code_challenge"))
	data, err := mgr.Get(ctx, "EXAMPLE_TOKEN")
	require.NoError(t, err)
	var grant authclient.Grant
	require.NoError(t, json.Unmarshal(data, &grant))
	assert.Equal(t, authclient.Registration{ClientID: "web-1"}, grant.Client)
	assert.Equal(t, "refresh", grant.Token.RefreshToken)
	assert.NotContains(t, string(data), "web-secret")

	// Its state is done once, and one which isn't asked for isn't anything
	status, body = s.Do(t, http.MethodGet, "credential/callback?code=code&state="+url.QueryEscape(state), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "expired, or was done already")
	status, _ = s.Do(t, http.MethodGet, "credential/callback?code=code&state=other", nil)
	assert.Equal(t, http.StatusBadRequest, status)

	// A sign-in the person refuses says why
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPost, "credential/EXAMPLE_OTHER/authorize", authorize, &authorization))
	u, err = url.Parse(authorization.URL)
	require.NoError(t, err)
	status, body = s.Do(t, http.MethodGet, "credential/callback?error=access_denied&state="+url.QueryEscape(u.Query().Get("state")), nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "access_denied")
	_, err = mgr.Get(ctx, "EXAMPLE_OTHER")
	assert.Error(t, err)

	// The web application's client signs in with a loopback address, too,
	// of a command line tool, which it registers
	status, _ = s.Do(t, http.MethodPost, "credential/EXAMPLE_LOOPBACK/signin", credential.CredentialCode{Code: "code", CodeVerifier: "verifier", RedirectURI: redirect})
	assert.Equal(t, http.StatusBadRequest, status, "of the server's callback, which isn't a loopback address")

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
		"NotHTTP":     {"EXAMPLE_TOKEN", credential.CredentialAuthorize{RedirectURI: "ftp://filer.example.com/api/credential/callback"}, http.StatusBadRequest},
		"Body":        {"EXAMPLE_TOKEN", "not a request", http.StatusBadRequest},
	} {
		status, _ := s.Do(t, http.MethodPost, "credential/"+test.key+"/authorize", test.body)
		assert.Equal(t, test.want, status, name)
	}
}
