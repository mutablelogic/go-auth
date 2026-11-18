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
	"testing"

	// Packages
	authclient "github.com/mutablelogic/go-auth/auth/httpclient"
	credential "github.com/mutablelogic/go-auth/credential"
	filecredential "github.com/mutablelogic/go-auth/credential/file"
	httphandler "github.com/mutablelogic/go-auth/credential/httphandler"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// newTokenServer returns an authorization server, whose token endpoint
// exchanges "code", of "verifier", for the client "client-1", whose secret
// is "secret", and refuses any other client as invalid_client
func newTokenServer(t *testing.T) authclient.ServerMetadata {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.FormValue("client_id") != "client-1" || r.FormValue("client_secret") != "secret":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		case r.FormValue("grant_type") != "authorization_code" || r.FormValue("code") != "code" || r.FormValue("code_verifier") != "verifier":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh", "expires_in": 3600, "scope": "tasks calendar"})
		}
	}))
	t.Cleanup(server.Close)
	return authclient.ServerMetadata{Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: server.URL + "/token"}
}

func Test_SignIn(t *testing.T) {
	ctx := context.Background()
	mgr, err := filecredential.New(t.TempDir(), filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	server := newTokenServer(t)
	s := test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false, httphandler.WithSignIn("EXAMPLE_", server, "EXAMPLE_CLIENT")))
	code := credential.CredentialCode{Code: "code", CodeVerifier: "verifier", RedirectURI: "http://127.0.0.1:8085/callback"}

	// Without a client, no one can sign in
	status, _ := s.Do(t, http.MethodPost, "credential/EXAMPLE_TOKEN/signin", code)
	assert.Equal(t, http.StatusServiceUnavailable, status)

	// The code is exchanged, with the client, of the file Google's console
	// downloads, and the grant is stored, without the client's secret
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"installed":{"client_id":"client-1","client_secret":"secret"}}`)))
	var signIn credential.CredentialSignIn
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPost, "credential/EXAMPLE_TOKEN/signin", code, &signIn))
	assert.Equal(t, credential.CredentialSignIn{Key: "EXAMPLE_TOKEN", Issuer: server.Issuer, Scopes: []string{"tasks", "calendar"}}, signIn)
	data, err := mgr.Get(ctx, "EXAMPLE_TOKEN")
	require.NoError(t, err)
	var grant authclient.Grant
	require.NoError(t, json.Unmarshal(data, &grant))
	assert.Equal(t, server, grant.Server)
	assert.Equal(t, authclient.Registration{ClientID: "client-1"}, grant.Client)
	assert.Equal(t, "refresh", grant.Token.RefreshToken)
	assert.NotContains(t, string(data), "secret")

	// Errors
	for name, test := range map[string]struct {
		key  string
		body any
		want int
	}{
		"NotASignIn":  {"OTHER_TOKEN", code, http.StatusBadRequest},
		"TheClient":   {"EXAMPLE_CLIENT", code, http.StatusBadRequest},
		"BadKey":      {"not-a-key!", code, http.StatusBadRequest},
		"NotLoopback": {"EXAMPLE_TOKEN", credential.CredentialCode{Code: "code", CodeVerifier: "verifier", RedirectURI: "http://example.com/callback"}, http.StatusBadRequest},
		"HTTPS":       {"EXAMPLE_TOKEN", credential.CredentialCode{Code: "code", CodeVerifier: "verifier", RedirectURI: "https://127.0.0.1/callback"}, http.StatusBadRequest},
		"Refused":     {"EXAMPLE_TOKEN", credential.CredentialCode{Code: "other", CodeVerifier: "verifier", RedirectURI: code.RedirectURI}, http.StatusBadRequest},
		"NoCode":      {"EXAMPLE_TOKEN", credential.CredentialCode{RedirectURI: code.RedirectURI}, http.StatusBadRequest},
		"Body":        {"EXAMPLE_TOKEN", "not a code", http.StatusBadRequest},
	} {
		status, _ := s.Do(t, http.MethodPost, "credential/"+test.key+"/signin", test.body)
		assert.Equal(t, test.want, status, name)
	}

	// A client which the server refuses is unavailable, and the sign-in
	// isn't replaced
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"client_id":"client-1","client_secret":"wrong"}`)))
	status, _ = s.Do(t, http.MethodPost, "credential/EXAMPLE_OTHER/signin", code)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	_, err = mgr.Get(ctx, "EXAMPLE_OTHER")
	assert.Error(t, err)

	// With overlapping prefixes, no client is replaced, and a key is the
	// sign-in of the longest prefix's server
	other := server
	other.Issuer = "https://other.example.com"
	both := test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false, httphandler.WithSignIn("EXAMPLE_", server, "EXAMPLE_CLIENT"), httphandler.WithSignIn("EXAMPLE_ALT_", other, "EXAMPLE_ALT_CLIENT")))
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"client_id":"client-1","client_secret":"secret"}`)))
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_ALT_CLIENT", json.RawMessage(`{"client_id":"client-1","client_secret":"secret"}`)))
	status, _ = both.Do(t, http.MethodPost, "credential/EXAMPLE_ALT_CLIENT/signin", code)
	assert.Equal(t, http.StatusBadRequest, status)
	data, err = mgr.Get(ctx, "EXAMPLE_ALT_CLIENT")
	require.NoError(t, err)
	assert.JSONEq(t, `{"client_id":"client-1","client_secret":"secret"}`, string(data), "the client isn't replaced")
	require.Equal(t, http.StatusOK, both.JSON(t, http.MethodPost, "credential/EXAMPLE_ALT_TOKEN/signin", code, &signIn))
	assert.Equal(t, other.Issuer, signIn.Issuer)

	// Without a server whose sign-ins are stored, there's no path
	plain := test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false))
	status, _ = plain.Do(t, http.MethodPost, "credential/EXAMPLE_TOKEN/signin", code)
	assert.Equal(t, http.StatusNotFound, status)
}
