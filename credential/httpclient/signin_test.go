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

package httpclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	authclient "github.com/mutablelogic/go-auth/auth/httpclient"
	credential "github.com/mutablelogic/go-auth/credential"
	filecredential "github.com/mutablelogic/go-auth/credential/file"
	httphandler "github.com/mutablelogic/go-auth/credential/httphandler"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_SignIn(t *testing.T) {
	ctx := context.Background()
	token := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.FormValue("code") != "code" || r.FormValue("client_secret") != "secret" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "refresh_token": "refresh", "expires_in": 3600, "scope": "tasks"})
	}))
	t.Cleanup(token.Close)
	server := authclient.ServerMetadata{Issuer: "https://issuer.example.com", TokenEndpoint: token.URL}
	mgr, err := filecredential.New(t.TempDir(), filecredential.WithPassphrase(1, passphrase))
	require.NoError(t, err)
	require.NoError(t, mgr.Set(ctx, "EXAMPLE_CLIENT", json.RawMessage(`{"client_id":"client-1","client_secret":"secret"}`)))
	c, _ := newClient(t, func(t *testing.T) *test.Server {
		return test.NewServer(t, httphandler.RegisterManagerHandlers(mgr, false, httphandler.WithSignIn("EXAMPLE_", server, "EXAMPLE_CLIENT")))
	})

	// The code is exchanged, and the sign-in stored
	code := authclient.SignInCode{Credential: "EXAMPLE_TOKEN", Code: "code", CodeVerifier: "verifier", RedirectURI: "http://localhost:8085/callback"}
	signIn, err := c.SignIn(ctx, code)
	require.NoError(t, err)
	assert.Equal(t, credential.CredentialSignIn{Key: "EXAMPLE_TOKEN", Issuer: server.Issuer, Scopes: []string{"tasks"}}, *signIn)
	_, err = mgr.Get(ctx, "EXAMPLE_TOKEN")
	require.NoError(t, err)

	// A code which is refused is a bad parameter
	code.Code = "other"
	_, err = c.SignIn(ctx, code)
	assert.ErrorIs(t, err, auth.ErrBadParameter)
}
