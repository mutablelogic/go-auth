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

package grant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	authclient "github.com/mutablelogic/go-auth/auth/httpclient"
	grant "github.com/mutablelogic/go-auth/credential/grant"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

const (
	clientKey = "EXAMPLE_CLIENT"
	tokenKey  = "EXAMPLE_TOKEN"
	clientID  = "client-1"
)

// credentials is a provider of credentials, in memory
type credentials struct {
	sync.Mutex
	values map[string]json.RawMessage
}

func (c *credentials) Get(_ context.Context, key string) (json.RawMessage, error) {
	c.Lock()
	defer c.Unlock()
	if value, exists := c.values[key]; exists {
		return value, nil
	}
	return nil, auth.ErrNotFound.Withf("credential %q", key)
}
func (c *credentials) Set(_ context.Context, key string, value json.RawMessage) error {
	c.Lock()
	defer c.Unlock()
	c.values[key] = value
	return nil
}

// grantOf returns the sign-in which is stored
func (c *credentials) grantOf(t *testing.T) authclient.Grant {
	t.Helper()
	c.Lock()
	defer c.Unlock()
	var g authclient.Grant
	require.NoError(t, json.Unmarshal(c.values[tokenKey], &g))
	return g
}

// newServer returns an authorization server, whose token endpoint refreshes
// the refresh token "refresh", for the client, with its secret "secret",
// and refuses another secret as invalid_client, and counts its refreshes
func newServer(t *testing.T) (authclient.ServerMetadata, *int) {
	t.Helper()
	var mu sync.Mutex
	refreshes := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.FormValue("client_secret") != "secret":
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
		case r.FormValue("grant_type") != "refresh_token" || r.FormValue("refresh_token") != "refresh" || r.FormValue("client_id") != clientID:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
		default:
			*refreshes++
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new", "token_type": "Bearer", "expires_in": 3600})
		}
	}))
	t.Cleanup(server.Close)
	return authclient.ServerMetadata{Issuer: "https://issuer.example.com", AuthorizationEndpoint: "https://issuer.example.com/auth", TokenEndpoint: server.URL + "/token"}, refreshes
}

// newCredentials returns the client, and a sign-in, which is changed by fn
func newCredentials(t *testing.T, server authclient.ServerMetadata, fn func(*authclient.Grant)) *credentials {
	t.Helper()
	g := authclient.Grant{
		Server: server,
		Client: authclient.Registration{ClientID: clientID},
		Scopes: []string{"read"},
		Token:  &oauth2.Token{AccessToken: "access", TokenType: "Bearer", RefreshToken: "refresh", Expiry: time.Now().Add(time.Hour)},
	}
	if fn != nil {
		fn(&g)
	}
	data, err := json.Marshal(g)
	require.NoError(t, err)
	return &credentials{values: map[string]json.RawMessage{
		clientKey: json.RawMessage(`{"installed":{"client_id":"` + clientID + `","client_secret":"secret"}}`),
		tokenKey:  data,
	}}
}

func Test_Source(t *testing.T) {
	ctx := context.Background()
	server, refreshes := newServer(t)
	config := grant.Config{Server: server, Client: clientKey, Key: tokenKey, Required: []string{"read", "write"}, Scopes: []string{"read"}}
	signIn := func(t *testing.T, err error) *authclient.SignIn {
		t.Helper()
		require.ErrorIs(t, err, auth.ErrInvalidProvider)
		s := authclient.SignInOf(err)
		require.NotNil(t, s)
		assert.Equal(t, server, s.Server)
		assert.Equal(t, clientID, s.ClientID)
		assert.Equal(t, tokenKey, s.Credential)
		return s
	}

	// A valid token, which isn't refreshed
	src, err := grant.New(ctx, newCredentials(t, server, nil), config)
	require.NoError(t, err)
	token, err := src.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access", token.AccessToken)
	assert.Zero(t, *refreshes)

	// An expired token, which is refreshed, and stored, keeping its refresh
	// token, and isn't refreshed again
	creds := newCredentials(t, server, func(g *authclient.Grant) { g.Token.Expiry = time.Now().Add(-time.Minute) })
	src, err = grant.New(ctx, creds, config)
	require.NoError(t, err)
	token, err = src.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "new", token.AccessToken)
	stored := creds.grantOf(t)
	assert.Equal(t, "new", stored.Token.AccessToken)
	assert.Equal(t, "refresh", stored.Token.RefreshToken)
	assert.Equal(t, authclient.Registration{ClientID: clientID}, stored.Client, "without the client's secret")
	_, err = src.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, *refreshes)

	// A sign-in which is replaced is used
	replaced := newCredentials(t, server, func(g *authclient.Grant) { g.Token.AccessToken = "replaced" })
	creds.Set(ctx, tokenKey, replaced.values[tokenKey])
	token, err = src.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "replaced", token.AccessToken)

	// Signing in: without a sign-in, or of another server, or client, or
	// without a token, or the scopes, which asks for those it has too
	missing := newCredentials(t, server, nil)
	delete(missing.values, tokenKey)
	_, err = grant.New(ctx, missing, config)
	assert.Equal(t, []string{"read"}, signIn(t, err).Scopes)
	for name, fn := range map[string]func(*authclient.Grant){
		"Server":   func(g *authclient.Grant) { g.Server.Issuer = "https://other.example.com" },
		"Client":   func(g *authclient.Grant) { g.Client.ClientID = "client-2" },
		"NoToken":  func(g *authclient.Grant) { g.Token = nil },
		"Endpoint": func(g *authclient.Grant) { g.Server.TokenEndpoint = "" },
		"Revoked": func(g *authclient.Grant) {
			g.Token.Expiry, g.Token.RefreshToken = time.Now().Add(-time.Minute), "revoked"
		},
	} {
		src, err := grant.New(ctx, newCredentials(t, server, fn), config)
		if err == nil {
			_, err = src.Token(ctx)
		}
		require.Error(t, err, name)
		signIn(t, err)
	}
	_, err = grant.New(ctx, newCredentials(t, server, func(g *authclient.Grant) { g.Scopes = []string{"other"} }), config)
	assert.Equal(t, []string{"read", "other"}, signIn(t, err).Scopes)

	// SignIn, such as when an API doesn't accept the token
	src, err = grant.New(ctx, newCredentials(t, server, nil), config)
	require.NoError(t, err)
	err = src.SignIn(auth.ErrInvalidProvider.With("not accepted"))
	signIn(t, err)

	// A client which the server refuses isn't signed in to again
	wrong := newCredentials(t, server, func(g *authclient.Grant) { g.Token.Expiry = time.Now().Add(-time.Minute) })
	wrong.values[clientKey] = json.RawMessage(`{"client_id":"` + clientID + `","client_secret":"wrong"}`)
	src, err = grant.New(ctx, wrong, config)
	require.NoError(t, err)
	_, err = src.Token(ctx)
	assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
	assert.Nil(t, authclient.SignInOf(err))

	// Without a client, or credentials, no one can sign in, and a client
	// which isn't one is bad
	noClient := newCredentials(t, server, nil)
	delete(noClient.values, clientKey)
	_, err = grant.New(ctx, noClient, config)
	assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
	_, err = grant.New(ctx, nil, config)
	assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
	badClient := newCredentials(t, server, nil)
	badClient.values[clientKey] = json.RawMessage(`{}`)
	_, err = grant.New(ctx, badClient, config)
	assert.ErrorIs(t, err, auth.ErrBadParameter)
}
