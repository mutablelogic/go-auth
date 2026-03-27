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

package manager

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	managerclient "github.com/djthorpe/go-auth/pkg/httpclient/manager"
	clientpkg "github.com/mutablelogic/go-client"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	trace "go.opentelemetry.io/otel/trace"
	oauth2 "golang.org/x/oauth2"
)

type fakeCmd struct {
	ctx      context.Context
	endpoint string
	store    map[string]any
	mu       sync.Mutex
	logger   *slog.Logger
}

func newFakeCmd(endpoint string) *fakeCmd {
	return &fakeCmd{
		ctx:      context.Background(),
		endpoint: endpoint,
		store:    make(map[string]any),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (f *fakeCmd) Name() string             { return "test" }
func (f *fakeCmd) Description() string      { return "test" }
func (f *fakeCmd) Version() string          { return "test" }
func (f *fakeCmd) Context() context.Context { return f.ctx }
func (f *fakeCmd) Logger() *slog.Logger     { return f.logger }
func (f *fakeCmd) Tracer() trace.Tracer     { return nil }
func (f *fakeCmd) ClientEndpoint() (string, []clientpkg.ClientOpt, error) {
	return f.endpoint, nil, nil
}
func (f *fakeCmd) Get(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.store[key]
}
func (f *fakeCmd) GetString(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, _ := f.store[key].(string)
	return value
}
func (f *fakeCmd) Set(key string, value any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if value == nil {
		delete(f.store, key)
	} else {
		f.store[key] = value
	}
	return nil
}
func (f *fakeCmd) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.store))
	for key := range f.store {
		keys = append(keys, key)
	}
	return keys
}
func (f *fakeCmd) IsTerm() bool               { return false }
func (f *fakeCmd) IsDebug() bool              { return false }
func (f *fakeCmd) HTTPAddr() string           { return "" }
func (f *fakeCmd) HTTPPrefix() string         { return "" }
func (f *fakeCmd) HTTPOrigin() string         { return "" }
func (f *fakeCmd) HTTPTimeout() time.Duration { return 0 }

func TestAuthTransportPreemptiveRefresh(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var protectedAuth []string
	var refreshCalls int
	issuerURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuerURL,
				"authorization_endpoint": "http://example.invalid/auth/authorize",
				"token_endpoint":         issuerURL + "/auth/code",
			})
		case "/auth/code":
			refreshCalls++
			require.NoError(r.ParseForm())
			assert.Equal("refresh_token", r.PostForm.Get("grant_type"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "fresh-token",
				"refresh_token": "fresh-refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/protected":
			protectedAuth = append(protectedAuth, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer fresh-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	issuerURL = server.URL
	defer server.Close()

	cmd := newFakeCmd(server.URL)
	store := NewCmdTokenStore(cmd)
	require.NoError(store.StoreToken(server.URL, server.URL, &oauth2.Token{
		AccessToken:  "expired-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(-time.Hour),
	}))

	authClient, err := auth.New(server.URL)
	require.NoError(err)
	httpClient := &http.Client{Transport: newAuthTransport(nil, cmd, server.URL, authClient)}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/protected", nil)
	require.NoError(err)
	resp, err := httpClient.Do(req)
	require.NoError(err)
	defer resp.Body.Close()

	require.Equal(http.StatusOK, resp.StatusCode)
	assert.Equal([]string{"Bearer fresh-token"}, protectedAuth)
	assert.Equal(1, refreshCalls)
	stored, issuer, err := store.Token(server.URL)
	require.NoError(err)
	require.NotNil(stored)
	assert.Equal(server.URL, issuer)
	assert.Equal("fresh-token", stored.AccessToken)
	assert.Equal("fresh-refresh", stored.RefreshToken)
}

func TestAuthTransportAllowsNonReplayableInitialRequest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var protectedAuth []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/protected" {
			http.NotFound(w, r)
			return
		}
		protectedAuth = append(protectedAuth, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cmd := newFakeCmd(server.URL)
	store := NewCmdTokenStore(cmd)
	require.NoError(store.StoreToken(server.URL, server.URL, &oauth2.Token{
		AccessToken:  "current-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}))

	authClient, err := auth.New(server.URL)
	require.NoError(err)
	httpClient := &http.Client{Transport: newAuthTransport(nil, cmd, server.URL, authClient)}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, server.URL+"/protected", strings.NewReader(""))
	require.NoError(err)
	req.GetBody = nil

	resp, err := httpClient.Do(req)
	require.NoError(err)
	defer resp.Body.Close()

	require.Equal(http.StatusOK, resp.StatusCode)
	assert.Equal([]string{"Bearer current-token"}, protectedAuth)
}

func TestAuthTransportRefreshesAfterUnauthorized(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var protectedAuth []string
	var refreshCalls int
	issuerURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 issuerURL,
				"authorization_endpoint": issuerURL + "/auth/authorize",
				"token_endpoint":         issuerURL + "/auth/code",
			})
		case "/auth/code":
			refreshCalls++
			require.NoError(r.ParseForm())
			assert.Equal("refresh_token", r.PostForm.Get("grant_type"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "fresh-token",
				"refresh_token": "fresh-refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
		case "/protected":
			protectedAuth = append(protectedAuth, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer fresh-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	issuerURL = server.URL
	defer server.Close()

	cmd := newFakeCmd(server.URL)
	store := NewCmdTokenStore(cmd)
	require.NoError(store.StoreToken(server.URL, server.URL, &oauth2.Token{
		AccessToken:  "stale-token",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}))

	authClient, err := auth.New(server.URL)
	require.NoError(err)
	httpClient := &http.Client{Transport: newAuthTransport(nil, cmd, server.URL, authClient)}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/protected", nil)
	require.NoError(err)
	resp, err := httpClient.Do(req)
	require.NoError(err)
	defer resp.Body.Close()

	require.Equal(http.StatusOK, resp.StatusCode)
	assert.Equal([]string{"Bearer stale-token", "Bearer fresh-token"}, protectedAuth)
	assert.Equal(1, refreshCalls)
	stored, issuer, err := store.Token(server.URL)
	require.NoError(err)
	require.NotNil(stored)
	assert.Equal(server.URL, issuer)
	assert.Equal("fresh-token", stored.AccessToken)
	assert.Equal("fresh-refresh", stored.RefreshToken)
}

func TestWithUnauthenticatedClientSkipsStoredTokenRefresh(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var refreshCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/config":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"local": map[string]any{}})
		case "/auth/code":
			refreshCalls++
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 400, "reason": "expired"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cmd := newFakeCmd(server.URL)
	store := NewCmdTokenStore(cmd)
	require.NoError(store.StoreToken(server.URL, server.URL, &oauth2.Token{
		AccessToken:  "expired-token",
		RefreshToken: "expired-refresh-token",
		Expiry:       time.Now().Add(-time.Hour),
	}))

	err := withUnauthenticatedClient(cmd, func(manager *managerclient.Client, endpoint string) error {
		config, err := manager.Config(context.Background())
		if err != nil {
			return err
		}
		assert.Contains(config, "local")
		assert.Equal(server.URL, endpoint)
		return nil
	})
	require.NoError(err)
	assert.Equal(0, refreshCalls)
}
