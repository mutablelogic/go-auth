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

package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

type stubTokenStore struct {
	mu      sync.Mutex
	token   *oauth2.Token
	issuer  string
	endpoint string
}

func (s *stubTokenStore) StoreToken(endpoint, issuer string, token *oauth2.Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpoint = endpoint
	s.issuer = issuer
	if token == nil {
		s.token = nil
		return nil
	}
	clone := *token
	s.token = &clone
	return nil
}

func (s *stubTokenStore) Token(endpoint string) (*oauth2.Token, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == nil {
		return nil, s.issuer, nil
	}
	clone := *s.token
	return &clone, s.issuer, nil
}

type stubRefresher struct {
	mu      sync.Mutex
	calls   int
	refreshed *oauth2.Token
	lastTokenURL string
	lastClientID string
}

func (s *stubRefresher) RefreshToken(_ context.Context, config *oauth2.Config, _ *oauth2.Token) (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if config != nil {
		s.lastClientID = config.ClientID
		s.lastTokenURL = config.Endpoint.TokenURL
	}
	if s.refreshed == nil {
		return nil, nil
	}
	clone := *s.refreshed
	return &clone, nil
}

func Test_transport_001(t *testing.T) {
	t.Run("PreemptiveRefresh", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := &stubTokenStore{
			token: &oauth2.Token{AccessToken: "expired-token", RefreshToken: "refresh-token", Expiry: time.Now().Add(-time.Hour)},
			issuer: "https://issuer.example.test/api",
		}
		refresher := &stubRefresher{refreshed: &oauth2.Token{AccessToken: "fresh-token", RefreshToken: "fresh-refresh", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

		var authHeaders []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		httpClient := &http.Client{Transport: TokenTransport(server.URL, store, refresher, "client-id")(nil)}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/protected", nil)
		require.NoError(err)
		resp, err := httpClient.Do(req)
		require.NoError(err)
		defer resp.Body.Close()

		require.Equal(http.StatusOK, resp.StatusCode)
		assert.Equal([]string{"Bearer fresh-token"}, authHeaders)
		assert.Equal(1, refresher.calls)
		assert.Equal("client-id", refresher.lastClientID)
		assert.True(strings.HasSuffix(refresher.lastTokenURL, "/auth/code"))
		stored, issuer, err := store.Token(server.URL)
		require.NoError(err)
		require.NotNil(stored)
		assert.Equal("https://issuer.example.test/api", issuer)
		assert.Equal("fresh-token", stored.AccessToken)
	})

	t.Run("RefreshesAfterUnauthorized", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := &stubTokenStore{
			token: &oauth2.Token{AccessToken: "stale-token", RefreshToken: "refresh-token", Expiry: time.Now().Add(time.Hour)},
			issuer: "https://issuer.example.test/api",
		}
		refresher := &stubRefresher{refreshed: &oauth2.Token{AccessToken: "fresh-token", RefreshToken: "fresh-refresh", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

		var authHeaders []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			if r.Header.Get("Authorization") != "Bearer fresh-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		httpClient := &http.Client{Transport: TokenTransport(server.URL, store, refresher, "")(nil)}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/protected", nil)
		require.NoError(err)
		resp, err := httpClient.Do(req)
		require.NoError(err)
		defer resp.Body.Close()

		require.Equal(http.StatusOK, resp.StatusCode)
		assert.Equal([]string{"Bearer stale-token", "Bearer fresh-token"}, authHeaders)
		assert.Equal(1, refresher.calls)
	})

	t.Run("AllowsNonReplayableInitialRequest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := &stubTokenStore{
			token: &oauth2.Token{AccessToken: "current-token", RefreshToken: "refresh-token", Expiry: time.Now().Add(time.Hour)},
			issuer: "https://issuer.example.test/api",
		}
		refresher := &stubRefresher{refreshed: &oauth2.Token{AccessToken: "fresh-token", RefreshToken: "fresh-refresh", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

		var authHeaders []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		httpClient := &http.Client{Transport: TokenTransport(server.URL, store, refresher, "")(nil)}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, server.URL+"/protected", strings.NewReader(""))
		require.NoError(err)
		req.GetBody = nil
		resp, err := httpClient.Do(req)
		require.NoError(err)
		defer resp.Body.Close()

		require.Equal(http.StatusOK, resp.StatusCode)
		assert.Equal([]string{"Bearer current-token"}, authHeaders)
		assert.Equal(0, refresher.calls)
	})
}