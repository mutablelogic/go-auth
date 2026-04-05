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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

func TestOAuth2ConfigWithoutClientID(t *testing.T) {
	config, err := OAuth2Config(oidc.BaseConfiguration{TokenEndpoint: "https://issuer.example.test/auth/code"}, "", "")
	require.NoError(t, err)
	require.NotNil(t, config)
	require.Empty(t, config.ClientID)
	require.Equal(t, "https://issuer.example.test/auth/code", config.Endpoint.TokenURL)
}

func TestOAuth2ConfigUsesTokenEndpointAuthMethods(t *testing.T) {
	config, err := OAuth2Config(oidc.BaseConfiguration{
		AuthorizationEndpoint:    "https://issuer.example.test/auth/authorize",
		TokenEndpoint:            "https://issuer.example.test/auth/code",
		TokenEndpointAuthMethods: []string{"client_secret_post"},
	}, "client-id", "client-secret")
	require.NoError(t, err)
	require.Equal(t, oauth2.AuthStyleInParams, config.Endpoint.AuthStyle)

	flowConfig, err := OAuth2ConfigForFlow(&oidc.AuthorizationCodeFlow{
		AuthorizationEndpoint:    "https://issuer.example.test/auth/authorize",
		TokenEndpoint:            "https://issuer.example.test/auth/code",
		TokenEndpointAuthMethods: []string{"client_secret_basic"},
		RedirectURL:              "http://localhost/callback",
	}, "client-secret")
	require.NoError(t, err)
	require.Equal(t, oauth2.AuthStyleInHeader, flowConfig.Endpoint.AuthStyle)
}

func TestRefreshStoredTokenWithoutClientID(t *testing.T) {
	tokenEndpointCalled := false
	tokenEndpointForm := url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		tokenEndpointCalled = true
		tokenEndpointForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "refreshed-access-token",
			"refresh_token": "refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}))
	}))
	defer server.Close()

	store := &stubTokenStore{
		token:  &oauth2.Token{AccessToken: "expired-access-token", RefreshToken: "refresh-token"},
		issuer: server.URL,
	}
	client, err := New(server.URL)
	require.NoError(t, err)

	refreshed, err := refreshStoredToken(store, server.URL, "", client, true)
	require.NoError(t, err)
	require.NotNil(t, refreshed)
	require.Equal(t, "refreshed-access-token", refreshed.AccessToken)
	require.True(t, tokenEndpointCalled)
	require.Equal(t, "refresh_token", tokenEndpointForm.Get("grant_type"))
	require.Equal(t, "refresh-token", tokenEndpointForm.Get("refresh_token"))
	require.Empty(t, tokenEndpointForm.Get("client_id"))
	require.Equal(t, refreshed.AccessToken, store.stored.AccessToken)
	require.Equal(t, server.URL, store.storedIssuer)
}

type stubTokenStore struct {
	token        *oauth2.Token
	issuer       string
	stored       *oauth2.Token
	storedIssuer string
}

func (s *stubTokenStore) StoreToken(_ string, issuer string, token *oauth2.Token) error {
	s.storedIssuer = strings.TrimSpace(issuer)
	if token != nil {
		clone := *token
		s.stored = &clone
	}
	return nil
}

func (s *stubTokenStore) Token(_ string) (*oauth2.Token, string, error) {
	if s.token == nil {
		return nil, s.issuer, nil
	}
	clone := *s.token
	return &clone, s.issuer, nil
}

var _ TokenStore = (*stubTokenStore)(nil)

func TestClientRefreshTokenWithoutClientID(t *testing.T) {
	tokenEndpointForm := url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		tokenEndpointForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(t, err)
	config := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: server.URL}}
	_, err = client.RefreshToken(context.Background(), config, &oauth2.Token{RefreshToken: "refresh-token"})
	require.NoError(t, err)
	require.Empty(t, tokenEndpointForm.Get("client_id"))
}
