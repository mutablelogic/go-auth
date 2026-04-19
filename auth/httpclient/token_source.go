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

package httpclient

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	// Packages
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

type TokenStore interface {
	StoreToken(endpoint, issuer string, token *oauth2.Token) error
	Token(endpoint string) (*oauth2.Token, string, error)
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type TokenSource struct {
	store      TokenStore
	endpoint   string
	clientID   string
	authClient *Client
	mu         sync.Mutex
}

var _ oauth2.TokenSource = (*TokenSource)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (c *Client) NewTokenSource(store TokenStore, clientID string) *TokenSource {
	return &TokenSource{
		store:      store,
		endpoint:   c.Endpoint,
		clientID:   clientID,
		authClient: c,
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (s *TokenSource) Token() (*oauth2.Token, error) {
	return s.token(false)
}

func (s *TokenSource) Refresh() (*oauth2.Token, error) {
	return s.token(true)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (s *TokenSource) token(forceRefresh bool) (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, _, err := s.store.Token(s.endpoint)
	if err != nil || token == nil {
		return nil, err
	}
	if !forceRefresh && token.Valid() {
		clone := *token
		return &clone, nil
	}
	refreshed, err := refreshStoredToken(s.store, s.endpoint, s.clientID, s.authClient, forceRefresh)
	if err != nil {
		if !forceRefresh && token.Valid() {
			clone := *token
			return &clone, nil
		}
		return nil, err
	}
	if refreshed == nil {
		return nil, nil
	}
	clone := *refreshed
	return &clone, nil
}

func refreshStoredToken(store TokenStore, endpoint, clientID string, authClient *Client, force bool) (*oauth2.Token, error) {
	endpoint = strings.TrimSpace(endpoint)
	clientID = strings.TrimSpace(clientID)

	if store == nil {
		return nil, fmt.Errorf("token store is required")
	}
	token, issuer, err := store.Token(endpoint)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, nil
	}
	if authClient == nil {
		return nil, fmt.Errorf("auth client is required")
	}
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		issuer = endpoint
	}
	if strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	oauthConfig := &oauth2.Config{
		ClientID: clientID,
		Endpoint: oauth2.Endpoint{TokenURL: oidc.AuthCodeURL(issuer)},
	}
	if force {
		clone := *token
		clone.Expiry = clone.Expiry.Add(-time.Until(clone.Expiry) - time.Second)
		token = &clone
	}
	refreshed, err := authClient.RefreshToken(context.Background(), oauthConfig, token)
	if err != nil {
		return nil, err
	}
	if err := store.StoreToken(endpoint, issuer, refreshed); err != nil {
		return nil, err
	}
	return refreshed, nil
}
