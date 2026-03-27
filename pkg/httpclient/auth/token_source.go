package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
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
		endpoint:   strings.TrimSpace(c.Endpoint),
		clientID:   strings.TrimSpace(clientID),
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
	if clientID == "" {
		return nil, fmt.Errorf("client ID is required")
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
