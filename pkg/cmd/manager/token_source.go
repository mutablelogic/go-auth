package manager

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type TokenSource struct {
	store      TokenStore
	endpoint   string
	authClient *auth.Client
	mu         sync.Mutex
}

var _ oauth2.TokenSource = (*TokenSource)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const managerRefreshClientID = "manager"

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewTokenSource(store TokenStore, endpoint string, authClient *auth.Client) *TokenSource {
	return &TokenSource{
		store:      store,
		endpoint:   strings.TrimSpace(endpoint),
		authClient: authClient,
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
	refreshed, err := refreshStoredToken(s.store, s.endpoint, s.authClient, forceRefresh)
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

func refreshStoredToken(store TokenStore, endpoint string, authClient *auth.Client, force bool) (*oauth2.Token, error) {
	endpoint = strings.TrimSpace(endpoint)

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
		ClientID: managerRefreshClientID,
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
