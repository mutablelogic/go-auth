package httpclient

import (
	"context"
	"fmt"
	"strings"
	"sync"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type tokenSource struct {
	ctx    context.Context
	client *Client
	mu     sync.Mutex
	token  *oauth2.Token
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// TokenSource returns an oauth2.TokenSource which uses the supplied local
// session token until it expires, then refreshes it using the auth server.
func (c *Client) TokenSource(ctx context.Context, token string) (oauth2.TokenSource, error) {
	if c == nil || c.Client == nil {
		return nil, fmt.Errorf("client is required")
	}
	parsed, err := oauthToken(token)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return &tokenSource{ctx: ctx, client: c, token: parsed}, nil
}

func (s *tokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != nil && s.token.Valid() {
		return cloneOAuthToken(s.token), nil
	}
	if s.token == nil || strings.TrimSpace(s.token.AccessToken) == "" {
		return nil, fmt.Errorf("token is required")
	}

	response, err := s.client.Refresh(s.ctx, s.token.AccessToken)
	if err != nil {
		return nil, err
	}
	refreshed, err := oauthToken(response.Token)
	if err != nil {
		return nil, err
	}
	s.token = refreshed
	return cloneOAuthToken(s.token), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func oauthToken(raw string) (*oauth2.Token, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("token is required")
	}
	claims := new(jwt.RegisteredClaims)
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	token := &oauth2.Token{
		AccessToken: raw,
		TokenType:   "Bearer",
	}
	if claims.ExpiresAt != nil {
		token.Expiry = claims.ExpiresAt.Time
	}
	return token, nil
}

func cloneOAuthToken(token *oauth2.Token) *oauth2.Token {
	if token == nil {
		return nil
	}
	clone := *token
	return &clone
}
