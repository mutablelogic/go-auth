package httpclient

import (
	"context"
	"fmt"
	"strings"
	"sync"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
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

// OAuth2Config resolves a configured auth provider and returns an oauth2
// client configuration that can be used for browser-based auth code flows.
func (c *Client) OAuth2Config(ctx context.Context, provider, redirectURL string, scopes ...string) (*oauth2.Config, error) {
	redirectURL = strings.TrimSpace(redirectURL)
	if redirectURL == "" {
		return nil, fmt.Errorf("redirect URL is required")
	}
	key, public, err := c.OAuthProviderConfig(ctx, provider)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(public.ClientID) == "" {
		return nil, fmt.Errorf("auth provider %q has no client_id", key)
	}
	discovery, err := c.OIDCConfig(ctx, public.Issuer)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(discovery.AuthorizationEndpoint) == "" {
		return nil, fmt.Errorf("issuer %q has no authorization_endpoint", public.Issuer)
	}
	if strings.TrimSpace(discovery.TokenEndpoint) == "" {
		return nil, fmt.Errorf("issuer %q has no token_endpoint", public.Issuer)
	}
	scopes = oidc.AuthorizationScopes(*discovery, scopes...)
	return &oauth2.Config{
		ClientID:    public.ClientID,
		RedirectURL: redirectURL,
		Scopes:      scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}, nil
}

// AuthCodeURL builds a provider-specific authorization URL for an auth code
// flow after resolving client configuration and discovery metadata.
func (c *Client) AuthCodeURL(ctx context.Context, provider, redirectURL, state string, opts ...oauth2.AuthCodeOption) (string, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return "", fmt.Errorf("state is required")
	}
	config, err := c.OAuth2Config(ctx, provider, redirectURL)
	if err != nil {
		return "", err
	}
	return config.AuthCodeURL(state, opts...), nil
}

// OAuthLoginBootstrap resolves provider config and discovery metadata into an
// OIDC authorization flow payload the CLI can use to start interactive login.
func (c *Client) OAuthLoginBootstrap(ctx context.Context, provider, redirectURL string) (*oidc.AuthorizationCodeFlow, error) {
	key, public, err := c.OAuthProviderConfig(ctx, provider)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(public.ClientID) == "" {
		return nil, fmt.Errorf("auth provider %q has no client_id", key)
	}
	discovery, err := c.OIDCConfig(ctx, public.Issuer)
	if err != nil {
		return nil, err
	}
	flow, err := oidc.NewAuthorizationCodeFlow(*discovery, public.ClientID, redirectURL)
	if err != nil {
		return nil, err
	}
	flow.Issuer = public.Issuer
	_ = key
	return flow, nil
}

// ExchangeAuthorizationCode exchanges an OAuth authorization code for an
// upstream OIDC id_token using the supplied flow configuration.
func (c *Client) ExchangeAuthorizationCode(ctx context.Context, flow *oidc.AuthorizationCodeFlow, code string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if flow == nil {
		return "", fmt.Errorf("authorization flow is required")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", fmt.Errorf("authorization code is required")
	}
	config, err := oauth2ConfigForFlow(flow)
	if err != nil {
		return "", err
	}
	options := make([]oauth2.AuthCodeOption, 0, 1)
	if verifier := strings.TrimSpace(flow.CodeVerifier); verifier != "" {
		options = append(options, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	token, err := config.Exchange(ctx, code, options...)
	if err != nil {
		return "", err
	}
	idToken, _ := token.Extra("id_token").(string)
	idToken = strings.TrimSpace(idToken)
	if idToken == "" {
		return "", fmt.Errorf("upstream token response missing id_token")
	}
	return idToken, nil
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

func oauth2ConfigForFlow(flow *oidc.AuthorizationCodeFlow) (*oauth2.Config, error) {
	if flow == nil {
		return nil, fmt.Errorf("authorization flow is required")
	}
	if strings.TrimSpace(flow.ClientID) == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if strings.TrimSpace(flow.RedirectURL) == "" {
		return nil, fmt.Errorf("redirect URL is required")
	}
	if strings.TrimSpace(flow.TokenEndpoint) == "" {
		return nil, fmt.Errorf("token endpoint is required")
	}
	return &oauth2.Config{
		ClientID:    flow.ClientID,
		RedirectURL: flow.RedirectURL,
		Scopes:      append([]string(nil), flow.Scopes...),
		Endpoint: oauth2.Endpoint{
			AuthURL:  strings.TrimSpace(flow.AuthorizationEndpoint),
			TokenURL: strings.TrimSpace(flow.TokenEndpoint),
		},
	}, nil
}
