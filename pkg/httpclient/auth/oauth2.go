package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

// FetchConfig discovers OAuth/OIDC metadata from an issuer's well-known
// configuration and returns an oauth2.Config for the supplied client.
func FetchConfig(ctx context.Context, issuer, clientID, redirectURL string, scopes ...string) (*oauth2.Config, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discovery, err := fetchOIDCConfig(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return oauth2ConfigFromDiscovery(discovery, issuer, clientID, redirectURL, scopes...)
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
	return oauth2ConfigFromDiscovery(discovery, public.Issuer, public.ClientID, redirectURL, scopes...)
}

// AuthCodeURL builds a provider-specific authorization URL for an auth code flow.
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

// OAuthLoginBootstrap resolves provider config and discovery metadata into an OIDC authorization flow payload.
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

// ExchangeAuthorizationCode exchanges an OAuth authorization code for an upstream OIDC id_token using the supplied flow configuration.
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
	token := &oauth2.Token{AccessToken: raw, TokenType: "Bearer"}
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

func fetchOIDCConfig(ctx context.Context, issuer string) (*oidc.Configuration, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, oidc.ConfigURL(issuer), nil)
	if err != nil {
		return nil, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if challenge := strings.TrimSpace(response.Header.Get("WWW-Authenticate")); challenge != "" {
			return nil, fmt.Errorf("fetch OIDC configuration from %q: %s (WWW-Authenticate: %s)", issuer, response.Status, challenge)
		}
		return nil, fmt.Errorf("fetch OIDC configuration from %q: %s", issuer, response.Status)
	}
	config := new(oidc.Configuration)
	if err := json.NewDecoder(response.Body).Decode(config); err != nil {
		return nil, fmt.Errorf("decode OIDC configuration from %q: %w", issuer, err)
	}
	return config, nil
}

func oauth2ConfigFromDiscovery(discovery *oidc.Configuration, issuer, clientID, redirectURL string, scopes ...string) (*oauth2.Config, error) {
	if discovery == nil {
		return nil, fmt.Errorf("OIDC configuration is required")
	}
	issuer = strings.TrimSpace(issuer)
	clientID = strings.TrimSpace(clientID)
	redirectURL = strings.TrimSpace(redirectURL)
	if clientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if redirectURL == "" {
		return nil, fmt.Errorf("redirect URL is required")
	}
	if strings.TrimSpace(discovery.AuthorizationEndpoint) == "" {
		return nil, fmt.Errorf("issuer %q has no authorization_endpoint", issuer)
	}
	if strings.TrimSpace(discovery.TokenEndpoint) == "" {
		return nil, fmt.Errorf("issuer %q has no token_endpoint", issuer)
	}
	scopes = oidc.AuthorizationScopes(*discovery, scopes...)
	return &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURL,
		Scopes:      scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}, nil
}
