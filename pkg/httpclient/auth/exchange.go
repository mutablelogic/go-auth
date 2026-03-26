package auth

import (
	"context"
	"fmt"
	"strings"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ExchangeCode exchanges an authorization code using the supplied flow
// configuration and returns the token response from the configured endpoint.
func (c *Client) ExchangeCode(ctx context.Context, flow *oidc.AuthorizationCodeFlow, code, clientSecret string) (*oauth2.Token, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c != nil && c.Client != nil && c.Client.Client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.Client.Client)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}
	config, err := OAuth2ConfigForFlow(flow, clientSecret)
	if err != nil {
		return nil, err
	}
	options := make([]oauth2.AuthCodeOption, 0, 1)
	if verifier := strings.TrimSpace(flow.CodeVerifier); verifier != "" {
		options = append(options, oauth2.SetAuthURLParam("code_verifier", verifier))
	}
	if provider := strings.TrimSpace(flow.Provider); provider != "" {
		options = append(options, oauth2.SetAuthURLParam("provider", provider))
	}
	if nonce := strings.TrimSpace(flow.Nonce); nonce != "" {
		options = append(options, oauth2.SetAuthURLParam("nonce", nonce))
	}
	token, err := config.Exchange(ctx, code, options...)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// OAuth2ConfigForFlow returns an oauth2.Config derived from the authorization flow.
func OAuth2ConfigForFlow(flow *oidc.AuthorizationCodeFlow, clientSecret string) (*oauth2.Config, error) {
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
		ClientID:     flow.ClientID,
		ClientSecret: strings.TrimSpace(clientSecret),
		RedirectURL:  flow.RedirectURL,
		Scopes:       append([]string(nil), flow.Scopes...),
		Endpoint: oauth2.Endpoint{
			AuthURL:  strings.TrimSpace(flow.AuthorizationEndpoint),
			TokenURL: strings.TrimSpace(flow.TokenEndpoint),
		},
	}, nil
}

// OAuth2Config returns an oauth2.Config derived from auth server metadata and client ID.
func OAuth2Config(config oidc.BaseConfiguration, clientID, clientSecret string, scopes ...string) (*oauth2.Config, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if strings.TrimSpace(config.TokenEndpoint) == "" {
		return nil, fmt.Errorf("token endpoint is required")
	}
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: strings.TrimSpace(clientSecret),
		Scopes:       append([]string(nil), scopes...),
		Endpoint: oauth2.Endpoint{
			AuthURL:  strings.TrimSpace(config.AuthorizationEndpoint),
			TokenURL: strings.TrimSpace(config.TokenEndpoint),
		},
	}, nil
}
