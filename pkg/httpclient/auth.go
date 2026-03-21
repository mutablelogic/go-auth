package httpclient

import (
	"context"
	"crypto/rsa"
	"fmt"
	"strings"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	authschema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Login encodes the supplied claims into a JWT signed by the supplied RSA
// private key, or as an unsecured JWT when key is nil, and posts it to
// /auth/login.
func (c *Client) Login(ctx context.Context, key *rsa.PrivateKey, claims jwt.MapClaims) (*authschema.TokenResponse, error) {
	token, err := oidc.IssueToken(key, claims)
	if err != nil {
		return nil, err
	}
	return c.LoginToken(ctx, token)
}

// LoginToken posts a verified upstream identity token to /auth/login and
// returns the issued local session token response.
func (c *Client) LoginToken(ctx context.Context, token string) (*authschema.TokenResponse, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, fmt.Errorf("token is required")
	}
	// Create a request payload with the token and provider type
	payload, err := client.NewJSONRequest(authschema.TokenRequest{
		Provider: authschema.ProviderOAuth,
		Token:    token,
	})
	if err != nil {
		return nil, err
	}

	// Exchange the token
	var response authschema.TokenResponse
	if err := c.DoWithContext(ctx, payload, &response, client.OptAbsPath("auth", "login")); err != nil {
		return nil, err
	}

	// Return the response
	return &response, nil
}

// LoginCode posts an authorization code exchange request to /auth/code and
// returns the issued local session token response.
func (c *Client) LoginCode(ctx context.Context, provider string, flow *oidc.AuthorizationCodeFlow, code string) (*authschema.TokenResponse, error) {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return nil, fmt.Errorf("provider is required")
	}
	if flow == nil {
		return nil, fmt.Errorf("authorization flow is required")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("authorization code is required")
	}
	payload, err := client.NewJSONRequest(authschema.AuthorizationCodeRequest{
		Provider:     provider,
		Code:         code,
		RedirectURL:  strings.TrimSpace(flow.RedirectURL),
		CodeVerifier: strings.TrimSpace(flow.CodeVerifier),
		Nonce:        strings.TrimSpace(flow.Nonce),
	})
	if err != nil {
		return nil, err
	}

	var response authschema.TokenResponse
	if err := c.DoWithContext(ctx, payload, &response, client.OptAbsPath("auth", "code")); err != nil {
		return nil, err
	}
	return &response, nil
}

// Refresh posts a previously issued local token to /auth/refresh and returns
// the refreshed local session token response.
func (c *Client) Refresh(ctx context.Context, token string) (*authschema.TokenResponse, error) {
	payload, err := client.NewJSONRequest(authschema.RefreshRequest{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	// Refresh the token
	var response authschema.TokenResponse
	if err := c.DoWithContext(ctx, payload, &response, client.OptAbsPath("auth", "refresh")); err != nil {
		return nil, err
	}

	// Return the response
	return &response, nil
}

// UserInfo retrieves the authenticated userinfo for a previously issued local
// bearer token.
func (c *Client) UserInfo(ctx context.Context, token string) (*authschema.UserInfo, error) {
	var response authschema.UserInfo
	if err := c.DoWithContext(ctx, client.NewRequest(), &response,
		client.OptAbsPath("auth", "userinfo"),
		client.OptToken(client.Token{Scheme: client.Bearer, Value: strings.TrimSpace(token)}),
	); err != nil {
		return nil, err
	}
	return &response, nil
}

// OIDCConfig retrieves the OpenID Connect discovery document for the supplied
// issuer URL.
func (c *Client) OIDCConfig(ctx context.Context, issuer string) (*oidc.Configuration, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	var response oidc.Configuration
	if err := c.DoWithContext(ctx, client.NewRequest(), &response,
		client.OptReqEndpoint(issuer),
		client.OptPath(oidc.ConfigPath),
	); err != nil {
		return nil, err
	}
	return &response, nil
}

// OAuthProviderConfig resolves the configured public auth provider details by
// provider key, defaulting to the reserved local provider when the key is
// empty.
func (c *Client) OAuthProviderConfig(ctx context.Context, provider string) (string, oidc.PublicClientConfiguration, error) {
	config, err := c.AuthConfig(ctx)
	if err != nil {
		return "", oidc.PublicClientConfiguration{}, err
	}
	key := strings.TrimSpace(provider)
	if key == "" {
		key = oidc.OAuthClientKeyLocal
	}
	entry, ok := config[key]
	if !ok {
		return "", oidc.PublicClientConfiguration{}, fmt.Errorf("unknown auth provider %q", key)
	}
	return key, entry, nil
}

// AuthConfig retrieves the shareable upstream auth provider configuration from
// /auth/config.
func (c *Client) AuthConfig(ctx context.Context) (oidc.PublicClientConfigurations, error) {
	var response oidc.PublicClientConfigurations
	if err := c.DoWithContext(ctx, client.NewRequest(), &response, client.OptAbsPath("auth", "config")); err != nil {
		return nil, err
	}
	return response, nil
}

// Revoke posts a previously issued local token to /auth/revoke and expects a
// successful revocation with no response body.
func (c *Client) Revoke(ctx context.Context, token string) error {
	payload, err := client.NewJSONRequest(authschema.RefreshRequest{
		Token: token,
	})
	if err != nil {
		return err
	}

	if err := c.DoWithContext(ctx, payload, nil, client.OptAbsPath("auth", "revoke")); err != nil {
		return err
	}
	return nil
}
