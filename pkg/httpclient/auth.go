package httpclient

import (
	"context"
	"crypto/rsa"
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
