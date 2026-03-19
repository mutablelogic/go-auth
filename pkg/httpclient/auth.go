package httpclient

import (
	"context"
	"crypto/rsa"

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

// Revoke posts a previously issued local token to /auth/revoke and returns the
// revoked session record.
func (c *Client) Revoke(ctx context.Context, token string) (*authschema.Session, error) {
	payload, err := client.NewJSONRequest(authschema.RefreshRequest{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	var response authschema.Session
	if err := c.DoWithContext(ctx, payload, &response, client.OptAbsPath("auth", "revoke")); err != nil {
		return nil, err
	}

	return &response, nil
}
