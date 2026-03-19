package httpclient

import (
	"context"
	"fmt"
	"time"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	authschema "github.com/djthorpe/go-auth/schema"
	jwt "github.com/golang-jwt/jwt/v5"
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Login encodes the supplied claims into a JWT signed by the supplied PEM key
// and posts it to /auth/login.
func (c *Client) Login(ctx context.Context, pem string, claims jwt.MapClaims) (map[string]any, error) {
	token, err := loginToken(pem, claims)
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
	var response map[string]any
	if err := c.DoWithContext(ctx, payload, &response, client.OptAbsPath("auth", "login")); err != nil {
		return nil, err
	}

	// Return the response
	return response, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func loginToken(pem string, claims jwt.MapClaims) (string, error) {
	if len(claims) == 0 {
		return "", fmt.Errorf("claims cannot be empty")
	} else if issuer, ok := claims["iss"].(string); !ok || issuer == "" {
		return "", fmt.Errorf("claims must include a non-empty iss")
	} else if pem == "" {
		return "", fmt.Errorf("private key PEM cannot be empty")
	} else {
		now := time.Now().UTC()

		// Set iat, nbf, and exp if not already set (issued at, not before, and expiration)
		if _, ok := claims["iat"]; !ok {
			claims["iat"] = now.Unix()
		}
		if _, ok := claims["nbf"]; !ok {
			claims["nbf"] = now.Unix()
		}
		if _, ok := claims["exp"]; !ok {
			claims["exp"] = now.Add(time.Hour).Unix()
		}

		// Sign the claims into a JWT
		return manager.OIDCSignPEM(pem, claims)
	}
}
