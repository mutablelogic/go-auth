package auth

import (
	"context"
	"fmt"
	"strings"

	// Packages
	client "github.com/mutablelogic/go-client"
	"github.com/mutablelogic/go-server/pkg/types"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type RevokeRequest struct {
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Token        string `json:"token,omitempty"`
	TokenType    string `json:"token_type_hint,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RevokeToken revokes an OAuth token using the supplied revocation endpoint.
func (c *Client) RevokeToken(ctx context.Context, endpoint string, token *oauth2.Token, clientID, clientSecret string) error {
	hint := "refresh_token"
	value := token.RefreshToken
	if value == "" {
		hint = "access_token"
		value = token.AccessToken
	}

	// Create the payload for the revocation request
	payload, err := client.NewFormRequest(RevokeRequest{
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: strings.TrimSpace(clientSecret),
		Token:        strings.TrimSpace(value),
		TokenType:    hint,
	}, types.ContentTypeAny)
	if err != nil {
		return fmt.Errorf("revoke token payload: %w", err)
	}

	// Send the revocation request to the endpoint
	return c.Client.DoWithContext(ctx, payload, nil, client.OptReqEndpoint(endpoint))
}
