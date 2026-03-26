package auth

import (
	"context"

	// Packages
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RefreshToken refreshes an OAuth token using the supplied OAuth client configuration.
func (c *Client) RefreshToken(ctx context.Context, config *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
	return config.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, c.Client.Client), token).Token()
}
