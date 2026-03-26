package auth

import (
	"context"

	// Packages
	authschema "github.com/djthorpe/go-auth/schema"
	client "github.com/mutablelogic/go-client"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) UserInfo(ctx context.Context, endpoint string, token *oauth2.Token) (*authschema.UserInfo, error) {
	var response authschema.UserInfo
	if err := c.DoWithContext(ctx, client.NewRequest(), &response,
		client.OptReqEndpoint(endpoint),
		client.OptToken(client.Token{Scheme: client.Bearer, Value: token.AccessToken}),
	); err != nil {
		return nil, err
	}
	return &response, nil
}
