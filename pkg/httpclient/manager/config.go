package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) Config(ctx context.Context) (schema.PublicClientConfigurations, error) {
	var response schema.PublicClientConfigurations
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("config")); err != nil {
		return nil, err
	}
	return response, nil
}
