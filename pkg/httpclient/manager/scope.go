package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) ListScopes(ctx context.Context, req schema.ScopeListRequest) (*schema.ScopeList, error) {
	var response schema.ScopeList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("scope"), client.OptQuery(req.Query())); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
