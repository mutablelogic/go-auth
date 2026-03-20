package httpclient

import (
	"context"
	"net/http"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) CreateGroup(ctx context.Context, insert schema.GroupInsert) (*schema.Group, error) {
	var response schema.Group
	req, err := client.NewJSONRequestEx(http.MethodPost, insert, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("group")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) ListGroups(ctx context.Context, req schema.GroupListRequest) (*schema.GroupList, error) {
	var response schema.GroupList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("group"), client.OptQuery(req.Query())); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
