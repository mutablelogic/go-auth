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

func (c *Client) CreateUser(ctx context.Context, meta schema.UserMeta) (*schema.User, error) {
	var response schema.User
	req, err := client.NewJSONRequestEx(http.MethodPost, meta, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("user")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) ListUsers(ctx context.Context, req schema.UserListRequest) (*schema.UserList, error) {
	var response schema.UserList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("user"), client.OptQuery(req.Query())); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) GetUser(ctx context.Context, user schema.UserID) (*schema.User, error) {
	var response schema.User
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("user", user)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) DeleteUser(ctx context.Context, user schema.UserID) error {
	if err := c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("user", user)); err != nil {
		return err
	}
	return nil
}

func (c *Client) UpdateUser(ctx context.Context, user schema.UserID, meta schema.UserMeta) (*schema.User, error) {
	var response schema.User
	req, err := client.NewJSONRequestEx(http.MethodPatch, meta, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("user", user)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
