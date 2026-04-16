// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manager

import (
	"context"
	"net/http"

	// Packages
	schema "github.com/mutablelogic/go-auth/schema/auth"
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
	return c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("user", user))
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

func (c *Client) AddUserGroups(ctx context.Context, user schema.UserID, groups []string) (*schema.User, error) {
	var response schema.User
	req, err := client.NewJSONRequestEx(http.MethodPost, groups, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("user", user, "group")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) RemoveUserGroups(ctx context.Context, user schema.UserID, groups []string) (*schema.User, error) {
	var response schema.User
	req, err := client.NewJSONRequestEx(http.MethodDelete, groups, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("user", user, "group")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
