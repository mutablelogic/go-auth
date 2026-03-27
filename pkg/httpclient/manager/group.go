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

func (c *Client) GetGroup(ctx context.Context, group string) (*schema.Group, error) {
	var response schema.Group
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("group", group)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) DeleteGroup(ctx context.Context, group string) error {
	return c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("group", group))
}

func (c *Client) UpdateGroup(ctx context.Context, group string, meta schema.GroupMeta) (*schema.Group, error) {
	var response schema.Group
	req, err := client.NewJSONRequestEx(http.MethodPatch, meta, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("group", group)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
