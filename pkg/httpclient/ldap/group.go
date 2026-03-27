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

package ldap

import (
	"context"
	"net/http"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) ListGroups(ctx context.Context, req schema.ObjectListRequest) (*schema.ObjectList, error) {
	var response schema.ObjectList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("group"), client.OptQuery(req.Query())); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) GetGroup(ctx context.Context, cn string) (*schema.Object, error) {
	var response schema.Object
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("group", cn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) CreateGroup(ctx context.Context, cn string, req *schema.ObjectPutRequest) (*schema.Object, error) {
	var response schema.Object
	var body client.Payload
	if req != nil {
		var err error
		if body, err = client.NewJSONRequestEx(http.MethodPut, req, types.ContentTypeJSON); err != nil {
			return nil, err
		}
	} else {
		body = client.MethodPut
	}
	if err := c.DoWithContext(ctx, body, &response, client.OptPath("group", cn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) UpdateGroup(ctx context.Context, cn string, req schema.ObjectPutRequest) (*schema.Object, error) {
	var response schema.Object
	body, err := client.NewJSONRequestEx(http.MethodPatch, req, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, body, &response, client.OptPath("group", cn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) DeleteGroup(ctx context.Context, cn string) (*schema.Object, error) {
	var response schema.Object
	if err := c.DoWithContext(ctx, client.MethodDelete, &response, client.OptPath("group", cn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
