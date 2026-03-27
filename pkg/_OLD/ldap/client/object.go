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

package client

import (
	"context"
	"net/http"

	// Packages
	client "github.com/mutablelogic/go-client"
	schema "github.com/mutablelogic/go-server/pkg/ldap/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) ListObjects(ctx context.Context, opts ...Opt) (*schema.ObjectList, error) {
	req := client.NewRequest()

	// Apply options
	opt, err := applyOpts(opts...)
	if err != nil {
		return nil, err
	}

	// Perform request
	var response schema.ObjectList
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("object"), client.OptQuery(opt.Values)); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}

func (c *Client) CreateObject(ctx context.Context, meta schema.Object) (*schema.Object, error) {
	req, err := client.NewJSONRequest(meta)
	if err != nil {
		return nil, err
	}

	// Perform request
	var response schema.Object
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("object")); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}

func (c *Client) GetObject(ctx context.Context, dn string) (*schema.Object, error) {
	var resp schema.Object

	// Perform request
	if err := c.DoWithContext(ctx, client.MethodGet, &resp, client.OptPath("object", dn)); err != nil {
		return nil, err
	}

	// Return the response
	return &resp, nil
}

func (c *Client) DeleteObject(ctx context.Context, dn string) error {
	// Perform request
	return c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("object", dn))
}

func (c *Client) UpdateObject(ctx context.Context, meta schema.Object) (*schema.Object, error) {
	req, err := client.NewJSONRequestEx(http.MethodPatch, meta, "")
	if err != nil {
		return nil, err
	}

	// Perform request
	var response schema.Object
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("object", meta.DN)); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}
