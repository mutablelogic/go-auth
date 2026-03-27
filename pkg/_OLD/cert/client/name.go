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
	schema "github.com/mutablelogic/go-server/pkg/cert/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) ListNames(ctx context.Context, opts ...Opt) (*schema.NameList, error) {
	req := client.NewRequest()

	// Apply options
	opt, err := applyOpts(opts...)
	if err != nil {
		return nil, err
	}

	// Perform request
	var response schema.NameList
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("name"), client.OptQuery(opt.Values)); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}

func (c *Client) CreateName(ctx context.Context, name schema.NameMeta) (*schema.Name, error) {
	req, err := client.NewJSONRequest(name)
	if err != nil {
		return nil, err
	}

	// Perform request
	var response schema.Name
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("name")); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}

func (c *Client) GetName(ctx context.Context, id uint64) (*schema.Name, error) {
	req := client.NewRequest()

	// Perform request
	var response schema.Name
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("name", id)); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}

func (c *Client) DeleteName(ctx context.Context, id uint64) error {
	return c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("name", id))
}

func (c *Client) UpdateName(ctx context.Context, id uint64, meta schema.NameMeta) (*schema.Name, error) {
	req, err := client.NewJSONRequestEx(http.MethodPatch, meta, "")
	if err != nil {
		return nil, err
	}

	// Perform request
	var response schema.Name
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("name", id)); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}
