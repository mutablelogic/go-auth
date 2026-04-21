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

package httpclient

import (
	"context"
	"net/http"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *ManagerClient) ListKeys(ctx context.Context, req schema.KeyListRequest) (*schema.KeyList, error) {
	var response schema.KeyList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("key"), client.OptQuery(req.Query())); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *ManagerClient) GetKey(ctx context.Context, key schema.KeyID) (*schema.Key, error) {
	var response schema.Key
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("key", key)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *ManagerClient) UpdateKey(ctx context.Context, key schema.KeyID, meta schema.KeyMeta) (*schema.Key, error) {
	var response schema.Key
	req, err := client.NewJSONRequestEx(http.MethodPatch, meta, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("key", key)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *ManagerClient) DeleteKey(ctx context.Context, key schema.KeyID) error {
	return c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("key", key))
}

func (c *ManagerClient) CreateKey(ctx context.Context, meta schema.KeyMeta) (*schema.Key, error) {
	var response schema.Key
	req, err := client.NewJSONRequestEx(http.MethodPost, meta, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("key")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
