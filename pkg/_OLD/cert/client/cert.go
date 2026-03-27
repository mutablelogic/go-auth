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

	// Packages
	client "github.com/mutablelogic/go-client"
	schema "github.com/mutablelogic/go-server/pkg/cert/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) CreateCert(ctx context.Context, meta schema.CertCreateMeta) (*schema.CertMeta, error) {
	req, err := client.NewJSONRequest(meta)
	if err != nil {
		return nil, err
	}

	// Perform request
	var response schema.CertMeta
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("cert")); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}

func (c *Client) GetCert(ctx context.Context, name string) (*schema.Cert, error) {
	req := client.NewRequest()

	// Perform request
	var response schema.Cert
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("cert", name)); err != nil {
		return nil, err
	}

	// Return the responses
	return &response, nil
}

func (c *Client) DeleteCert(ctx context.Context, name string) error {
	return c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("cert", name))
}
