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

package certmanager

import (
	"context"
	"net/http"
	"strings"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/cert"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) CreateCA(ctx context.Context, req schema.CreateCertRequest) (*schema.Cert, error) {
	var response schema.Cert
	body, err := client.NewJSONRequestEx(http.MethodPost, req, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, body, &response, client.OptPath("ca")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) RenewCA(ctx context.Context, ca schema.CertKey, req schema.RenewCertRequest) (*schema.Cert, error) {
	var response schema.Cert
	body, err := client.NewJSONRequestEx(http.MethodPost, renewRequestBody(req), types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if serial := strings.TrimSpace(ca.Serial); serial != "" {
		if err := c.DoWithContext(ctx, body, &response, client.OptPath("ca", ca.Name, serial, "renew")); err != nil {
			return nil, err
		}
	} else if err := c.DoWithContext(ctx, body, &response, client.OptPath("ca", ca.Name, "renew")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}
