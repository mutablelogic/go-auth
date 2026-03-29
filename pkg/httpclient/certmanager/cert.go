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
	"net/url"
	"strconv"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/cert"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) ListCerts(ctx context.Context, req schema.CertListRequest) (*schema.CertList, error) {
	var response schema.CertList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("cert"), client.OptQuery(certListQuery(req))); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func certListQuery(req schema.CertListRequest) url.Values {
	values := url.Values{}
	if req.Offset > 0 {
		values.Set("offset", strconv.FormatUint(req.Offset, 10))
	}
	if req.Limit != nil {
		values.Set("limit", strconv.FormatUint(types.Value(req.Limit), 10))
	}
	if req.IsCA != nil {
		values.Set("is_ca", strconv.FormatBool(*req.IsCA))
	}
	if req.Enabled != nil {
		values.Set("enabled", strconv.FormatBool(*req.Enabled))
	}
	for _, tag := range req.Tags {
		values.Add("tags", tag)
	}
	if req.Valid != nil {
		values.Set("valid", strconv.FormatBool(*req.Valid))
	}
	if req.Subject != nil {
		values.Set("subject", strconv.FormatUint(types.Value(req.Subject), 10))
	}
	return values
}
