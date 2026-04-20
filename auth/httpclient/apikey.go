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
